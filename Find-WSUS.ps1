function Find-WSUS {
    [CmdletBinding()]
    Param(
        # Filter for GPOs. Defaults to all GPOs.
        [string]$Name = "*",

        # Specify a domain to query. Defaults to the current user's domain.
        [string]$Domain
    )

    # ---------------------------------------------------------------------------
    #  Function-Private Helper: Get-Hostname
    # ---------------------------------------------------------------------------
    function Get-Hostname {
      param([string]$v)
      if (-not $v) { return $null }
      try { $u=[Uri]$v; if ($u.Host){return $u.Host} } catch {}
      $m=[regex]::Match($v,'https?://([^/:]+)'); if($m.Success){return $m.Groups[1].Value}
      if ($v -match '^[A-Za-z0-9.-]+$'){return $v}
      return $null
    }

    # ---------------------------------------------------------------------------
    #  Function-Private Helper: Add-Row
    # ---------------------------------------------------------------------------
    function Add-Row {
      param($results, $gpo, $scope, $key, $name, $value)
      $results.Add([pscustomobject]@{
        GPOName  = $gpo.DisplayName
        Scope    = $scope
        Key      = $key
        ValueName= $name
        Value    = $value
        Hostname = (Get-Hostname $value)
        GPOGuid  = $gpo.Id
      }) | Out-Null
    }

    # ---------------------------------------------------------------------------
    #  WSUS-GPO Discovery  -  Environment Pre-Flight Validation
    # ---------------------------------------------------------------------------

    # 1. Require 64-bit PowerShell
    if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
        Write-Host "[ERROR] You are running a 32-bit PowerShell host (ARCH=$($env:PROCESSOR_ARCHITECTURE))." -ForegroundColor Red
        Write-Host "        Please close this window and run the 64-bit PowerShell console instead:" -ForegroundColor Yellow
        Write-Host "        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`n" -ForegroundColor Gray
        return # Stop function
    }

    # 2. Verify RSAT GroupPolicy module exists and can load
    $gpModulePath = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\Modules\GroupPolicy\GroupPolicy.psd1"
    if (-not (Test-Path $gpModulePath)) {
        Write-Host "[ERROR] GroupPolicy RSAT module not found at:" -ForegroundColor Red
        Write-Host "        $gpModulePath" -ForegroundColor Gray
        Write-Host "        Install RSAT: Group Policy Management Tools and re-run this script.`n" -ForegroundColor Yellow
        return # Stop function
    }

    try {
        Import-Module $gpModulePath -ErrorAction Stop
    }
    catch {
        Write-Host "[ERROR] Failed to import GroupPolicy module (`$gpModulePath`)." -ForegroundColor Red
        Write-Host "        $_`n" -ForegroundColor Gray
        return # Stop function
    }

    # ======================= START: FIXED SECTION =======================
    # 3. Confirm we can query at least one known GPO
    
    # Build parameters for Get-GPO
    $gpoParams = @{
        ErrorAction = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('Domain')) { $gpoParams.Domain = $Domain }

    # FIX: Use -All for default "*", otherwise use -Name
    if ($Name -eq "*") {
        $gpoParams.All = $true
    } else {
        $gpoParams.Name = $Name
    }
    # ======================== END: FIXED SECTION ========================

    try {
        $testGpo = Get-GPO @gpoParams | Select-Object -First 1
        if (-not $testGpo) {
            $domainMsg = if ($Domain) { " in domain $Domain" } else { "" }
            $nameMsg = if ($Name -eq "*") { "No GPOs returned" } else { "No GPOs matching '$Name' found" }
            Write-Host "[ERROR] $nameMsg$domainMsg. Check your AD permissions or domain connectivity." -ForegroundColor Red
            return # Stop function
        }
    }
    catch {
        Write-Host "[ERROR] Unable to enumerate GPOs using Get-GPO. Ensure you have RSAT and AD rights." -ForegroundColor Red
        Write-Host "        $_`n" -ForegroundColor Gray
        return # Stop function
    }

    # 4. Optional: confirm elevation
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[WARNING] You are not running PowerShell as Administrator." -ForegroundColor Yellow
        Write-Host "          The script will continue, but some registry policy queries may fail.`n" -ForegroundColor DarkYellow
    }

    Write-Host "[OK] Environment check passed: 64-bit PowerShell, GroupPolicy module loaded, GPOs accessible.`n" -ForegroundColor Green
    # ---------------------------------------------------------------------------

    # Main script logic
    $policyKey = 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate'
    $wantedNames = @('WUServer','WUStatusServer','WSUSStatusServer') # include common typo
    $results = New-Object System.Collections.Generic.List[object]
    
    try {
        # We re-use the $gpoParams from the pre-flight check
        $gpos = Get-GPO @gpoParams
    } catch {
        $errMsg = if ($Name -eq "*") { "Could not find any GPOs." } else { "Could not find any GPOs matching name '$Name'." }
        Write-Error "$errMsg Error: $_"
        return
    }

    # Create a serializable array of PSCustomObjects for the runspace
    $gposForRunspace = $gpos | Select-Object DisplayName, Id

    Write-Verbose "Scanning $($gpos.Count) GPOs..."

    # ======================= START: STA Runspace Section =======================
    Write-Verbose "[INFO] Creating STA runspace for Policy (Get-GPRegistryValue) scan..."

    $policyResults = @()
    $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $runspace.ApartmentState = 'STA' # <-- This is the magic "fix"
    $runspace.Open()

    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.Runspace = $runspace

    $null = $ps.AddScript({
        # Add $Domain to the param block
        param($allGpos, $wantedNames, $key, $Domain)
        
        Import-Module GroupPolicy -ErrorAction SilentlyContinue
        
        $runspaceResults = New-Object System.Collections.Generic.List[object]
        
        foreach ($gpo in $allGpos) {
            if (-not $gpo -or -not $gpo.DisplayName) { continue } # Skip bad objects

            foreach ($vn in $wantedNames) {
                # Create params for splatting
                $gprvParams = @{
                    Name = $gpo.DisplayName
                    Key = $key
                    ValueName = $vn
                    ErrorAction = 'Stop'
                }
                if ($Domain) { $gprvParams.Domain = $Domain }

                try {
                    $r = Get-GPRegistryValue @gprvParams
                    
                    if ($r -and $r.Value -and $r.Value -match '^https?://') {
                        $runspaceResults.Add([pscustomobject]@{
                            GPOName = $gpo.DisplayName
                            GPOGuid = $gpo.Id
                            ValueName = $vn
                            Value = $r.Value
                        })
                    }
                } 
                catch {
                    # Silently catch the error when a key is not found
                }
            }
        }
        return $runspaceResults
    })

    # Pass the $Domain variable to the runspace
    $runspaceParams = @{
        allGpos = $gposForRunspace
        wantedNames = $wantedNames
        key = $policyKey
    }
    if ($PSBoundParameters.ContainsKey('Domain')) { $runspaceParams.Domain = $Domain }
    
    $null = $ps.AddParameters($runspaceParams)

    # Run the pipeline and get the results
    try {
        $policyResults = $ps.Invoke()
        Write-Verbose "[INFO] STA runspace policy scan complete. Found $($policyResults.Count) policy entries."
    }
    catch {
        Write-Error "The STA runspace pipeline itself failed: $_"
    }
    finally {
        # Clean up the runspace and pipeline
        $ps.Dispose()
        $runspace.Close()
        $runspace.Dispose()
    }

    # Add these job results to our main $results list
    foreach ($pr in $policyResults) {
        $originalGpo = $gpos | Where-Object { $_.Id -eq $pr.GPOGuid }
        if ($originalGpo) {
            Add-Row -results $results -gpo $originalGpo -scope 'Policy (Computer)' `
                -key $policyKey -name $pr.ValueName -value $pr.Value
        }
    }
    # ======================== END: STA Runspace Section ========================


    # The rest of the script (GPP / XML scan)
    # Get-GPOReport also needs the -Domain parameter
    $gpoReportParams = @{
        ReportType = 'Xml'
        ErrorAction = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('Domain')) { $gpoReportParams.Domain = $Domain }

    foreach ($gpo in $gpos) {

      Write-Verbose "`n[GPO] $($gpo.DisplayName)"

      # ---- 1) POLICY (Computer) ----
      $runspaceHits = $policyResults | Where-Object { $_.GPOGuid -eq $gpo.Id }
      foreach ($hit in $runspaceHits) {
           Write-Verbose "  Policy: $($hit.ValueName) = $($hit.Value)"
      }

      # ---- 2) PREFERENCES (GPP Registry) ----
      try { 
          $gpoReportParams.Guid = $gpo.Id
          [xml]$xml = Get-GPOReport @gpoReportParams 
      } catch { 
          Write-Warning "Could not generate XML report for $($gpo.DisplayName). Skipping."
          continue 
      }

      # 2a) Namespaced pass
      $nsMgr = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
      $nsMgr.AddNamespace("q2", "http://www.microsoft.com/GroupPolicy/Settings/Windows/Registry")

      $regsQ2 = $xml.SelectNodes("//q2:Registry", $nsMgr)
      Write-Verbose "  q2:Registry nodes: $($regsQ2.Count)"

      foreach ($reg in $regsQ2) {
        $props = $reg.SelectSingleNode("q2:Properties", $nsMgr)
        if (-not $props) { continue }

        $hive = $props.GetAttribute("hive")
        if (-not $hive) { $hive = "HKEY_LOCAL_MACHINE" } 
        $isHKLM = ($hive.ToUpper() -eq 'HKLM' -or $hive.ToUpper() -eq 'HKEY_LOCAL_MACHINE')
        if (-not $isHKLM) { continue }

        $key  = $props.GetAttribute("key")
        $name = $props.GetAttribute("name")
        $val  = $props.GetAttribute("value")

        if (-not $key -or -not $val) { continue }
        if ($key -notmatch '(?i)windows\\windowsupdate') { continue }
        if ($val -notmatch '^https?://') { continue }

        Write-Verbose "  GPP(q2): HKLM\$key => $name = $val"
        Add-Row -results $results -gpo $gpo -scope 'Preference (Registry)' `
          -key ("HKLM\{0}" -f $key) -name $name -value $val
      }

      # 2b) Fallback pass
      $regsAny = $xml.SelectNodes("//*[local-name()='Registry']")
      Write-Verbose "  Fallback Registry nodes: $($regsAny.Count)"

      foreach ($reg in $regsAny) {
        $props = $reg.SelectSingleNode("*[local-name()='Properties']")
        if (-not $props) { continue }

        $hive = $null
        if ($props.Attributes['hive']) { $hive = $props.GetAttribute('hive') }
        elseif ($reg.Attributes['hive']) { $hive = $reg.GetAttribute('hive') }
        else { $hive = 'HKEY_LOCAL_MACHINE' }

        $isHKLM = ($hive.ToUpper() -eq 'HKLM' -or $hive.ToUpper() -eq 'HKEY_LOCAL_MACHINE')
        if (-not $isHKLM) { continue }

        $key = $null
        if ($props.Attributes['key']) { $key = $props.GetAttribute('key') }
        elseif ($reg.Attributes['key']) { $key = $reg.GetAttribute('key') }
        if (-not $key) { continue }
        
        $val = $null
        if ($props.Attributes['value']) { $val = $props.GetAttribute('value') }
        if (-not $val) {
          $valNode = $props.SelectSingleNode("*[local-name()='Value']")
          if ($valNode -and $valNode.InnerText) { $val = $valNode.InnerText.Trim() }
        }

        if (-not $val) { continue }
        if ($key -notmatch '(?i)windows\\windowsupdate') { continue }
        if ($val -notmatch '^https?://') { continue }

        $name = $null
        if ($props.Attributes['name']) { $name = $props.GetAttribute('name') }
        elseif ($reg.Attributes['name']) { $name = $reg.GetAttribute('name') }

        Write-Verbose "  GPP(fallback): HKLM\$key => $name = $val"
        Add-Row -results $results -gpo $gpo -scope 'Preference (Registry)' `
          -key ("HKLM\{0}" -f $key) -name $name -value $val
      }
    }

    # ---- Output section ----
    Write-Verbose "Scan complete. Sorting and de-duplicating $($results.Count) raw findings."
    $rows = $results | Sort-Object GPOName, Scope, Key, ValueName, Value -Unique
    
    # Return the final objects to the pipeline
    return $rows
}
