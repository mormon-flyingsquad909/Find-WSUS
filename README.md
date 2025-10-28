# 🧭 Find-WSUS

**Discover WSUS server configurations across Group Policy Objects (GPOs) — including hidden Group Policy Preferences (GPP).**

`Find-WSUS` is a PowerShell script designed for **security professionals and system administrators** to identify all WSUS (Windows Server Update Services) server URLs configured via GPOs. It detects configurations from both:

* **Administrative Template Policies (HKLM\Software\Policies)**
* **Group Policy Preferences (GPP)** registry settings hidden in XML reports

---

## ⚠️ Why This Matters

WSUS servers are **high-value infrastructure assets**. If compromised, an attacker can deploy malicious “updates” to all domain-joined systems, leading to **total domain compromise**.

> 🧨 Vulnerabilities like **CVE-2025-59287** demonstrate that a single WSUS exploit can grant attackers domain-wide control.

**Find-WSUS** helps organizations locate every WSUS configuration source before attackers do.

---

## 🔍 The “Hidden WSUS” Problem

Most scans only check:

```
HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate
```

However, many organizations deploy WSUS configuration through **Group Policy Preferences (GPP)**, which directly modify registry keys. These settings **don’t appear** in standard GPMC reports.

✅ `Find-WSUS` detects both standard and GPP-based configurations, giving you full visibility into your environment.

---

## 🧩 Prerequisites

| Requirement                             | Description                                                                                                                                                                                                                                                 |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **64-bit PowerShell**                   | Required for COM compatibility. The script exits automatically if run in 32-bit PowerShell.                                                                                                                                                                 |
| **RSAT: Group Policy Management Tools** | Required for the `GroupPolicy` module.<br><br>**Windows 10/11:** `Settings → Optional Features → Add a Feature → RSAT: Group Policy Management Tools`<br>**Windows Server:** `Server Manager → Add Roles and Features → Features → Group Policy Management` |
| **Permissions**                         | Read-access to all GPOs in the domain being scanned.                                                                                                                                                                                                        |
| **Optional:** Administrator rights      | Some registry policy queries may fail without elevation.                                                                                                                                                                                                    |

---

## ⚙️ Usage

### 1. Import the Script

Load the script into your PowerShell session:

```powershell
. .\Find-WSUS.ps1
```

### 2. Run the Scan

After importing, the `Find-WSUS` function becomes available.

#### Example 1: Scan the Current Domain

```powershell
Find-WSUS | Format-Table -AutoSize
```

#### Example 2: Verbose Output

See detailed progress messages while scanning:

```powershell
Find-WSUS -Verbose
```

#### Example 3: Scan a Different Domain

```powershell
Find-WSUS -Domain "child.mydomain.com" | Format-Table -AutoSize
```

#### Example 4: Filter GPOs by Name

```powershell
Find-WSUS -Name "*Server*" -Verbose
```

#### Example 5: Get a Unique List of WSUS Hosts

```powershell
$results = Find-WSUS -Domain "mydomain.com"
$results.Hostname | Where-Object { $_ } | Sort-Object -Unique
```

---

## 📦 Parameters

| Parameter  | Description                                                        | Default               |
| ---------- | ------------------------------------------------------------------ | --------------------- |
| `-Name`    | Filter GPOs by display name using wildcards. Uses `-All` when `*`. | `*` (all GPOs)        |
| `-Domain`  | Specify a domain to query (useful in multi-domain forests).        | Current user's domain |
| `-Verbose` | Displays detailed scanning progress and findings.                  | Off                   |

---

## 🧠 How It Works

### 1. **Environment Validation**

* Ensures PowerShell is 64-bit.
* Verifies the GroupPolicy module is installed.
* Confirms GPOs are accessible in the specified domain.

### 2. **Policy Scan (STA Runspace)**

* Uses `Get-GPRegistryValue` in an **STA runspace** to avoid COM threading errors.
* Scans for `WUServer` and `WUStatusServer` values in:

  ```
  HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate
  ```

### 3. **Preference Scan (GPP XML)**

* Parses XML output from `Get-GPOReport -ReportType Xml`.
* Finds hidden WSUS URLs in namespaced (`q2:Registry`) and fallback (`*[local-name()='Registry']`) nodes.
* Captures values written under HKLM, including `...\Windows\WindowsUpdate` keys.

### 4. **Result Aggregation**

* Merges all findings into a single dataset.
* Extracts hostnames from URLs for easy deduplication.
* Returns clean, sorted objects.

---

## 🧾 Example Output (real-style formatting)

> This mirrors the **actual** `Format-Table -AutoSize` layout and headers from `Find-WSUS`, but with realistic sample hosts/URLs and GPO names/GUIDs.

```text
PS C:\Users\Administrator\Documents> Find-WSUS | Format-Table -AutoSize
[OK] Environment check passed: 64-bit PowerShell, GroupPolicy module loaded, GPOs accessible.


GPOName               Scope                 Key                                                    ValueName      Value                                    Hostname              GPOGuid                              
-------               -----                 ---                                                    ---------      -----                                    --------              -------                              
Default Domain Policy Policy (Computer)     HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate WUServer       https://wsus.corp.contoso.com:8531       wsus.corp.contoso.com 31b2f340-016d-11d2-945f-00c04fb984f9
Default Domain Policy Policy (Computer)     HKLM\Software\Policies\Microsoft\Windows\Windows\Update WUStatusServer https://wsus.corp.contoso.com:8531       wsus.corp.contoso.com 31b2f340-016d-11d2-945f-00c04fb984f9
Corporate WSUS Baseline Policy (Computer)   HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate WUServer       http://wsus01.contoso.com:8530           wsus01.contoso.com    57f2e3da-33c5-4a35-abce-c12a0b7f9823
Corporate WSUS Baseline Policy (Computer)   HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate WUStatusServer https://wsus01.contoso.com:8531          wsus01.contoso.com    57f2e3da-33c5-4a35-abce-c12a0b7f9823
Workstations - Windows Update (GPP) Preference (Registry) HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate WUStatusServer https://wsus-west.contoso.com:8531   wsus-west.contoso.com a1cde8b2-7f45-43f2-9db4-9c1e93a0e5c1
```

> **Note:** In real environments you’ll often see SSL on `:8531` and legacy HTTP on `:8530`. Hostnames above are examples; replace with your actual inventory.

---

## 🚫 Limitations

> [!WARNING]
> This script is a **discovery tool**, not a full inventory system.

It **only** finds WSUS servers defined via Group Policy.
It does **not** detect:

* Non-domain clients or manually configured registries
* Rogue WSUS servers with no GPO linkage
* Systems managed by Intune or SCCM policies

---

## ✅ Recommended Next Steps

1. Run `Find-WSUS` across **all domains** in your forest.
2. Combine the output into a central inventory.
3. Compare with an EDR or asset scanner for machines running the `WSUSService`.
4. Investigate any **mismatched or unexpected WSUS hosts**.

---

## 🧑‍💻 Author & Credits

Developed by security engineers to expose hidden WSUS configurations and improve patch infrastructure visibility.

> 📘 Contributions welcome! Submit pull requests or issues to enhance compatibility or add new discovery methods.
