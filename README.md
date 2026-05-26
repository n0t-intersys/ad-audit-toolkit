# Active Directory Security Auditor

[![CI](https://github.com/n0t-intersys/ad-audit-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/n0t-intersys/ad-audit-toolkit/actions)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.x%20%7C%205.1-blue?logo=powershell)](https://microsoft.com/powershell)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Auth Required](https://img.shields.io/badge/⚠_Authorization-Required-red)

Five PowerShell modules that cover the AD weaknesses I find most often — Kerberoastable accounts, AS-REP roasting exposure, shadow admins sitting outside privileged groups, password policies that don't meet CIS or NIST baselines, stale computer objects, and EOL operating systems still authenticating to the domain. Run `Invoke-ADAuditSuite.ps1` and it produces a full HTML report in one shot.

> ⚠️ Run only on domains you own or have **explicit written authorization** to audit — see [LEGAL.md](LEGAL.md).

---

## Scripts

| Script | Purpose | Key Findings |
|--------|---------|-------------|
| `Invoke-ADUserAudit.ps1` | User account hygiene | Stale accounts, PWD_NEVER_EXPIRES, reversible encryption, disabled accounts with group memberships |
| `Invoke-ADPrivilegedAudit.ps1` | Privileged access review | DA/EA/SA membership, shadow admins (AdminCount=1), DCSync rights, Protected Users gaps |
| `Invoke-ADKerberosAudit.ps1` | Kerberos attack surface | Kerberoastable (T1558.003), AS-REP roastable (T1558.004), unconstrained delegation (T1134.001) |
| `Invoke-ADPasswordPolicyAudit.ps1` | Policy vs CIS/NIST baseline | Default Domain Policy gaps, Fine-Grained PSOs, lockout settings, complexity enforcement |
| `Invoke-ADComputerAudit.ps1` | Computer account hygiene | Stale machines, EOL OS inventory, LAPS deployment, unconstrained delegation |
| `Invoke-ADAuditSuite.ps1` | **Master orchestrator** | Runs all modules, generates consolidated HTML report |

---

## Requirements

- Windows PowerShell 5.1 **or** PowerShell 7.x (cross-platform)
- `ActiveDirectory` module — installed via:
  - **Domain Controller:** included by default
  - **Admin workstation:** RSAT → `Add-WindowsFeature RSAT-AD-PowerShell`
  - **Windows 10/11:** Settings → Optional Features → RSAT: Active Directory DS Tools
- Domain read access (Domain Admin **not** required for most checks)
- DCSync ACL check requires read access to the domain NC DACL

---

## Quick Start

```powershell
# Run all modules, output to C:\ADReports
.\scripts\Invoke-ADAuditSuite.ps1 -OutputPath C:\ADReports

# Run with LAPS check and DnsAdmins group included
.\scripts\Invoke-ADAuditSuite.ps1 -IncludeLAPSCheck -IncludeDnsAdmins -Verbose

# Scope to a specific OU
.\scripts\Invoke-ADAuditSuite.ps1 -SearchBase "OU=Corp,DC=contoso,DC=com"

# Run individual modules
.\scripts\Invoke-ADKerberosAudit.ps1 -PassThru | Where-Object Severity -eq Critical
.\scripts\Invoke-ADUserAudit.ps1 -StaleLogonDays 60 -OutputPath C:\Reports
.\scripts\Invoke-ADPrivilegedAudit.ps1 -IncludeDnsAdmins

# Pipeline example — export only Critical findings
.\scripts\Invoke-ADAuditSuite.ps1 -PassThru |
    Where-Object Severity -eq 'Critical' |
    Export-Csv -Path C:\critical_findings.csv -NoTypeInformation
```

---

## Sample Output

```
══════════════════════════════════════════════════════════════════════
  AD KERBEROS ATTACK SURFACE AUDIT
  ATT&CK: T1558.003 | T1558.004 | T1134.001 | T1550.003
══════════════════════════════════════════════════════════════════════

  Kerberoastable            7 finding(s)
  ASREPRoastable            3 finding(s)
  UnconstrainedDelegation   2 finding(s)

  🔴 Critical       2
  🟠 High           8
  🟡 Medium         2

  Remediation priorities:
    1. Remove DoesNotRequirePreAuth from all accounts (immediate)
    2. Review all user accounts with SPNs — move to MSA/gMSA
    3. Eliminate unconstrained delegation (replace with constrained)
```

The orchestrator also generates a dark-themed **HTML report** summarizing all findings across modules.

---

## MITRE ATT&CK Coverage

| Technique | Name | Script |
|-----------|------|--------|
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | `Invoke-ADKerberosAudit.ps1` |
| T1558.004 | Steal or Forge Kerberos Tickets: AS-REP Roasting | `Invoke-ADKerberosAudit.ps1` |
| T1134.001 | Access Token Manipulation: Unconstrained Delegation | `Invoke-ADKerberosAudit.ps1` |
| T1550.003 | Use Alternate Auth: Pass-the-Ticket (constrained delegation) | `Invoke-ADKerberosAudit.ps1` |
| T1078.002 | Valid Accounts: Domain Accounts (shadow admins) | `Invoke-ADPrivilegedAudit.ps1` |
| T1003.006 | OS Credential Dumping: DCSync | `Invoke-ADPrivilegedAudit.ps1` |

---

## CIS / NIST Baselines Referenced

| Standard | Application |
|---------|-------------|
| CIS Microsoft Windows Server 2022 Benchmark v2.0.0 | Password policy thresholds |
| NIST SP 800-63B | Password policy philosophy (no forced rotation) |
| NIST SP 800-207 | Zero Trust principles for privileged access |
| Microsoft Tier Model | Privileged access workstation and account tiers |

---

## Lab Environments

Test these scripts safely in a purpose-built lab:

| Platform | Notes |
|----------|-------|
| [Detection Lab](https://github.com/clong/DetectionLab) | Full Windows AD lab with Splunk |
| [GOAD](https://github.com/Orange-Cyberdefense/GOAD) | Game of Active Directory — intentionally vulnerable |
| Windows Server Eval | Free 180-day eval from microsoft.com |
| Proxmox / VMware home lab | Run your own DC + workstation VMs |

---

## Legal & Responsible Use

**See [LEGAL.md](LEGAL.md) for the full policy.**

Authorized use:
- Domains you personally own or administer
- Engagements with signed SOW/ROE
- Internal IT security teams on their own infrastructure
- Lab/training environments

**Prohibited:** Any use against systems without explicit written authorization.

---

## License

MIT — see [LICENSE](LICENSE).
