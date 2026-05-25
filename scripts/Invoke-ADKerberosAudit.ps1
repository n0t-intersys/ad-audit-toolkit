#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Audits Kerberos attack surface in Active Directory.

.DESCRIPTION
    Maps Kerberoastable accounts, AS-REP roastable accounts, unconstrained
    delegation targets, and constrained delegation with protocol transition.
    Each finding maps directly to MITRE ATT&CK techniques.

    ATT&CK Coverage:
      T1558.003 — Kerberoasting         (accounts with SPNs)
      T1558.004 — AS-REP Roasting       (DoesNotRequirePreAuth)
      T1134.001 — Unconstrained Delegation (token impersonation)
      T1550.003 — Constrained w/ Protocol Transition (S4U2Self abuse)

.PARAMETER OutputPath
    Directory to write CSV output. Default: .\reports\

.PARAMETER SearchBase
    LDAP Distinguished Name to scope the search. Default: domain root.

.PARAMETER ExcludeServiceAccounts
    Comma-separated list of SamAccountName prefixes to exclude from
    Kerberoastable findings (e.g., managed service accounts you've reviewed).

.PARAMETER PassThru
    Return result objects to the pipeline.

.EXAMPLE
    .\Invoke-ADKerberosAudit.ps1

.EXAMPLE
    .\Invoke-ADKerberosAudit.ps1 -ExcludeServiceAccounts svc_backup,svc_sql

.NOTES
    Requires : ActiveDirectory PowerShell module
    Privilege: Domain read access — Domain Admin NOT required
    Legal     : Run only on domains you own or have written authorisation to audit.
    MITRE     : T1558.003, T1558.004, T1134.001, T1550.003
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$OutputPath = '.\reports',

    [Parameter()]
    [string]$SearchBase = '',

    [Parameter()]
    [string[]]$ExcludeServiceAccounts = @(),

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-AuditBanner {
    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host '  AD KERBEROS ATTACK SURFACE AUDIT' -ForegroundColor Cyan
    Write-Host '  ATT&CK: T1558.003 | T1558.004 | T1134.001 | T1550.003' -ForegroundColor DarkGray
    Write-Host '  ⚠  Run only on domains you own or have written authorisation to audit.' -ForegroundColor Yellow
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host ''
}

function New-Finding {
    param(
        [string]$Category,
        [string]$MitreID,
        [string]$SamAccountName,
        [string]$DistinguishedName,
        [string]$Detail,
        [string]$ExploitNote,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity
    )
    [PSCustomObject]@{
        Timestamp         = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Severity          = $Severity
        Category          = $Category
        MitreATTCK        = $MitreID
        SamAccountName    = $SamAccountName
        DistinguishedName = $DistinguishedName
        Detail            = $Detail
        ExploitNote       = $ExploitNote
    }
}

function Build-SearchParams {
    param([string]$Filter, [string[]]$Properties, [string]$SearchBase)
    $p = @{ Filter = $Filter; Properties = $Properties }
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }
    return $p
}

# ── Kerberoastable accounts ───────────────────────────────────────────────────

function Get-KerberoastableAccounts {
    [CmdletBinding()]
    param([string]$SearchBase, [string[]]$Exclude)

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $params = Build-SearchParams `
        -Filter "ServicePrincipalName -ne '$null' -and objectClass -eq 'user'" `
        -Properties @('ServicePrincipalName', 'Enabled', 'PasswordLastSet', 'AdminCount', 'Description') `
        -SearchBase $SearchBase

    Write-Verbose 'Querying Kerberoastable accounts (user objects with SPNs)…'

    try {
        $accounts = Get-ADUser @params
    }
    catch {
        Write-Warning "Kerberoastable query failed: $_"
        return $findings
    }

    foreach ($acct in $accounts) {
        # Skip excluded prefixes
        $excluded = $false
        foreach ($prefix in $Exclude) {
            if ($acct.SamAccountName -like "$prefix*") { $excluded = $true; break }
        }
        if ($excluded) { continue }

        $spns = $acct.ServicePrincipalName -join '; '

        # Higher severity if account is privileged or password is old
        $sev = 'High'
        $notes = @()

        if ($acct.AdminCount -eq 1)  { $sev = 'Critical'; $notes += 'AdminCount=1' }
        if (-not $acct.Enabled)      { $sev = 'Low';      $notes += 'account is disabled' }

        if ($acct.PasswordLastSet) {
            $ageDays = [int]((Get-Date) - $acct.PasswordLastSet).TotalDays
            if ($ageDays -gt 365) { $notes += "password $ageDays days old" }
        }

        $detail = "SPN(s): $spns"
        if ($notes) { $detail += " [$($notes -join ', ')]" }

        $findings.Add((New-Finding -Category 'Kerberoastable' -MitreID 'T1558.003' `
            -SamAccountName $acct.SamAccountName `
            -DistinguishedName $acct.DistinguishedName `
            -Severity $sev -Detail $detail `
            -ExploitNote 'Request TGS ticket for SPN, crack offline: Rubeus kerberoast /outfile:hashes.txt'))
    }

    Write-Verbose "  Found $($findings.Count) Kerberoastable account(s)"
    return $findings
}

# ── AS-REP Roastable accounts ─────────────────────────────────────────────────

function Get-ASREPRoastableAccounts {
    [CmdletBinding()]
    param([string]$SearchBase)

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $params = Build-SearchParams `
        -Filter "DoesNotRequirePreAuth -eq 'True' -and Enabled -eq 'True'" `
        -Properties @('DoesNotRequirePreAuth', 'Enabled', 'PasswordLastSet', 'AdminCount', 'MemberOf') `
        -SearchBase $SearchBase

    Write-Verbose 'Querying AS-REP roastable accounts (no Kerberos pre-authentication)…'

    try {
        $accounts = Get-ADUser @params
    }
    catch {
        Write-Warning "AS-REP roastable query failed: $_"
        return $findings
    }

    foreach ($acct in $accounts) {
        $sev   = if ($acct.AdminCount -eq 1) { 'Critical' } else { 'High' }
        $notes = @()
        if ($acct.AdminCount -eq 1)  { $notes += 'AdminCount=1' }
        if ($acct.MemberOf.Count -gt 0) {
            $notes += "$($acct.MemberOf.Count) group(s)"
        }

        $detail = "DONT_REQ_PREAUTH flag set$(if ($notes) { " [$($notes -join ', ')]" })"

        $findings.Add((New-Finding -Category 'ASREPRoastable' -MitreID 'T1558.004' `
            -SamAccountName $acct.SamAccountName `
            -DistinguishedName $acct.DistinguishedName `
            -Severity $sev -Detail $detail `
            -ExploitNote 'No credentials needed: Rubeus asreproast /user:<sam> — crack AS-REP hash offline'))
    }

    Write-Verbose "  Found $($findings.Count) AS-REP roastable account(s)"
    return $findings
}

# ── Unconstrained delegation ──────────────────────────────────────────────────

function Get-UnconstrainedDelegation {
    [CmdletBinding()]
    param([string]$SearchBase)

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Users with unconstrained delegation
    $userParams = Build-SearchParams `
        -Filter "TrustedForDelegation -eq 'True' -and Enabled -eq 'True'" `
        -Properties @('TrustedForDelegation', 'AdminCount', 'ServicePrincipalName') `
        -SearchBase $SearchBase

    Write-Verbose 'Querying users with unconstrained delegation…'
    try {
        $users = Get-ADUser @userParams
        foreach ($u in $users) {
            $findings.Add((New-Finding -Category 'UnconstrainedDelegation' -MitreID 'T1134.001' `
                -SamAccountName $u.SamAccountName `
                -DistinguishedName $u.DistinguishedName `
                -Severity 'Critical' `
                -Detail 'User account has unconstrained delegation — caches Kerberos TGTs for all authenticating users' `
                -ExploitNote 'Compromise this host, extract TGTs with Rubeus monitor/dump, relay to any service'))
        }
    }
    catch { Write-Warning "Unconstrained delegation (users) query failed: $_" }

    # Computers with unconstrained delegation (excluding DCs — expected)
    $compParams = @{
        Filter     = { TrustedForDelegation -eq $true }
        Properties = @('TrustedForDelegation', 'OperatingSystem', 'LastLogonDate', 'IsDomainController')
    }
    if ($SearchBase) { $compParams['SearchBase'] = $SearchBase }

    Write-Verbose 'Querying computers with unconstrained delegation (excluding DCs)…'
    try {
        $computers = Get-ADComputer @compParams | Where-Object { -not $_.IsDomainController }
        foreach ($c in $computers) {
            $findings.Add((New-Finding -Category 'UnconstrainedDelegation' -MitreID 'T1134.001' `
                -SamAccountName $c.SamAccountName `
                -DistinguishedName $c.DistinguishedName `
                -Severity 'High' `
                -Detail "Computer has unconstrained delegation — OS: $($c.OperatingSystem)" `
                -ExploitNote 'Attacker who compromises this machine can steal TGTs using SpoolSample/PrinterBug or PetitPotam'))
        }
    }
    catch { Write-Warning "Unconstrained delegation (computers) query failed: $_" }

    Write-Verbose "  Found $($findings.Count) unconstrained delegation object(s)"
    return $findings
}

# ── Constrained delegation with protocol transition ───────────────────────────

function Get-ProtocolTransitionDelegation {
    [CmdletBinding()]
    param([string]$SearchBase)

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $params = Build-SearchParams `
        -Filter "TrustedToAuthForDelegation -eq 'True' -and Enabled -eq 'True'" `
        -Properties @('TrustedToAuthForDelegation', 'msDS-AllowedToDelegateTo', 'AdminCount') `
        -SearchBase $SearchBase

    Write-Verbose 'Querying constrained delegation with protocol transition (S4U2Self)…'
    try {
        $accounts = Get-ADUser @params
        foreach ($acct in $accounts) {
            $delegateTo = ($acct.'msDS-AllowedToDelegateTo' -join '; ')
            $findings.Add((New-Finding -Category 'ConstrainedDelegationS4U' -MitreID 'T1550.003' `
                -SamAccountName $acct.SamAccountName `
                -DistinguishedName $acct.DistinguishedName `
                -Severity 'High' `
                -Detail "Protocol transition enabled — allowed to delegate to: $delegateTo" `
                -ExploitNote 'Can impersonate any domain user to the target services without their credentials (S4U2Self)'))
        }
    }
    catch { Write-Warning "Protocol transition delegation query failed: $_" }

    Write-Verbose "  Found $($findings.Count) protocol-transition delegation account(s)"
    return $findings
}

# ── Summary output ────────────────────────────────────────────────────────────

function Write-AuditSummary {
    param([System.Collections.Generic.List[PSCustomObject]]$Findings)

    $severityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $colorMap      = @{ Critical = 'Red'; High = 'DarkYellow'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'Gray' }

    Write-Host ('─' * 70) -ForegroundColor DarkGray
    Write-Host '  FINDINGS SUMMARY' -ForegroundColor White
    Write-Host ('─' * 70) -ForegroundColor DarkGray

    $Findings | Group-Object Category | ForEach-Object {
        Write-Host ("  {0,-35} {1,4} finding(s)" -f $_.Name, $_.Count) -ForegroundColor White
    }
    Write-Host ''

    $Findings | Group-Object Severity | Sort-Object { $severityOrder[$_.Name] } |
        ForEach-Object {
            $icon = switch ($_.Name) {
                'Critical' { '🔴' }; 'High' { '🟠' }; 'Medium' { '🟡' };
                'Low' { '🔵' }; default { '⚪' }
            }
            Write-Host ("  $icon {0,-10} {1,4} finding(s)" -f $_.Name, $_.Count) `
                -ForegroundColor $colorMap[$_.Name]
        }

    Write-Host ''
    Write-Host '  Remediation priorities:' -ForegroundColor White
    Write-Host '    1. Remove DoesNotRequirePreAuth from all accounts (immediate)' -ForegroundColor DarkYellow
    Write-Host '    2. Review all user accounts with SPNs — move to MSA/gMSA' -ForegroundColor DarkYellow
    Write-Host '    3. Eliminate unconstrained delegation (replace with constrained)' -ForegroundColor DarkYellow
    Write-Host '    4. Add privileged service accounts to Protected Users group' -ForegroundColor Yellow
    Write-Host ''
}

# ── Entry point ───────────────────────────────────────────────────────────────

Write-AuditBanner

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

$allFindings.AddRange((Get-KerberoastableAccounts   -SearchBase $SearchBase -Exclude $ExcludeServiceAccounts))
$allFindings.AddRange((Get-ASREPRoastableAccounts    -SearchBase $SearchBase))
$allFindings.AddRange((Get-UnconstrainedDelegation   -SearchBase $SearchBase))
$allFindings.AddRange((Get-ProtocolTransitionDelegation -SearchBase $SearchBase))

if ($allFindings.Count -eq 0) {
    Write-Host '  ✅ No Kerberos attack surface findings.' -ForegroundColor Green
}
else {
    Write-AuditSummary -Findings $allFindings

    $csvPath = Join-Path $OutputPath "ADKerberosAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $allFindings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "  📄 Report saved: $csvPath" -ForegroundColor Green
}

Write-Host ''

if ($PassThru) { return $allFindings }
