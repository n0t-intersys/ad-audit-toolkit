#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Audits Active Directory user accounts for security risks.

.DESCRIPTION
    Identifies stale accounts, insecure password configurations, locked-out
    accounts, and other user-level weaknesses across the domain. Outputs
    structured findings to CSV and prints a colour-coded console summary.

    Findings covered:
      - Stale accounts (no interactive logon beyond threshold)
      - Password Never Expires
      - Password Not Required
      - Reversible Encryption Enabled
      - Accounts with passwords older than threshold
      - Locked-out accounts
      - Disabled accounts still holding group memberships
      - Accounts missing a manager attribute

.PARAMETER StaleLogonDays
    Days since last logon before account is flagged as stale. Default: 90.

.PARAMETER PasswordAgeDays
    Days since last password set before flagging. Default: 90.

.PARAMETER OutputPath
    Directory to write CSV output files. Default: .\reports\

.PARAMETER SearchBase
    LDAP Distinguished Name to scope the search. Default: domain root.

.PARAMETER PassThru
    Return result objects to the pipeline in addition to writing CSV.

.EXAMPLE
    .\Invoke-ADUserAudit.ps1

.EXAMPLE
    .\Invoke-ADUserAudit.ps1 -StaleLogonDays 60 -OutputPath C:\AuditReports

.EXAMPLE
    .\Invoke-ADUserAudit.ps1 -SearchBase "OU=Corp,DC=contoso,DC=com" -PassThru

.NOTES
    Requires : ActiveDirectory PowerShell module (RSAT or on a DC)
    Privilege: Domain read access — Domain Admin is NOT required
    Legal     : Run only on domains you own or have written authorisation to audit.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleLogonDays = 90,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$PasswordAgeDays = 90,

    [Parameter()]
    [string]$OutputPath = '.\reports',

    [Parameter()]
    [string]$SearchBase = '',

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-AuditBanner {
    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host '  AD USER ACCOUNT AUDIT' -ForegroundColor Cyan
    Write-Host '  ⚠  Run only on domains you own or have written authorisation to audit.' -ForegroundColor Yellow
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host ''
}

function Get-ADSearchParams {
    param([string]$SearchBase)
    $params = @{
        Filter     = { Enabled -eq $true -or Enabled -eq $false }
        Properties = @(
            'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires',
            'PasswordNotRequired', 'AllowReversiblePasswordEncryption',
            'LockedOut', 'Enabled', 'MemberOf', 'Manager',
            'DoesNotRequirePreAuth', 'AdminCount', 'Description',
            'whenCreated', 'SamAccountName', 'DistinguishedName'
        )
    }
    if ($SearchBase) { $params['SearchBase'] = $SearchBase }
    return $params
}

function New-Finding {
    param(
        [string]$Category,
        [string]$SamAccountName,
        [string]$DistinguishedName,
        [string]$Detail,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity
    )
    [PSCustomObject]@{
        Timestamp         = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Severity          = $Severity
        Category          = $Category
        SamAccountName    = $SamAccountName
        DistinguishedName = $DistinguishedName
        Detail            = $Detail
    }
}

# ── Main audit logic ──────────────────────────────────────────────────────────

function Invoke-UserAudit {
    [CmdletBinding()]
    param(
        [int]$StaleLogonDays,
        [int]$PasswordAgeDays,
        [string]$SearchBase
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $staleDate    = (Get-Date).AddDays(-$StaleLogonDays)
    $pwAgeDate    = (Get-Date).AddDays(-$PasswordAgeDays)
    $searchParams = Get-ADSearchParams -SearchBase $SearchBase

    Write-Verbose 'Querying Active Directory for all user objects…'
    try {
        $allUsers = Get-ADUser @searchParams
    }
    catch {
        Write-Error "Failed to query Active Directory: $_"
        return
    }

    Write-Verbose "Retrieved $($allUsers.Count) user objects."

    foreach ($user in $allUsers) {
        $dn  = $user.DistinguishedName
        $sam = $user.SamAccountName

        # ── Stale accounts (enabled, never logged on or stale) ──
        if ($user.Enabled) {
            if (-not $user.LastLogonDate) {
                $findings.Add((New-Finding -Category 'StaleAccount' -SamAccountName $sam `
                    -DistinguishedName $dn -Severity 'High' `
                    -Detail 'Enabled account has never logged on'))
            }
            elseif ($user.LastLogonDate -lt $staleDate) {
                $daysStale = [int]((Get-Date) - $user.LastLogonDate).TotalDays
                $findings.Add((New-Finding -Category 'StaleAccount' -SamAccountName $sam `
                    -DistinguishedName $dn -Severity 'Medium' `
                    -Detail "No logon for $daysStale days (threshold: $StaleLogonDays)"))
            }
        }

        # ── Password Never Expires ──
        if ($user.PasswordNeverExpires -and $user.Enabled) {
            $sev = if ($user.AdminCount -eq 1) { 'Critical' } else { 'High' }
            $findings.Add((New-Finding -Category 'PasswordNeverExpires' -SamAccountName $sam `
                -DistinguishedName $dn -Severity $sev `
                -Detail "Password never expires$(if ($user.AdminCount -eq 1) { ' [AdminCount=1 — privileged account]' })"))
        }

        # ── Password Not Required ──
        if ($user.PasswordNotRequired) {
            $findings.Add((New-Finding -Category 'PasswordNotRequired' -SamAccountName $sam `
                -DistinguishedName $dn -Severity 'Critical' `
                -Detail 'PASSWD_NOTREQD flag set — account can authenticate with blank password'))
        }

        # ── Reversible Encryption ──
        if ($user.AllowReversiblePasswordEncryption) {
            $findings.Add((New-Finding -Category 'ReversibleEncryption' -SamAccountName $sam `
                -DistinguishedName $dn -Severity 'Critical' `
                -Detail 'Password stored with reversible encryption — equivalent to plaintext'))
        }

        # ── Old password ──
        if ($user.Enabled -and $user.PasswordLastSet -and $user.PasswordLastSet -lt $pwAgeDate) {
            $ageDays = [int]((Get-Date) - $user.PasswordLastSet).TotalDays
            $findings.Add((New-Finding -Category 'OldPassword' -SamAccountName $sam `
                -DistinguishedName $dn -Severity 'Low' `
                -Detail "Password last set $ageDays days ago (threshold: $PasswordAgeDays)"))
        }

        # ── Locked out ──
        if ($user.LockedOut) {
            $findings.Add((New-Finding -Category 'LockedOut' -SamAccountName $sam `
                -DistinguishedName $dn -Severity 'Info' `
                -Detail 'Account is currently locked out'))
        }

        # ── Disabled account still in groups ──
        if (-not $user.Enabled -and $user.MemberOf.Count -gt 0) {
            $groupCount = $user.MemberOf.Count
            $findings.Add((New-Finding -Category 'DisabledWithMemberships' -SamAccountName $sam `
                -DistinguishedName $dn -Severity 'Medium' `
                -Detail "Disabled account retains $groupCount group membership(s) — access not fully revoked"))
        }

        # ── No manager ──
        if ($user.Enabled -and -not $user.Manager) {
            $findings.Add((New-Finding -Category 'NoManager' -SamAccountName $sam `
                -DistinguishedName $dn -Severity 'Low' `
                -Detail 'No manager attribute — orphaned accounts evade access review processes'))
        }
    }

    return $findings
}

# ── Output & reporting ────────────────────────────────────────────────────────

function Write-AuditSummary {
    param([System.Collections.Generic.List[PSCustomObject]]$Findings)

    $severityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $colorMap      = @{ Critical = 'Red'; High = 'DarkYellow'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'Gray' }

    Write-Host ''
    Write-Host ('─' * 70) -ForegroundColor DarkGray
    Write-Host '  FINDINGS SUMMARY' -ForegroundColor White
    Write-Host ('─' * 70) -ForegroundColor DarkGray

    $grouped = $Findings | Group-Object Severity | Sort-Object { $severityOrder[$_.Name] }
    foreach ($group in $grouped) {
        $icon = switch ($group.Name) {
            'Critical' { '🔴' }; 'High' { '🟠' }; 'Medium' { '🟡' }; 'Low' { '🔵' }; default { '⚪' }
        }
        Write-Host ("  $icon {0,-10} {1,4} finding(s)" -f $group.Name, $group.Count) `
            -ForegroundColor $colorMap[$group.Name]
    }

    Write-Host ''
    Write-Host '  Top findings:' -ForegroundColor White
    $Findings | Where-Object { $_.Severity -in 'Critical', 'High' } |
        Select-Object -First 10 |
        ForEach-Object {
            Write-Host ("    [{0}] {1} — {2}" -f $_.Severity, $_.SamAccountName, $_.Detail) `
                -ForegroundColor $colorMap[$_.Severity]
        }
    Write-Host ''
}

# ── Entry point ───────────────────────────────────────────────────────────────

Write-AuditBanner

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Verbose "Created output directory: $OutputPath"
}

$auditParams = @{
    StaleLogonDays = $StaleLogonDays
    PasswordAgeDays = $PasswordAgeDays
    SearchBase      = $SearchBase
    Verbose         = ($PSBoundParameters['Verbose'] -eq $true)
}

$findings = Invoke-UserAudit @auditParams

if ($findings.Count -eq 0) {
    Write-Host '  ✅ No user account findings.' -ForegroundColor Green
}
else {
    Write-AuditSummary -Findings $findings

    $csvPath = Join-Path $OutputPath "ADUserAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "  📄 Report saved: $csvPath" -ForegroundColor Green
}

Write-Host ''

if ($PassThru) { return $findings }
