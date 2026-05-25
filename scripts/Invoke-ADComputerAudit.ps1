#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Audits Active Directory computer accounts for stale systems, EOL operating
    systems, LAPS deployment, and delegation risks.

.DESCRIPTION
    Identifies stale computer accounts, maps operating system versions to
    end-of-life status, checks for Local Administrator Password Solution (LAPS)
    deployment, detects computers with unconstrained delegation, and reports
    computers that have never authenticated to the domain.

    Findings covered:
      - Stale computer accounts (no domain logon beyond threshold)
      - End-of-life / unsupported operating systems
      - Computers without LAPS (ms-Mcs-AdmPwdExpirationTime not set)
      - Computers with unconstrained Kerberos delegation (non-DCs)
      - Computer accounts that have never authenticated

.PARAMETER StaleThresholdDays
    Days since last logon before a computer is flagged as stale. Default: 90.

.PARAMETER OutputPath
    Directory to write CSV output. Default: .\reports\

.PARAMETER SearchBase
    LDAP Distinguished Name to scope the search. Default: domain root.

.PARAMETER IncludeLAPSCheck
    Include LAPS deployment check (requires ms-Mcs-AdmPwdExpirationTime attribute).

.PARAMETER PassThru
    Return result objects to the pipeline.

.EXAMPLE
    .\Invoke-ADComputerAudit.ps1

.EXAMPLE
    .\Invoke-ADComputerAudit.ps1 -StaleThresholdDays 60 -IncludeLAPSCheck -OutputPath C:\Reports

.NOTES
    Requires : ActiveDirectory PowerShell module
    Privilege: Domain read access. LAPS check requires the LAPS schema extension.
    Legal     : Run only on domains you own or have written authorisation to audit.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleThresholdDays = 90,

    [Parameter()]
    [string]$OutputPath = '.\reports',

    [Parameter()]
    [string]$SearchBase = '',

    [Parameter()]
    [switch]$IncludeLAPSCheck,

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── EOL OS reference table ────────────────────────────────────────────────────

$EOL_OPERATING_SYSTEMS = @{
    # Windows Workstation
    'Windows XP'          = @{ EOL = '2014-04-08'; Severity = 'Critical' }
    'Windows Vista'       = @{ EOL = '2017-04-11'; Severity = 'Critical' }
    'Windows 7'           = @{ EOL = '2020-01-14'; Severity = 'Critical' }
    'Windows 8'           = @{ EOL = '2016-01-12'; Severity = 'Critical' }
    'Windows 8.1'         = @{ EOL = '2023-01-10'; Severity = 'High'     }
    'Windows 10'          = @{ EOL = '2025-10-14'; Severity = 'Medium'   }  # varies by edition
    # Windows Server
    'Windows Server 2003' = @{ EOL = '2015-07-14'; Severity = 'Critical' }
    'Windows Server 2008' = @{ EOL = '2020-01-14'; Severity = 'Critical' }
    'Windows Server 2012' = @{ EOL = '2023-10-10'; Severity = 'High'     }
    'Windows Server 2016' = @{ EOL = '2027-01-12'; Severity = 'Low'      }
}

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-AuditBanner {
    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host '  AD COMPUTER ACCOUNT AUDIT' -ForegroundColor Cyan
    Write-Host '  ⚠  Run only on domains you own or have written authorisation to audit.' -ForegroundColor Yellow
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host ''
}

function New-Finding {
    param(
        [string]$Category,
        [string]$ComputerName,
        [string]$DistinguishedName,
        [string]$OperatingSystem,
        [string]$Detail,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity
    )
    [PSCustomObject]@{
        Timestamp         = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Severity          = $Severity
        Category          = $Category
        ComputerName      = $ComputerName
        DistinguishedName = $DistinguishedName
        OperatingSystem   = $OperatingSystem
        Detail            = $Detail
    }
}

function Get-EOLInfo {
    param([string]$OS)
    foreach ($key in $EOL_OPERATING_SYSTEMS.Keys) {
        if ($OS -match [regex]::Escape($key)) {
            return $EOL_OPERATING_SYSTEMS[$key]
        }
    }
    return $null
}

# ── Main audit ────────────────────────────────────────────────────────────────

function Invoke-ComputerAudit {
    [CmdletBinding()]
    param([int]$StaleThresholdDays, [string]$SearchBase, [bool]$IncludeLAPS)

    $findings    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $staleDate   = (Get-Date).AddDays(-$StaleThresholdDays)
    $osInventory = @{}

    $props = @(
        'LastLogonDate', 'OperatingSystem', 'OperatingSystemVersion',
        'Enabled', 'TrustedForDelegation', 'IsDomainController',
        'whenCreated', 'IPv4Address', 'DNSHostName'
    )
    if ($IncludeLAPS) { $props += 'ms-Mcs-AdmPwdExpirationTime' }

    $queryParams = @{
        Filter     = '*'
        Properties = $props
    }
    if ($SearchBase) { $queryParams['SearchBase'] = $SearchBase }

    Write-Verbose 'Querying Active Directory for all computer objects…'
    try {
        $computers = Get-ADComputer @queryParams
    }
    catch {
        Write-Error "Failed to query AD computer objects: $_"
        return
    }

    Write-Verbose "  Retrieved $($computers.Count) computer object(s)"

    foreach ($comp in $computers) {
        $name = $comp.Name
        $dn   = $comp.DistinguishedName
        $os   = $comp.OperatingSystem ?? 'Unknown'

        # ── OS inventory ────────────────────────────────────────────────────
        if (-not $osInventory.ContainsKey($os)) { $osInventory[$os] = 0 }
        $osInventory[$os]++

        # ── Stale accounts ───────────────────────────────────────────────────
        if ($comp.Enabled) {
            if (-not $comp.LastLogonDate) {
                $findings.Add((New-Finding -Category 'StaleComputer' -ComputerName $name `
                    -DistinguishedName $dn -OperatingSystem $os -Severity 'High' `
                    -Detail 'Computer has never authenticated to the domain'))
            }
            elseif ($comp.LastLogonDate -lt $staleDate) {
                $daysStale = [int]((Get-Date) - $comp.LastLogonDate).TotalDays
                $findings.Add((New-Finding -Category 'StaleComputer' -ComputerName $name `
                    -DistinguishedName $dn -OperatingSystem $os -Severity 'Medium' `
                    -Detail "No domain logon in $daysStale days (threshold: $StaleThresholdDays)"))
            }
        }

        # ── EOL OS ───────────────────────────────────────────────────────────
        $eolInfo = Get-EOLInfo -OS $os
        if ($eolInfo) {
            $findings.Add((New-Finding -Category 'EndOfLifeOS' -ComputerName $name `
                -DistinguishedName $dn -OperatingSystem $os `
                -Severity $eolInfo.Severity `
                -Detail "EOL OS detected — $os (end of support: $($eolInfo.EOL)) — no security patches available"))
        }

        # ── LAPS deployment ──────────────────────────────────────────────────
        if ($IncludeLAPS -and $comp.Enabled -and -not $comp.IsDomainController) {
            $lapsAttr = $comp.'ms-Mcs-AdmPwdExpirationTime'
            if (-not $lapsAttr) {
                $findings.Add((New-Finding -Category 'LAPSNotDeployed' -ComputerName $name `
                    -DistinguishedName $dn -OperatingSystem $os -Severity 'Medium' `
                    -Detail 'LAPS not deployed — local administrator password is not centrally managed; lateral movement risk'))
            }
        }

        # ── Unconstrained delegation (non-DCs) ───────────────────────────────
        if ($comp.TrustedForDelegation -and -not $comp.IsDomainController) {
            $findings.Add((New-Finding -Category 'UnconstrainedDelegation' -ComputerName $name `
                -DistinguishedName $dn -OperatingSystem $os -Severity 'High' `
                -Detail 'Computer has unconstrained Kerberos delegation — attacker who compromises this host can steal TGTs (ATT&CK T1134.001)'))
        }
    }

    # Print OS inventory
    Write-Host '  Operating System Inventory:' -ForegroundColor White
    $osInventory.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
        $eolInfo = Get-EOLInfo -OS $_.Key
        $eolTag  = if ($eolInfo) { " [EOL: $($eolInfo.EOL)]" } else { '' }
        $color   = if ($eolInfo) {
            switch ($eolInfo.Severity) { 'Critical' { 'Red' } 'High' { 'DarkYellow' } default { 'Yellow' } }
        } else { 'Gray' }
        Write-Host ("    {0,-45} {1,5} host(s){2}" -f $_.Key, $_.Value, $eolTag) -ForegroundColor $color
    }
    Write-Host ''

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
}

# ── Entry point ───────────────────────────────────────────────────────────────

Write-AuditBanner

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$findings = Invoke-ComputerAudit `
    -StaleThresholdDays $StaleThresholdDays `
    -SearchBase $SearchBase `
    -IncludeLAPS:$IncludeLAPSCheck.IsPresent

if ($findings.Count -eq 0) {
    Write-Host '  ✅ No computer account findings.' -ForegroundColor Green
}
else {
    Write-AuditSummary -Findings $findings

    $csvPath = Join-Path $OutputPath "ADComputerAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "  📄 Report saved: $csvPath" -ForegroundColor Green
}

Write-Host ''

if ($PassThru) { return $findings }
