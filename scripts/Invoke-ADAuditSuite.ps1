#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Master orchestrator — runs all AD audit modules and produces a consolidated report.

.DESCRIPTION
    Runs Invoke-ADUserAudit, Invoke-ADPrivilegedAudit, Invoke-ADKerberosAudit,
    Invoke-ADPasswordPolicyAudit, and Invoke-ADComputerAudit in sequence,
    aggregates all findings into a single timestamped HTML report, and prints
    an executive summary to the console.

.PARAMETER OutputPath
    Directory to write all CSV reports and the HTML summary. Default: .\reports\

.PARAMETER SearchBase
    LDAP Distinguished Name to scope queries. Default: domain root.

.PARAMETER StaleThresholdDays
    Days without logon before users/computers are flagged stale. Default: 90.

.PARAMETER IncludeLAPSCheck
    Include LAPS deployment check in the computer audit.

.PARAMETER IncludeDnsAdmins
    Include DnsAdmins in the privileged group audit.

.EXAMPLE
    .\Invoke-ADAuditSuite.ps1

.EXAMPLE
    .\Invoke-ADAuditSuite.ps1 -OutputPath C:\ADReports -StaleThresholdDays 60 -IncludeLAPSCheck -Verbose

.NOTES
    Requires : ActiveDirectory PowerShell module (RSAT or DC)
    Privilege: Domain read access. DCSync ACL check may need elevated rights.
    Duration : Varies by domain size — expect 1–10 minutes for large domains.
    Legal     : Run only on domains you own or have written authorisation to audit.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$OutputPath = '.\reports',

    [Parameter()]
    [string]$SearchBase = '',

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleThresholdDays = 90,

    [Parameter()]
    [switch]$IncludeLAPSCheck,

    [Parameter()]
    [switch]$IncludeDnsAdmins
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptRoot = $PSScriptRoot

# ── Banner ────────────────────────────────────────────────────────────────────

Write-Host ''
Write-Host ('█' * 70) -ForegroundColor DarkCyan
Write-Host ''
Write-Host '   ██████╗ ██████╗     █████╗ ██╗   ██╗██████╗ ██╗████████╗' -ForegroundColor Cyan
Write-Host '  ██╔══██╗██╔══██╗   ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝' -ForegroundColor Cyan
Write-Host '  ███████║██║  ██║   ███████║██║   ██║██║  ██║██║   ██║   ' -ForegroundColor Cyan
Write-Host '  ██╔══██║██║  ██║   ██╔══██║██║   ██║██║  ██║██║   ██║   ' -ForegroundColor Cyan
Write-Host '  ██║  ██║██████╔╝   ██║  ██║╚██████╔╝██████╔╝██║   ██║   ' -ForegroundColor Cyan
Write-Host '  ╚═╝  ╚═╝╚═════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝  ' -ForegroundColor Cyan
Write-Host ''
Write-Host '  Active Directory Security Audit Suite' -ForegroundColor White
Write-Host "  Domain: $((Get-ADDomain).DNSRoot)  |  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor DarkGray
Write-Host '  ⚠  AUTHORIZED USE ONLY — Written authorization required' -ForegroundColor Yellow
Write-Host ''
Write-Host ('█' * 70) -ForegroundColor DarkCyan
Write-Host ''

# ── Setup ─────────────────────────────────────────────────────────────────────

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$startTime   = Get-Date
$allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
$moduleResults = @{}

function Invoke-AuditModule {
    param([string]$Name, [string]$Script, [hashtable]$Params)

    Write-Host "  ▶ Running: $Name" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $results = & $Script @Params
        $sw.Stop()
        $count = if ($results) { @($results).Count } else { 0 }
        Write-Host ("    ✓ {0} complete — {1} finding(s) in {2:N1}s" -f $Name, $count, $sw.Elapsed.TotalSeconds) `
            -ForegroundColor Green
        return $results
    }
    catch {
        $sw.Stop()
        Write-Warning "  ✗ $Name failed: $_"
        return @()
    }
}

# ── Run modules ───────────────────────────────────────────────────────────────

$commonParams = @{ OutputPath = $OutputPath; PassThru = $true }
if ($SearchBase) { $commonParams['SearchBase'] = $SearchBase }

$userResults = Invoke-AuditModule -Name 'User Account Audit' `
    -Script (Join-Path $ScriptRoot 'Invoke-ADUserAudit.ps1') `
    -Params ($commonParams + @{ StaleLogonDays = $StaleThresholdDays })

$privResults = Invoke-AuditModule -Name 'Privileged Access Audit' `
    -Script (Join-Path $ScriptRoot 'Invoke-ADPrivilegedAudit.ps1') `
    -Params ($commonParams + @{ IncludeDnsAdmins = $IncludeDnsAdmins.IsPresent })

$kerbResults = Invoke-AuditModule -Name 'Kerberos Attack Surface Audit' `
    -Script (Join-Path $ScriptRoot 'Invoke-ADKerberosAudit.ps1') `
    -Params $commonParams

$pwdResults = Invoke-AuditModule -Name 'Password Policy Audit' `
    -Script (Join-Path $ScriptRoot 'Invoke-ADPasswordPolicyAudit.ps1') `
    -Params $commonParams

$compResults = Invoke-AuditModule -Name 'Computer Account Audit' `
    -Script (Join-Path $ScriptRoot 'Invoke-ADComputerAudit.ps1') `
    -Params ($commonParams + @{
        StaleThresholdDays = $StaleThresholdDays
        IncludeLAPSCheck   = $IncludeLAPSCheck.IsPresent
    })

# Aggregate
foreach ($r in @($userResults, $privResults, $kerbResults, $pwdResults, $compResults)) {
    if ($r) { $allFindings.AddRange([PSCustomObject[]]@($r)) }
}

$moduleResults = @{
    'User Accounts'    = @($userResults).Count
    'Privileged Access' = @($privResults).Count
    'Kerberos'         = @($kerbResults).Count
    'Password Policy'  = @($pwdResults).Count
    'Computers'        = @($compResults).Count
}

# ── Executive summary ─────────────────────────────────────────────────────────

$elapsed       = (Get-Date) - $startTime
$severityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
$colorMap      = @{ Critical = 'Red'; High = 'DarkYellow'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'Gray' }

Write-Host ''
Write-Host ('═' * 70) -ForegroundColor DarkCyan
Write-Host '  EXECUTIVE SUMMARY' -ForegroundColor White
Write-Host ('═' * 70) -ForegroundColor DarkCyan
Write-Host ("  Domain       : $((Get-ADDomain).DNSRoot)") -ForegroundColor White
Write-Host ("  Completed    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')") -ForegroundColor White
Write-Host ("  Duration     : $([math]::Round($elapsed.TotalSeconds, 1))s") -ForegroundColor White
Write-Host ("  Total findings: $($allFindings.Count)") -ForegroundColor White
Write-Host ''

Write-Host '  By Severity:' -ForegroundColor White
$allFindings | Group-Object Severity | Sort-Object { $severityOrder[$_.Name] } |
    ForEach-Object {
        $icon = switch ($_.Name) {
            'Critical' { '🔴' }; 'High' { '🟠' }; 'Medium' { '🟡' };
            'Low' { '🔵' }; default { '⚪' }
        }
        Write-Host ("  $icon {0,-10} {1,4}" -f $_.Name, $_.Count) -ForegroundColor $colorMap[$_.Name]
    }

Write-Host ''
Write-Host '  By Module:' -ForegroundColor White
foreach ($mod in $moduleResults.GetEnumerator() | Sort-Object Value -Descending) {
    Write-Host ("    {0,-25} {1,4} finding(s)" -f $mod.Key, $mod.Value) -ForegroundColor Gray
}

# Critical findings callout
$criticals = $allFindings | Where-Object { $_.Severity -eq 'Critical' }
if ($criticals) {
    Write-Host ''
    Write-Host '  🔴 CRITICAL FINDINGS REQUIRING IMMEDIATE ACTION:' -ForegroundColor Red
    foreach ($c in $criticals | Select-Object -First 10) {
        $target = if ($c.PSObject.Properties['SamAccountName']) { $c.SamAccountName } `
                  elseif ($c.PSObject.Properties['ComputerName']) { $c.ComputerName } `
                  else { $c.PolicyName }
        Write-Host ("    • [$($c.Category)] $target — $($c.Detail)" -f '') -ForegroundColor Red
    }
}

Write-Host ''

# ── Generate HTML report ──────────────────────────────────────────────────────

function New-HTMLReport {
    param(
        [System.Collections.Generic.List[PSCustomObject]]$Findings,
        [string]$OutputPath,
        [hashtable]$ModuleResults
    )

    $domain   = (Get-ADDomain).DNSRoot
    $date     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $critical = ($Findings | Where-Object Severity -eq 'Critical').Count
    $high     = ($Findings | Where-Object Severity -eq 'High').Count
    $medium   = ($Findings | Where-Object Severity -eq 'Medium').Count
    $low      = ($Findings | Where-Object Severity -eq 'Low').Count

    $rowsHtml = $Findings | Sort-Object { $severityOrder[$_.Severity] } | ForEach-Object {
        $sevColor = switch ($_.Severity) {
            'Critical' { '#ff4444' }; 'High' { '#ff8c00' };
            'Medium' { '#ffd700' }; 'Low' { '#00aaff' }; default { '#808080' }
        }
        $target = if ($_.PSObject.Properties['SamAccountName'] -and $_.SamAccountName) {
            $_.SamAccountName
        } elseif ($_.PSObject.Properties['ComputerName'] -and $_.ComputerName) {
            $_.ComputerName
        } elseif ($_.PSObject.Properties['PolicyName'] -and $_.PolicyName) {
            $_.PolicyName
        } else { '—' }

        $category = if ($_.PSObject.Properties['Category'] -and $_.Category) { $_.Category }
                    elseif ($_.PSObject.Properties['Setting'] -and $_.Setting) { $_.Setting }
                    else { '—' }

        "<tr>
          <td><span style='color:$sevColor;font-weight:bold'>$($_.Severity)</span></td>
          <td>$category</td>
          <td><code>$target</code></td>
          <td>$($_.Detail)</td>
        </tr>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AD Security Audit — $domain</title>
<style>
  body { background:#0d1117; color:#c9d1d9; font-family:'Courier New',monospace; margin:0; padding:20px; }
  h1,h2,h3 { color:#00FF41; }
  .banner { border:1px solid #30363d; padding:20px; margin-bottom:20px; background:#161b22; }
  .summary-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:20px 0; }
  .sev-card { padding:16px; border-radius:6px; text-align:center; }
  .critical { background:#2d0909; border:1px solid #ff4444; }
  .high     { background:#2d1a00; border:1px solid #ff8c00; }
  .medium   { background:#2d2700; border:1px solid #ffd700; }
  .low      { background:#00122d; border:1px solid #00aaff; }
  .sev-count { font-size:2em; font-weight:bold; }
  table { width:100%; border-collapse:collapse; margin-top:20px; }
  th { background:#161b22; color:#00FF41; padding:10px; text-align:left; border-bottom:1px solid #30363d; }
  td { padding:8px 10px; border-bottom:1px solid #21262d; font-size:0.9em; vertical-align:top; }
  tr:hover { background:#161b22; }
  code { background:#21262d; padding:2px 6px; border-radius:3px; color:#f0883e; }
  .warning { color:#ffd700; border:1px solid #ffd700; padding:10px; margin-bottom:20px; }
</style>
</head>
<body>
<div class="banner">
  <h1>🛡 Active Directory Security Audit Report</h1>
  <p><strong>Domain:</strong> $domain &nbsp;|&nbsp; <strong>Generated:</strong> $date</p>
  <p class="warning">⚠ CONFIDENTIAL — Authorized use only. Contains sensitive security findings.</p>
</div>

<h2>Executive Summary</h2>
<div class="summary-grid">
  <div class="sev-card critical"><div class="sev-count" style="color:#ff4444">$critical</div>Critical</div>
  <div class="sev-card high">   <div class="sev-count" style="color:#ff8c00">$high</div>High</div>
  <div class="sev-card medium"> <div class="sev-count" style="color:#ffd700">$medium</div>Medium</div>
  <div class="sev-card low">    <div class="sev-count" style="color:#00aaff">$low</div>Low</div>
</div>

<h2>All Findings ($($Findings.Count) total)</h2>
<table>
  <tr><th>Severity</th><th>Category</th><th>Target</th><th>Detail</th></tr>
  $($rowsHtml -join "`n")
</table>

<br><p style="color:#30363d;font-size:0.8em">Generated by ad-audit-toolkit — github.com/n0t-intersys/ad-audit-toolkit</p>
</body>
</html>
"@

    $htmlPath = Join-Path $OutputPath "ADAuditReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    return $htmlPath
}

$htmlPath = New-HTMLReport -Findings $allFindings -OutputPath $OutputPath -ModuleResults $moduleResults
Write-Host "  📊 HTML report : $htmlPath" -ForegroundColor Green
Write-Host "  📁 CSV reports : $OutputPath" -ForegroundColor Green
Write-Host ''
