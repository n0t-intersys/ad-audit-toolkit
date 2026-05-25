#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Audits the Default Domain Password Policy and Fine-Grained Password Policies
    against CIS Benchmark and NIST SP 800-63B recommendations.

.DESCRIPTION
    Retrieves the Default Domain Password Policy and all Fine-Grained Password
    Policies (PSOs), evaluates each setting against CIS L1 and NIST baselines,
    and reports gaps with severity ratings. Also identifies which users and groups
    each PSO applies to.

    CIS Benchmark L1 (Windows Server 2022):
      - Min password length : ≥ 14 characters
      - Password history     : ≥ 24 passwords
      - Max password age     : ≤ 60 days (or disabled per NIST)
      - Lockout threshold    : 1–10 invalid attempts
      - Lockout duration     : ≥ 15 minutes
      - Complexity           : Enabled

    NIST SP 800-63B divergence (noted, not flagged as failure):
      - NIST does NOT recommend max password age (avoid forcing periodic rotation)
      - NIST recommends checking against breach databases instead

.PARAMETER OutputPath
    Directory to write CSV output. Default: .\reports\

.PARAMETER PassThru
    Return result objects to the pipeline.

.EXAMPLE
    .\Invoke-ADPasswordPolicyAudit.ps1

.EXAMPLE
    .\Invoke-ADPasswordPolicyAudit.ps1 -OutputPath C:\AuditReports -Verbose

.NOTES
    Requires : ActiveDirectory PowerShell module
    Privilege: Domain read access. Fine-Grained PSO reading may need
               'Read msDS-PasswordSettings-Container' delegation.
    Legal     : Run only on domains you own or have written authorisation to audit.
    Reference : CIS Microsoft Windows Server 2022 Benchmark v2.0.0
                NIST SP 800-63B Digital Identity Guidelines
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$OutputPath = '.\reports',

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── CIS / NIST baselines ──────────────────────────────────────────────────────

$CIS_BASELINE = @{
    MinPasswordLength       = @{ Min = 14;   Severity = 'High';   Setting = 'MinPasswordLength' }
    PasswordHistoryCount    = @{ Min = 24;   Severity = 'Medium'; Setting = 'PasswordHistoryCount' }
    MaxPasswordAge          = @{ Max = 60;   Severity = 'Medium'; Setting = 'MaxPasswordAge' }   # CIS says ≤60d; NIST disagrees
    LockoutThreshold        = @{ Min = 1; Max = 10; Severity = 'High'; Setting = 'LockoutThreshold' }
    LockoutDuration         = @{ Min = 15;   Severity = 'Medium'; Setting = 'LockoutDuration' }
    LockoutObservationWindow = @{ Min = 15;  Severity = 'Low';    Setting = 'LockoutObservationWindow' }
    ComplexityEnabled       = @{ Expected = $true; Severity = 'High'; Setting = 'ComplexityEnabled' }
    ReversibleEncryption    = @{ Expected = $false; Severity = 'Critical'; Setting = 'ReversibleEncryptionEnabled' }
}

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-AuditBanner {
    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host '  AD PASSWORD POLICY AUDIT' -ForegroundColor Cyan
    Write-Host '  Baseline: CIS Windows Server 2022 L1 + NIST SP 800-63B' -ForegroundColor DarkGray
    Write-Host '  ⚠  Run only on domains you own or have written authorisation to audit.' -ForegroundColor Yellow
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host ''
}

function New-Finding {
    param(
        [string]$PolicyName,
        [string]$Setting,
        [string]$CurrentValue,
        [string]$RecommendedValue,
        [string]$Detail,
        [string]$Reference,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity
    )
    [PSCustomObject]@{
        Timestamp        = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Severity         = $Severity
        PolicyName       = $PolicyName
        Setting          = $Setting
        CurrentValue     = $CurrentValue
        RecommendedValue = $RecommendedValue
        Detail           = $Detail
        Reference        = $Reference
    }
}

function Get-TimeSpanDays {
    param([object]$Value)
    if ($null -eq $Value) { return 'Not set' }
    if ($Value -is [timespan]) { return [math]::Abs($Value.Days) }
    return $Value
}

function Get-TimeSpanMinutes {
    param([object]$Value)
    if ($null -eq $Value) { return 'Not set' }
    if ($Value -is [timespan]) { return [math]::Abs($Value.TotalMinutes) }
    return $Value
}

# ── Policy evaluation ─────────────────────────────────────────────────────────

function Test-PasswordPolicy {
    param(
        [object]$Policy,
        [string]$PolicyName
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Min password length
    $minLen = $Policy.MinPasswordLength
    if ($minLen -lt $CIS_BASELINE.MinPasswordLength.Min) {
        $findings.Add((New-Finding -PolicyName $PolicyName -Setting 'MinPasswordLength' `
            -CurrentValue $minLen -RecommendedValue ">= $($CIS_BASELINE.MinPasswordLength.Min)" `
            -Severity $CIS_BASELINE.MinPasswordLength.Severity `
            -Detail "Minimum password length is $minLen — CIS requires ≥14, NIST recommends ≥15 or passphrase" `
            -Reference 'CIS L1 1.1.4 / NIST SP 800-63B §5.1.1'))
    }

    # Password history
    $history = $Policy.PasswordHistoryCount
    if ($history -lt $CIS_BASELINE.PasswordHistoryCount.Min) {
        $findings.Add((New-Finding -PolicyName $PolicyName -Setting 'PasswordHistoryCount' `
            -CurrentValue $history -RecommendedValue ">= $($CIS_BASELINE.PasswordHistoryCount.Min)" `
            -Severity $CIS_BASELINE.PasswordHistoryCount.Severity `
            -Detail "Password history is $history — CIS requires ≥24 to prevent cycling" `
            -Reference 'CIS L1 1.1.1'))
    }

    # Max password age (CIS perspective — NIST notes added)
    $maxAgeDays = Get-TimeSpanDays -Value $Policy.MaxPasswordAge
    if ($maxAgeDays -ne 'Not set' -and $maxAgeDays -gt $CIS_BASELINE.MaxPasswordAge.Max) {
        $findings.Add((New-Finding -PolicyName $PolicyName -Setting 'MaxPasswordAge' `
            -CurrentValue "${maxAgeDays}d" -RecommendedValue "<= $($CIS_BASELINE.MaxPasswordAge.Max)d (CIS) or Disabled (NIST)" `
            -Severity $CIS_BASELINE.MaxPasswordAge.Severity `
            -Detail "Max password age is ${maxAgeDays} days — CIS L1 says ≤60d. NIST SP 800-63B recommends NOT expiring unless compromise suspected" `
            -Reference 'CIS L1 1.1.2 / NIST SP 800-63B §5.1.1'))
    }

    # Lockout threshold
    $lockThreshold = $Policy.LockoutThreshold
    if ($lockThreshold -eq 0) {
        $findings.Add((New-Finding -PolicyName $PolicyName -Setting 'LockoutThreshold' `
            -CurrentValue 'Disabled (0)' -RecommendedValue '1–10' `
            -Severity 'High' `
            -Detail 'Account lockout is DISABLED — unlimited brute-force attempts permitted' `
            -Reference 'CIS L1 1.2.1'))
    }
    elseif ($lockThreshold -gt $CIS_BASELINE.LockoutThreshold.Max) {
        $findings.Add((New-Finding -PolicyName $PolicyName -Setting 'LockoutThreshold' `
            -CurrentValue $lockThreshold -RecommendedValue '1–10' `
            -Severity $CIS_BASELINE.LockoutThreshold.Severity `
            -Detail "Lockout threshold is $lockThreshold — allows too many attempts before locking; CIS requires ≤10" `
            -Reference 'CIS L1 1.2.1'))
    }

    # Lockout duration
    $lockDuration = Get-TimeSpanMinutes -Value $Policy.LockoutDuration
    if ($lockDuration -ne 'Not set' -and $lockDuration -lt $CIS_BASELINE.LockoutDuration.Min) {
        $findings.Add((New-Finding -PolicyName $PolicyName -Setting 'LockoutDuration' `
            -CurrentValue "${lockDuration}m" -RecommendedValue ">= $($CIS_BASELINE.LockoutDuration.Min)m" `
            -Severity $CIS_BASELINE.LockoutDuration.Severity `
            -Detail "Lockout duration is ${lockDuration} minutes — too short; CIS requires ≥15 min to deter brute-force" `
            -Reference 'CIS L1 1.2.2'))
    }

    # Complexity
    $complexity = $Policy.ComplexityEnabled
    if (-not $complexity) {
        $findings.Add((New-Finding -PolicyName $PolicyName -Setting 'ComplexityEnabled' `
            -CurrentValue 'False' -RecommendedValue 'True' `
            -Severity $CIS_BASELINE.ComplexityEnabled.Severity `
            -Detail 'Password complexity is disabled — users can set trivially simple passwords' `
            -Reference 'CIS L1 1.1.5'))
    }

    # Reversible encryption
    $reversible = $Policy.ReversibleEncryptionEnabled
    if ($reversible) {
        $findings.Add((New-Finding -PolicyName $PolicyName -Setting 'ReversibleEncryptionEnabled' `
            -CurrentValue 'True' -RecommendedValue 'False' `
            -Severity $CIS_BASELINE.ReversibleEncryption.Severity `
            -Detail 'Reversible encryption is ENABLED — passwords stored in recoverable form (functionally plaintext)' `
            -Reference 'CIS L1 1.1.6'))
    }

    return $findings
}

# ── PSO subject enumeration ───────────────────────────────────────────────────

function Get-PSOSubjects {
    param([Microsoft.ActiveDirectory.Management.ADFineGrainedPasswordPolicy]$PSO)

    $subjects = [System.Collections.Generic.List[string]]::new()
    try {
        $appliesTo = Get-ADFineGrainedPasswordPolicySubject -Identity $PSO -ErrorAction SilentlyContinue
        foreach ($s in $appliesTo) {
            $subjects.Add("$($s.objectClass):$($s.SamAccountName)")
        }
    }
    catch { <# not all environments allow this query #> }

    return ($subjects -join '; ')
}

# ── Main ──────────────────────────────────────────────────────────────────────

function Invoke-PasswordPolicyAudit {
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Default Domain Password Policy
    Write-Verbose 'Retrieving Default Domain Password Policy…'
    try {
        $ddpp = Get-ADDefaultDomainPasswordPolicy
        Write-Host '  Default Domain Password Policy:' -ForegroundColor White
        Write-Host ("    Min Length       : {0}" -f $ddpp.MinPasswordLength)
        Write-Host ("    Password History : {0}" -f $ddpp.PasswordHistoryCount)
        Write-Host ("    Max Age          : {0}" -f (Get-TimeSpanDays $ddpp.MaxPasswordAge))
        Write-Host ("    Lockout Threshold: {0}" -f $ddpp.LockoutThreshold)
        Write-Host ("    Lockout Duration : {0} min" -f (Get-TimeSpanMinutes $ddpp.LockoutDuration))
        Write-Host ("    Complexity       : {0}" -f $ddpp.ComplexityEnabled)
        Write-Host ("    Reversible Enc.  : {0}" -f $ddpp.ReversibleEncryptionEnabled)
        Write-Host ''

        $ddppFindings = Test-PasswordPolicy -Policy $ddpp -PolicyName 'Default Domain Policy'
        $allFindings.AddRange($ddppFindings)
    }
    catch {
        Write-Warning "Could not retrieve Default Domain Password Policy: $_"
    }

    # Fine-Grained Password Policies
    Write-Verbose 'Retrieving Fine-Grained Password Policies (PSOs)…'
    try {
        $psos = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -ErrorAction SilentlyContinue

        if ($psos) {
            Write-Host "  Fine-Grained Password Policies found: $($psos.Count)" -ForegroundColor White
            foreach ($pso in $psos) {
                $subjects = Get-PSOSubjects -PSO $pso
                Write-Host ("  PSO: {0} (precedence {1}) — applies to: {2}" -f `
                    $pso.Name, $pso.Precedence, $subjects) -ForegroundColor DarkGray

                $psoFindings = Test-PasswordPolicy -Policy $pso -PolicyName "PSO: $($pso.Name)"
                $allFindings.AddRange($psoFindings)

                # Flag PSOs with higher precedence overriding stricter default
                $psoMinLen = $pso.MinPasswordLength
                $ddppMinLen = (Get-ADDefaultDomainPasswordPolicy).MinPasswordLength
                if ($psoMinLen -lt $ddppMinLen) {
                    $allFindings.Add((New-Finding -PolicyName "PSO: $($pso.Name)" `
                        -Setting 'PSO Precedence Override' `
                        -CurrentValue "MinLen=$psoMinLen" `
                        -RecommendedValue "MinLen>=$ddppMinLen" `
                        -Severity 'High' `
                        -Detail "This PSO sets a LOWER minimum length ($psoMinLen) than the Default Domain Policy ($ddppMinLen)" `
                        -Reference 'AD Fine-Grained Password Policy review'))
                }
            }
        }
        else {
            Write-Host '  No Fine-Grained Password Policies configured.' -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "Fine-Grained Password Policy query failed: $_"
    }

    return $allFindings
}

# ── Summary output ────────────────────────────────────────────────────────────

function Write-AuditSummary {
    param([System.Collections.Generic.List[PSCustomObject]]$Findings)

    $severityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $colorMap      = @{ Critical = 'Red'; High = 'DarkYellow'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'Gray' }

    Write-Host ('─' * 70) -ForegroundColor DarkGray
    Write-Host '  FINDINGS SUMMARY' -ForegroundColor White
    Write-Host ('─' * 70) -ForegroundColor DarkGray

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
    foreach ($f in $Findings | Sort-Object { $severityOrder[$_.Severity] }) {
        Write-Host ("  [{0}] {1} — Current: {2} | Recommended: {3}" -f `
            $f.Severity, $f.Setting, $f.CurrentValue, $f.RecommendedValue) `
            -ForegroundColor $colorMap[$f.Severity]
    }
    Write-Host ''
}

# ── Entry point ───────────────────────────────────────────────────────────────

Write-AuditBanner

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$findings = Invoke-PasswordPolicyAudit

if ($findings.Count -eq 0) {
    Write-Host '  ✅ Password policies meet CIS/NIST baseline.' -ForegroundColor Green
}
else {
    Write-AuditSummary -Findings $findings

    $csvPath = Join-Path $OutputPath "ADPasswordPolicyAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "  📄 Report saved: $csvPath" -ForegroundColor Green
}

Write-Host ''

if ($PassThru) { return $findings }
