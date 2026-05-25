#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Audits privileged access in Active Directory for over-permissioning and shadow admins.

.DESCRIPTION
    Enumerates membership of all high-value groups, identifies accounts with AdminCount=1
    that are not in expected privileged groups (shadow admins), detects accounts with
    DCSync rights, and flags privileged accounts not enrolled in Protected Users.

    Findings covered:
      - Membership of Domain Admins, Enterprise Admins, Schema Admins, Administrators,
        Account Operators, Backup Operators, Print Operators, Server Operators,
        Group Policy Creator Owners, DnsAdmins
      - Nested group membership resolution (recursive)
      - AdminCount=1 accounts outside known privileged groups (potential shadow admins)
      - Accounts with DCSync replication rights on the domain NC
      - Privileged user accounts not in the Protected Users group
      - Enabled privileged accounts with non-expiring passwords

.PARAMETER OutputPath
    Directory to write CSV output. Default: .\reports\

.PARAMETER SearchBase
    LDAP Distinguished Name to scope user queries. Default: domain root.

.PARAMETER IncludeDnsAdmins
    Include DnsAdmins group in the audit (can be escalated to DA via DNS abuse).

.PARAMETER PassThru
    Return result objects to the pipeline.

.EXAMPLE
    .\Invoke-ADPrivilegedAudit.ps1

.EXAMPLE
    .\Invoke-ADPrivilegedAudit.ps1 -IncludeDnsAdmins -OutputPath C:\AuditReports

.NOTES
    Requires : ActiveDirectory PowerShell module
    Privilege: Domain read access for group/user queries.
               Domain Admin or delegated rights to read ACLs for DCSync check.
    Legal     : Run only on domains you own or have written authorisation to audit.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$OutputPath = '.\reports',

    [Parameter()]
    [string]$SearchBase = '',

    [Parameter()]
    [switch]$IncludeDnsAdmins,

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Constants ─────────────────────────────────────────────────────────────────

$PRIVILEGED_GROUPS = @(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Backup Operators',
    'Print Operators',
    'Server Operators',
    'Group Policy Creator Owners'
)

# DS-Replication-Get-Changes-All right GUID (DCSync)
$DCSYNC_RIGHT_GUID = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-AuditBanner {
    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host '  AD PRIVILEGED ACCESS AUDIT' -ForegroundColor Cyan
    Write-Host '  ⚠  Run only on domains you own or have written authorisation to audit.' -ForegroundColor Yellow
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host ''
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

function Get-NestedGroupMembers {
    <#
    .SYNOPSIS Recursively resolve group members, returning only user objects.
    #>
    param(
        [string]$GroupName,
        [System.Collections.Generic.HashSet[string]]$Visited
    )

    if ($Visited.Contains($GroupName)) { return @() }
    [void]$Visited.Add($GroupName)

    $members = @()
    try {
        $group = Get-ADGroup -Identity $GroupName -ErrorAction SilentlyContinue
        if (-not $group) { return @() }

        $directMembers = Get-ADGroupMember -Identity $GroupName -Recursive:$false -ErrorAction SilentlyContinue
        foreach ($m in $directMembers) {
            if ($m.objectClass -eq 'user') {
                $members += Get-ADUser -Identity $m.DistinguishedName `
                    -Properties 'PasswordNeverExpires', 'Enabled', 'LastLogonDate', 'AdminCount' `
                    -ErrorAction SilentlyContinue
            }
            elseif ($m.objectClass -eq 'group') {
                # Recurse — note: Get-ADGroupMember -Recursive flattens but loses path info
                $members += Get-NestedGroupMembers -GroupName $m.SamAccountName -Visited $Visited
            }
        }
    }
    catch {
        Write-Warning "Could not enumerate group '$GroupName': $_"
    }
    return $members
}

function Get-DomainNC {
    $rootDSE = [ADSI]'LDAP://RootDSE'
    return $rootDSE.defaultNamingContext
}

# ── DCSync rights check ───────────────────────────────────────────────────────

function Get-DCSyncAccounts {
    [CmdletBinding()]
    param()

    $dcsyncAccounts = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $domainNC     = Get-DomainNC
        $domainObject = [ADSI]"LDAP://$domainNC"
        $acl          = $domainObject.psbase.ObjectSecurity

        foreach ($ace in $acl.Access) {
            # Look for DS-Replication-Get-Changes-All (full DCSync)
            if ($ace.ObjectType -eq $DCSYNC_RIGHT_GUID -and
                $ace.ActiveDirectoryRights -match 'ExtendedRight' -and
                $ace.AccessControlType -eq 'Allow') {

                $identity = $ace.IdentityReference.Value
                # Skip well-known system principals
                if ($identity -match 'S-1-5-18|S-1-5-20|S-1-5-32-544|SYSTEM|Domain Controllers|Enterprise Domain Controllers') {
                    continue
                }
                $dcsyncAccounts.Add([PSCustomObject]@{
                    Identity = $identity
                    Right    = 'DS-Replication-Get-Changes-All (DCSync)'
                })
            }
        }
    }
    catch {
        Write-Warning "DCSync ACL check failed (may require elevated read on domain NC): $_"
    }

    return $dcsyncAccounts
}

# ── Main audit ────────────────────────────────────────────────────────────────

function Invoke-PrivilegedAudit {
    [CmdletBinding()]
    param(
        [string]$SearchBase,
        [bool]$IncludeDnsAdmins
    )

    $findings        = [System.Collections.Generic.List[PSCustomObject]]::new()
    $groupsToCheck   = $PRIVILEGED_GROUPS.Clone()
    $allPrivUsers    = [System.Collections.Generic.HashSet[string]]::new()

    if ($IncludeDnsAdmins) { $groupsToCheck += 'DnsAdmins' }

    # ── 1. Enumerate privileged group memberships ────────────────────────────
    Write-Verbose 'Enumerating privileged group memberships…'

    foreach ($groupName in $groupsToCheck) {
        $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $members = Get-NestedGroupMembers -GroupName $groupName -Visited $visited

        $sev = switch ($groupName) {
            { $_ -in 'Domain Admins', 'Enterprise Admins', 'Schema Admins' } { 'Critical' }
            { $_ -in 'Administrators', 'Account Operators', 'Backup Operators' }  { 'High' }
            default { 'Medium' }
        }

        foreach ($member in $members) {
            [void]$allPrivUsers.Add($member.DistinguishedName)

            $detail = "Member of '$groupName'"
            if (-not $member.Enabled)              { $detail += ' [DISABLED]' }
            if ($member.PasswordNeverExpires)       { $detail += ' [PWD_NEVER_EXPIRES]' }

            $findings.Add((New-Finding -Category 'PrivilegedGroupMember' `
                -SamAccountName $member.SamAccountName `
                -DistinguishedName $member.DistinguishedName `
                -Severity $sev -Detail $detail))
        }

        Write-Verbose "  $groupName : $($members.Count) member(s)"
    }

    # ── 2. Shadow admin detection (AdminCount=1 outside privileged groups) ───
    Write-Verbose 'Checking for shadow admins (AdminCount=1)…'

    $adminCountParams = @{
        Filter     = { AdminCount -eq 1 -and Enabled -eq $true }
        Properties = @('AdminCount', 'MemberOf', 'PasswordNeverExpires', 'LastLogonDate')
    }
    if ($SearchBase) { $adminCountParams['SearchBase'] = $SearchBase }

    try {
        $adminCountUsers = Get-ADUser @adminCountParams
        foreach ($user in $adminCountUsers) {
            if (-not $allPrivUsers.Contains($user.DistinguishedName)) {
                $findings.Add((New-Finding -Category 'ShadowAdmin' `
                    -SamAccountName $user.SamAccountName `
                    -DistinguishedName $user.DistinguishedName `
                    -Severity 'High' `
                    -Detail 'AdminCount=1 but not in any known privileged group — possible shadow admin or SDProp residue'))
            }
        }
    }
    catch {
        Write-Warning "AdminCount query failed: $_"
    }

    # ── 3. DCSync rights ─────────────────────────────────────────────────────
    Write-Verbose 'Checking for DCSync replication rights on domain NC…'

    $dcsyncAccounts = Get-DCSyncAccounts
    foreach ($entry in $dcsyncAccounts) {
        $findings.Add((New-Finding -Category 'DCSyncRight' `
            -SamAccountName $entry.Identity `
            -DistinguishedName $entry.Identity `
            -Severity 'Critical' `
            -Detail "Has '$($entry.Right)' — can extract all credential hashes from the domain"))
    }

    # ── 4. Privileged accounts not in Protected Users ────────────────────────
    Write-Verbose 'Checking Protected Users group membership for privileged accounts…'

    try {
        $protectedUsers = Get-ADGroupMember -Identity 'Protected Users' -Recursive -ErrorAction SilentlyContinue |
            Where-Object { $_.objectClass -eq 'user' } |
            Select-Object -ExpandProperty DistinguishedName

        $protectedSet = [System.Collections.Generic.HashSet[string]]::new(
            $protectedUsers, [StringComparer]::OrdinalIgnoreCase)

        foreach ($privDN in $allPrivUsers) {
            if (-not $protectedSet.Contains($privDN)) {
                try {
                    $u = Get-ADUser -Identity $privDN -Properties 'Enabled' -ErrorAction SilentlyContinue
                    if ($u -and $u.Enabled) {
                        $findings.Add((New-Finding -Category 'NotInProtectedUsers' `
                            -SamAccountName $u.SamAccountName `
                            -DistinguishedName $privDN `
                            -Severity 'Medium' `
                            -Detail 'Privileged account not in Protected Users group — vulnerable to credential theft (Pass-the-Hash, Kerberos delegation)'))
                    }
                }
                catch { <# skip inaccessible objects #> }
            }
        }
    }
    catch {
        Write-Warning "Protected Users check failed: $_"
    }

    return $findings
}

# ── Output ────────────────────────────────────────────────────────────────────

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
    Write-Host '  Critical / High findings:' -ForegroundColor White
    $Findings | Where-Object { $_.Severity -in 'Critical', 'High' } |
        Select-Object -First 15 |
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
}

$findings = Invoke-PrivilegedAudit -SearchBase $SearchBase -IncludeDnsAdmins:$IncludeDnsAdmins.IsPresent

if ($findings.Count -eq 0) {
    Write-Host '  ✅ No privileged access findings.' -ForegroundColor Green
}
else {
    Write-AuditSummary -Findings $findings

    $csvPath = Join-Path $OutputPath "ADPrivilegedAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "  📄 Report saved: $csvPath" -ForegroundColor Green
}

Write-Host ''

if ($PassThru) { return $findings }
