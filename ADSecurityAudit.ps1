#================================================================
# AD Security Audit Script
# Author: Asong Bertrand
# Title: CyberArk PAM Engineer | IAM Specialist
# Domain: schoolofwise.local
# Description: Audits Active Directory for security gaps
#              including privileged groups, stale accounts,
#              password policy violations and more.
# Output: HTML Report saved to C:\ADSecurityAudit\Report.html
#================================================================

# Import Active Directory Module
Import-Module ActiveDirectory

# Set output file path
$ReportPath = "C:\ADSecurityAudit\ADSecurityAudit_Report.html"
$Date = Get-Date -Format "dd-MM-yyyy HH:mm"
$Domain = (Get-ADDomain).DNSRoot

Write-Host "Starting AD Security Audit on $Domain..." -ForegroundColor Green
Write-Host "Date: $Date" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green

#================================================================
# SECTION 1: PRIVILEGED GROUP MEMBERSHIP AUDIT
#================================================================

Write-Host "`nAuditing Privileged Groups..." -ForegroundColor Yellow

$PrivilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Group Policy Creator Owners"
)

$PrivGroupResults = @()

foreach ($Group in $PrivilegedGroups) {
    try {
        $Members = Get-ADGroupMember -Identity $Group -Recursive |
                   Get-ADUser -Properties LastLogonDate, PasswordLastSet, Enabled
        foreach ($Member in $Members) {
            $PrivGroupResults += [PSCustomObject]@{
                Group           = $Group
                Username        = $Member.SamAccountName
                FullName        = $Member.Name
                Enabled         = $Member.Enabled
                LastLogon       = $Member.LastLogonDate
                PasswordLastSet = $Member.PasswordLastSet
            }
        }
    } catch {
        Write-Host "Could not query group: $Group" -ForegroundColor Red
    }
}

Write-Host "Found $($PrivGroupResults.Count) privileged account(s)" -ForegroundColor Cyan

#================================================================
# SECTION 2: STALE ACCOUNTS AUDIT (Inactive 90+ days)
#================================================================

Write-Host "`nAuditing Stale Accounts..." -ForegroundColor Yellow

$90Days = (Get-Date).AddDays(-90)

$StaleAccounts = Get-ADUser -Filter {
    LastLogonDate -lt $90Days -and Enabled -eq $true
} -Properties LastLogonDate, PasswordLastSet, Department, Title |
Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet, Department, Title

Write-Host "Found $($StaleAccounts.Count) stale account(s) inactive for 90+ days" -ForegroundColor Cyan

#================================================================
# SECTION 3: ACCOUNTS WITH PASSWORD NEVER EXPIRES
#================================================================

Write-Host "`nAuditing Password Never Expires..." -ForegroundColor Yellow

$PasswordNeverExpires = Get-ADUser -Filter {
    PasswordNeverExpires -eq $true -and Enabled -eq $true
} -Properties PasswordNeverExpires, PasswordLastSet, LastLogonDate |
Select-Object Name, SamAccountName, PasswordLastSet, LastLogonDate

Write-Host "Found $($PasswordNeverExpires.Count) account(s) with Password Never Expires" -ForegroundColor Cyan

#================================================================
# SECTION 4: ACCOUNTS WITH PASSWORD NOT REQUIRED
#================================================================

Write-Host "`nAuditing Password Not Required..." -ForegroundColor Yellow

$PasswordNotRequired = Get-ADUser -Filter {
    PasswordNotRequired -eq $true -and Enabled -eq $true
} -Properties PasswordNotRequired, LastLogonDate |
Select-Object Name, SamAccountName, LastLogonDate

Write-Host "Found $($PasswordNotRequired.Count) account(s) with Password Not Required" -ForegroundColor Cyan

#================================================================
# SECTION 5: DISABLED ACCOUNTS STILL IN PRIVILEGED GROUPS
#================================================================

Write-Host "`nAuditing Disabled Accounts in Privileged Groups..." -ForegroundColor Yellow

$DisabledPrivAccounts = @()

foreach ($Group in $PrivilegedGroups) {
    try {
        $Members = Get-ADGroupMember -Identity $Group -Recursive |
                   Get-ADUser -Properties Enabled, LastLogonDate |
                   Where-Object { $_.Enabled -eq $false }
        foreach ($Member in $Members) {
            $DisabledPrivAccounts += [PSCustomObject]@{
                Group     = $Group
                Username  = $Member.SamAccountName
                FullName  = $Member.Name
                Enabled   = $Member.Enabled
                LastLogon = $Member.LastLogonDate
            }
        }
    } catch {
        Write-Host "Could not query group: $Group" -ForegroundColor Red
    }
}

Write-Host "Found $($DisabledPrivAccounts.Count) disabled account(s) still in privileged groups" -ForegroundColor Cyan

#================================================================
# SECTION 6: STALE COMPUTER ACCOUNTS
#================================================================

Write-Host "`nAuditing Stale Computer Accounts..." -ForegroundColor Yellow

$StaleComputers = Get-ADComputer -Filter {
    LastLogonDate -lt $90Days -and Enabled -eq $true
} -Properties LastLogonDate, OperatingSystem |
Select-Object Name, Enabled, LastLogonDate, OperatingSystem

Write-Host "Found $($StaleComputers.Count) stale computer account(s)" -ForegroundColor Cyan

#================================================================
# SECTION 7: ADMIN ACCOUNTS WITHOUT TIERED NAMING CONVENTION
#================================================================

Write-Host "`nAuditing Admin Account Naming Convention..." -ForegroundColor Yellow

$DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive |
                Get-ADUser -Properties Enabled |
                Where-Object {
                    $_.SamAccountName -notlike "T0-*" -and
                    $_.SamAccountName -ne "Administrator"
                }

Write-Host "Found $($DomainAdmins.Count) Domain Admin(s) not following T0- naming convention" -ForegroundColor Cyan

#================================================================
# SECTION 8: GENERATE HTML REPORT
#================================================================

Write-Host "`nGenerating HTML Report..." -ForegroundColor Yellow

$PrivRows = ""
foreach ($Item in $PrivGroupResults) {
    $PrivRows += "<tr><td>$($Item.Group)</td><td>$($Item.Username)</td><td>$($Item.FullName)</td><td>$($Item.Enabled)</td><td>$($Item.LastLogon)</td><td>$($Item.PasswordLastSet)</td></tr>`n"
}

$StaleRows = ""
foreach ($Item in $StaleAccounts) {
    $StaleRows += "<tr><td>$($Item.Name)</td><td>$($Item.SamAccountName)</td><td class='risk-high'>$($Item.LastLogonDate)</td><td>$($Item.PasswordLastSet)</td><td>$($Item.Department)</td></tr>`n"
}

$PwdNeverRows = ""
foreach ($Item in $PasswordNeverExpires) {
    $PwdNeverRows += "<tr><td>$($Item.Name)</td><td>$($Item.SamAccountName)</td><td class='risk-high'>$($Item.PasswordLastSet)</td><td>$($Item.LastLogonDate)</td></tr>`n"
}

$PwdNotReqRows = ""
foreach ($Item in $PasswordNotRequired) {
    $PwdNotReqRows += "<tr><td>$($Item.Name)</td><td>$($Item.SamAccountName)</td><td class='risk-high'>$($Item.LastLogonDate)</td></tr>`n"
}

$DisabledRows = ""
foreach ($Item in $DisabledPrivAccounts) {
    $DisabledRows += "<tr><td>$($Item.Group)</td><td>$($Item.Username)</td><td>$($Item.FullName)</td><td class='risk-high'>$($Item.LastLogon)</td></tr>`n"
}

$ComputerRows = ""
foreach ($Item in $StaleComputers) {
    $ComputerRows += "<tr><td>$($Item.Name)</td><td class='risk-high'>$($Item.LastLogonDate)</td><td>$($Item.OperatingSystem)</td></tr>`n"
}

$AdminRows = ""
foreach ($Item in $DomainAdmins) {
    $AdminRows += "<tr><td>$($Item.Name)</td><td class='risk-high'>$($Item.SamAccountName)</td><td>$($Item.Enabled)</td></tr>`n"
}

$HTMLReport = @"
<!DOCTYPE html>
<html>
<head>
<title>AD Security Audit Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; }
h1 { background-color: #1B3A6B; color: white; padding: 15px; border-radius: 5px; }
h2 { background-color: #2E5FA3; color: white; padding: 10px; border-radius: 5px; }
table { width: 100%; border-collapse: collapse; margin-bottom: 30px; background-color: white; }
th { background-color: #1B3A6B; color: white; padding: 10px; text-align: left; }
td { padding: 8px; border-bottom: 1px solid #ddd; }
tr:hover { background-color: #f0f0f0; }
.risk-high { color: #A32D2D; font-weight: bold; }
.risk-low { color: #0F6E56; font-weight: bold; }
.summary { background-color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
.summary-item { display: inline-block; margin: 10px; padding: 15px; background-color: #1B3A6B; color: white; border-radius: 5px; text-align: center; min-width: 150px; }
.summary-num { font-size: 32px; font-weight: bold; }
.summary-lbl { font-size: 12px; }
</style>
</head>
<body>
<h1>Active Directory Security Audit Report</h1>
<p><strong>Domain:</strong> $Domain</p>
<p><strong>Generated:</strong> $Date</p>
<p><strong>Author:</strong> Asong Bertrand - CyberArk PAM Engineer | IAM Specialist</p>

<div class="summary">
<h2>Executive Summary</h2>
<div class="summary-item"><div class="summary-num">$($PrivGroupResults.Count)</div><div class="summary-lbl">Privileged Accounts</div></div>
<div class="summary-item"><div class="summary-num">$($StaleAccounts.Count)</div><div class="summary-lbl">Stale Accounts</div></div>
<div class="summary-item"><div class="summary-num">$($PasswordNeverExpires.Count)</div><div class="summary-num">$($PasswordNeverExpires.Count)</div><div class="summary-lbl">Password Never Expires</div></div>
<div class="summary-item"><div class="summary-num">$($PasswordNotRequired.Count)</div><div class="summary-lbl">Password Not Required</div></div>
<div class="summary-item"><div class="summary-num">$($DisabledPrivAccounts.Count)</div><div class="summary-lbl">Disabled in Priv Groups</div></div>
<div class="summary-item"><div class="summary-num">$($StaleComputers.Count)</div><div class="summary-lbl">Stale Computers</div></div>
</div>

<h2>Section 1 - Privileged Group Membership</h2>
<table>
<tr><th>Group</th><th>Username</th><th>Full Name</th><th>Enabled</th><th>Last Logon</th><th>Password Last Set</th></tr>
$PrivRows
</table>

<h2>Section 2 - Stale Accounts (Inactive 90+ Days)</h2>
<table>
<tr><th>Name</th><th>Username</th><th>Last Logon</th><th>Password Last Set</th><th>Department</th></tr>
$StaleRows
</table>

<h2>Section 3 - Password Never Expires</h2>
<table>
<tr><th>Name</th><th>Username</th><th>Password Last Set</th><th>Last Logon</th></tr>
$PwdNeverRows
</table>

<h2>Section 4 - Password Not Required</h2>
<table>
<tr><th>Name</th><th>Username</th><th>Last Logon</th></tr>
$PwdNotReqRows
</table>

<h2>Section 5 - Disabled Accounts in Privileged Groups</h2>
<table>
<tr><th>Group</th><th>Username</th><th>Full Name</th><th>Last Logon</th></tr>
$DisabledRows
</table>

<h2>Section 6 - Stale Computer Accounts</h2>
<table>
<tr><th>Computer Name</th><th>Last Logon</th><th>Operating System</th></tr>
$ComputerRows
</table>

<h2>Section 7 - Domain Admins Not Following T0- Naming Convention</h2>
<table>
<tr><th>Name</th><th>Username</th><th>Enabled</th></tr>
$AdminRows
</table>

<p style="text-align:center;color:#888;margin-top:30px;">Report generated by ADSecurityAudit.ps1 - Asong Bertrand | schoolofwise.local</p>
</body>
</html>
"@

$HTMLReport | Out-File -FilePath $ReportPath -Encoding UTF8

Write-Host "`n================================================" -ForegroundColor Green
Write-Host "Audit Complete!" -ForegroundColor Green
Write-Host "Report saved to: $ReportPath" -ForegroundColor Green
Write-Host "Open the report in your browser to view results." -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green

Start-Process $ReportPath
