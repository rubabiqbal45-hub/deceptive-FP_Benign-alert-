# ---------------------------------------------------------------------------
# Promote dc-01 to a domain controller, then (second pass) populate it.
#
# The Windows box is optional. It exists to make lateral movement and identity
# context realistic: PsExec to a DC, role/asset mismatches, a file share.
#
# Because promotion reboots the VM, this script is idempotent and phase-aware:
#
#   vagrant up dc-01          # phase 1 -> promotes, schedules a reboot
#   vagrant reload dc-01      # wait for the reboot to finish
#   vagrant provision dc-01   # phase 2 -> creates OUs, users, groups, share
#
# Accounts mirror lab/inventory/users.csv. Keep the two in sync; the bridge
# resolves users by account name, so a missing account silently degrades to
# role=unclassified.
# ---------------------------------------------------------------------------
[CmdletBinding()]
param(
    [string]$NetbiosName = "CORP",
    [string]$DomainName  = "corp.local",
    [string]$SafeModePassword = "Lab-SafeMode-Passw0rd!",
    [string]$UserPassword = "Lab-Passw0rd!",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
Start-Transcript -Path "C:\lab\logs\dc.log" -Append -Force | Out-Null

function Write-Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

$role = (Get-CimInstance Win32_ComputerSystem).DomainRole
$isDc = $role -ge 4
Write-Step "role=$role isDc=$isDc"

# ---------------------------------------------------------------- phase 1: promote
if (-not $isDc) {
    Write-Step "installing AD DS + DNS"
    Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools |
        Out-Null

    Import-Module ADDSDeployment

    if (-not (Get-Command Install-ADDSForest -ErrorAction SilentlyContinue)) {
        throw "ADDSDeployment module missing after feature install"
    }

    Write-Step "creating forest $DomainName"
    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetbiosName $NetbiosName `
        -InstallDns `
        -SafeModeAdministratorPassword (ConvertTo-SecureString $SafeModePassword -AsPlainText -Force) `
        -NoRebootOnCompletion `
        -Force:$true

    Write-Step "rebooting in 15 seconds to finish promotion"
    shutdown.exe /r /t 15 /c "Promoting to domain controller (lab)" | Out-Null
    Stop-Transcript | Out-Null
    exit 0
}

# ---------------------------------------------------------------- phase 2: populate
Import-Module ActiveDirectory

$baseDn = "DC=" + ($DomainName -replace "\.", ",DC=")
Write-Step "populating $baseDn"

function Ensure-OU {
    param([string]$Name, [string]$Path)
    $dn = "OU=$Name,$Path"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $false | Out-Null
        Write-Host "  created OU $Name"
    }
    return $dn
}

$usersOu = Ensure-OU -Name "LabUsers" -Path $baseDn
$groupsOu = Ensure-OU -Name "LabGroups" -Path $baseDn

# account, role, display name, ou
$accounts = @(
    @{ account = "alice";  role = "it_admin";        name = "Alice Ng"    },
    @{ account = "bob";    role = "it_admin";        name = "Bob Mensah"  },
    @{ account = "svc-backup";  role = "service_account"; name = "Backup Service"  },
    @{ account = "svc-monitor"; role = "service_account"; name = "Monitor Service" },
    @{ account = "carol";  role = "finance";         name = "Carol Adey"  },
    @{ account = "dave";   role = "developer";       name = "Dave Osei"   },
    @{ account = "erin";   role = "hr";              name = "Erin Boateng"},
    @{ account = "frank";  role = "sales";           name = "Frank Yaw"   }
)

foreach ($a in $accounts) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($a.account)'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name $a.name -SamAccountName $a.account `
            -UserPrincipalName "$($a.account)@$DomainName" `
            -Path $usersOu -Enabled $true `
            -AccountPassword (ConvertTo-SecureString $UserPassword -AsPlainText -Force) `
            -PasswordNeverExpires $true -ChangePasswordAtLogon $false | Out-Null
        Write-Host "  created user $($a.account) ($($a.role))"
    }
}

foreach ($role in ($accounts.role | Sort-Object -Unique)) {
    if (-not (Get-ADGroup -Filter "Name -eq 'Lab-$role'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name "Lab-$role" -GroupScope Global -Path $groupsOu | Out-Null
        Write-Host "  created group Lab-$role"
    }
    foreach ($a in ($accounts | Where-Object { $_.role -eq $role })) {
        Add-ADGroupMember -Identity "Lab-$role" -Members $a.account -ErrorAction SilentlyContinue
    }
}

# Service accounts are also local admins on the victim (set on the victim, not
# here); the domain side only needs the group membership for Kerberos.

# ------------------------------------------------------------------- file share
Write-Step "file share"
$shareRoot = "C:\Shares\finance"
New-Item -ItemType Directory -Force -Path $shareRoot | Out-Null
"quarterly forecast" | Set-Content (Join-Path $shareRoot "forecast.txt") -Encoding UTF8

if (-not (Get-SmbShare -Name "finance" -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name "finance" -Path $shareRoot -FullAccess "CORP\Domain Admins" `
        -ChangeAccess "CORP\Lab-finance" | Out-Null
}

# ----------------------------------------------------------------------- DNS
Write-Step "dns forwarder"
try {
    Add-DnsServerForwarder -IPAddress 8.8.8.8 -ErrorAction SilentlyContinue | Out-Null
} catch { }

Write-Step "done"
Write-Host @"
Domain : $DomainName
Users  : alice bob svc-backup svc-monitor carol dave erin frank
Passwd : $UserPassword
Share  : \\dc-01\finance

From the victim, verify:
  nltest /dsgetdc:corp.local
  net use Z: \\dc-01\finance
"@ -ForegroundColor Green

Stop-Transcript | Out-Null
