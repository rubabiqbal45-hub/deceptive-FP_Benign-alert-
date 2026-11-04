# ---------------------------------------------------------------------------
# Windows lab host: Sysmon + Wazuh agent + tooling.
#
# Run by Vagrant, but safe to run manually:
#   .\windows-common.ps1 -ManagerIp 192.168.56.10 -AgentName soc-victim
# ---------------------------------------------------------------------------
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ManagerIp,
    [Parameter(Mandatory = $true)][string]$AgentName,
    [string]$SharedFolder = "C:\vagrant",
    [switch]$WithVNC,
    [switch]$DisableDefender
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$LabRoot = "C:\lab"
$LogDir  = Join-Path $LabRoot "logs"
New-Item -ItemType Directory -Force -Path $LabRoot, $LogDir | Out-Null
Start-Transcript -Path (Join-Path $LogDir "provision.log") -Append | Out-Null

function Write-Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

function Get-File($url, $dest) {
    if (Test-Path $dest) { return }
    Write-Host "downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
}

# --------------------------------------------------------------------- Sysmon
Write-Step "Sysmon"
$sysmonDir = Join-Path $LabRoot "sysmon"
New-Item -ItemType Directory -Force -Path $sysmonDir | Out-Null
Get-File "https://download.sysinternals.com/files/Sysmon.zip" "$sysmonDir\Sysmon.zip"
if (-not (Test-Path "$sysmonDir\Sysmon64.exe")) {
    Expand-Archive -Path "$sysmonDir\Sysmon.zip" -DestinationPath $sysmonDir -Force
}

$configPath = Join-Path $SharedFolder "lab\sysmon\sysmon-lab.xml"
if (-not (Test-Path $configPath)) {
    throw "Sysmon config not found at $configPath. Is the shared folder mounted?"
}

$installed = (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) -ne $null
if ($installed) {
    & "$sysmonDir\Sysmon64.exe" -accepteula -c $configPath | Out-Null
} else {
    & "$sysmonDir\Sysmon64.exe" -accepteula -i $configPath | Out-Null
}
Get-Service Sysmon64 | Format-Table -AutoSize

# ---------------------------------------------------------------- Wazuh agent
Write-Step "Wazuh agent"
$wazuhVersion = "4.9.0"
$msi = "$LabRoot\wazuh-agent-$wazuhVersion.msi"
Get-File "https://packages.wazuh.com/4.x/windows/wazuh-agent-$wazuhVersion-1.msi" $msi

$agentInstalled = Test-Path "C:\Program Files (x86)\ossec-agent\ossec.conf"
if (-not $agentInstalled) {
    $args = "/i `"$msi`" /q WAZUH_MANAGER=`"$ManagerIp`" WAZUH_AGENT_NAME=`"$AgentName`""
    Start-Process msiexec.exe -ArgumentList $args -Wait
}

$ossecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$conf = Get-Content $ossecConf -Raw

# Raw Sysmon + Security telemetry. Without these two blocks the manager sees
# nothing, and the bridge produces an empty dataset.
$blocks = @"
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@

if ($conf -notmatch "Microsoft-Windows-Sysmon/Operational") {
    $conf = $conf -replace "</ossec_config>", "$blocks`n</ossec_config>"
    # ASCII, not UTF8: Windows PowerShell 5.1 writes a BOM with -Encoding UTF8,
    # and a BOM at the top of ossec.conf can make the agent reject the file.
    Set-Content -Path $ossecConf -Value $conf -Encoding ASCII
}

if (Get-Service WazuhSvc -ErrorAction SilentlyContinue) {
    Restart-Service WazuhSvc -Force
    Start-Sleep -Seconds 5
    Get-Service WazuhSvc | Format-Table -AutoSize
}

# -------------------------------------------------------------- audit policy
Write-Step "Audit policy"
auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
# 4688 needs command-line auditing explicitly enabled
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

# ---------------------------------------------------------- attacker tooling
Write-Step "Tooling (PsTools, procdump)"
$tools = "C:\Tools"
New-Item -ItemType Directory -Force -Path $tools | Out-Null

Get-File "https://download.sysinternals.com/files/PSTools.zip" "$tools\PSTools.zip"
if (-not (Test-Path "$tools\PsExec.exe")) {
    Expand-Archive -Path "$tools\PSTools.zip" -DestinationPath $tools -Force
}
Get-File "https://download.sysinternals.com/files/Procdump.zip" "$tools\Procdump.zip"
if (-not (Test-Path "$tools\procdump.exe")) {
    Expand-Archive -Path "$tools\Procdump.zip" -DestinationPath $tools -Force
}
$env:Path = "$tools;" + $env:Path
[Environment]::SetEnvironmentVariable(
    "Path", "$tools;" + [Environment]::GetEnvironmentVariable("Path", "Machine"),
    "Machine")

# ------------------------------------------------------------------ optional
if ($WithVNC) {
    Write-Step "TightVNC"
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        Invoke-Expression ((New-Object Net.WebClient).DownloadString(
            "https://community.chocolatey.org/install.ps1"))
    }
    choco install tightvnc -y --no-progress
    Get-Service tvnserver -ErrorAction SilentlyContinue |
        Set-Service -StartupType Automatic
    Start-Service tvnserver -ErrorAction SilentlyContinue
}

Write-Step "Defender"
if ($DisableDefender) {
    Write-Warning "Disabling Defender. Isolated lab only."
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
} else {
    # Keep Defender on, but stop it quarantining the tools the tests use.
    # Atomic Red Team itself will still be partially blocked; see README.
    Add-MpPreference -ExclusionPath $LabRoot, "C:\Tools",
        "C:\AtomicRedTeam" -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------- summary
Write-Step "Ready"
"MANAGER=$ManagerIp`nAGENT=$AgentName" | Set-Content "$LabRoot\lab.env"
Write-Host @"
Capture checklist:
  1. Sysmon64 service is Running
  2. WazuhSvc is Running and shows 'Connected to the server'
  3. Audit logon + command-line auditing enabled
  4. Next: C:\vagrant\lab\attack\install-atomic.ps1
"@

Stop-Transcript | Out-Null
