# ---------------------------------------------------------------------------
# Benign twin traffic.
#
# This script is the other half of the experiment. It performs *legitimate*
# administrative actions that are intentionally close to the atomic tests:
# same binaries, same parent process, similar command lines.
#
# Why? Because "deceptive false positive" has a precise meaning here: a benign
# alert whose behavioural signature (rule + process + parent) also appears in
# the malicious class, so suppressing it would suppress a real attack too.
# Benign traffic that looks nothing like an attack is merely noisy; it is not
# the phenomenon under study.
#
#   .\run-benign.ps1 -DryRun
#   .\run-benign.ps1 -Count 8 -GapSeconds 60
#
# Run it both during the atomic window (to create overlap) and on quiet days
# (to create the baseline).
# ---------------------------------------------------------------------------
[CmdletBinding()]
param(
    [string]$OutDir = "C:\lab\out",
    [string]$Staging = "C:\ProgramData\lab",
    [int]$Count = 8,
    [int]$GapSeconds = 30,
    [switch]$DryRun,
    [switch]$OnlyBackground
)

$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $OutDir, $Staging | Out-Null

$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$log   = Join-Path $OutDir "benign_manifest.csv"
$rows  = New-Object System.Collections.Generic.List[object]

function Write-Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Now-Iso { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }

function Add-Record {
    param([string]$Action, [string]$Detail)
    $rows.Add([pscustomobject]@{
        ts_utc = Now-Iso; action = $Action; detail = $Detail
        host = $env:COMPUTERNAME; successful = $true
    }) | Out-Null
}

# ---------------------------------------------------------------------------
# Each function is a plausible business action that happens to satisfy one of
# the deployed detection rules. The comment names the rule it exercises.
# ---------------------------------------------------------------------------

function Invoke-BenignLogon {
    # R-1133: external remote service login.
    Write-Host "  [benign] RDP client to the jump host"
    $p = Start-Process mstsc.exe -ArgumentList "/v:192.168.56.11" -PassThru
    Start-Sleep -Seconds 4
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Add-Record "rdp-login" "mstsc /v:192.168.56.11"
}

function Invoke-BenignEncodedPowerShell {
    # R-1059-001: encoded PowerShell. This is how the backup team ships an
    # inventory script through the management console — base64 for quoting,
    # not for evasion.
    $script = "Get-ChildItem -Path C:\Users -Directory | Select-Object -ExpandProperty Name"
    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    $args = "-NoProfile -WindowStyle Hidden -EncodedCommand $b64"
    Write-Host "  [benign] encoded inventory script"
    Start-Process powershell.exe -ArgumentList $args -Wait -WindowStyle Hidden
    Add-Record "encoded-powershell" $args
}

function Invoke-BenignScheduledTask {
    # R-1053-005: scheduled task creation. Nightly backup registration.
    Write-Host "  [benign] register nightly backup task"
    & schtasks.exe /Create /TN "Lab\NightlyBackup" /TR "cmd.exe /c echo backup" `
        /SC DAILY /ST 23:00 /F 2>&1 | Out-Null
    Add-Record "scheduled-task" "schtasks /Create /TN Lab\NightlyBackup"
}

function Invoke-BenignDownload {
    # R-1105: ingress tool transfer. Agent pulling a signed update package.
    # The URL is intentionally unresolvable: we want the command line, not a
    # real download, and we do not want the lab reaching the internet.
    $dest = Join-Path $Staging "update.zip"
    Write-Host "  [benign] fetch update package"
    & curl.exe -s -o $dest https://updates.corp.example/agent/update.zip 2>&1 | Out-Null
    Add-Record "download" "curl -o $dest https://updates.corp.example/agent/update.zip"
}

function Invoke-BenignRundll32 {
    # R-1218-011: rundll32 proxy execution. Printer UI via a vendor DLL.
    # Called from PowerShell by the helpdesk script, matching the atomic's
    # process lineage rather than explorer.exe.
    $dll = Join-Path $Staging "printui.dll"
    if (-not (Test-Path $dll)) {
        # A real vendor DLL, copied so the path is outside System32.
        Copy-Item "C:\Windows\System32\printui.dll" $dll -ErrorAction SilentlyContinue
    }
    Write-Host "  [benign] open printer configuration UI"
    Start-Process rundll32.exe -ArgumentList "$dll,PrintUIEntry /il" -Wait
    Add-Record "rundll32" "rundll32 $dll,PrintUIEntry /il"
}

function Invoke-BenignRemoteAccess {
    # R-1219: remote access tool. Support engineers keep VNC running.
    $vnc = @(
        "C:\Program Files\TightVNC\tvnserver.exe",
        "C:\Program Files (x86)\TightVNC\tvnserver.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $vnc) {
        Write-Warning "  [benign] TightVNC not installed, skipping R-1219 twin"
        return
    }
    Write-Host "  [benign] restart the support VNC service"
    Start-Process $vnc -ArgumentList "-run"
    Start-Sleep -Seconds 3
    Get-Process tvnserver -ErrorAction SilentlyContinue | Stop-Process -Force
    Add-Record "remote-access" $vnc
}

function Invoke-BenignPsExec {
    # R-1021-002: remote service execution. The patching team uses PsExec for
    # a weekly maintenance sweep. It fails against this host (no admin share
    # credentials in the lab), but the process creation is what we need.
    Write-Host "  [benign] maintenance sweep via PsExec"
    $psexec = "C:\Tools\PsExec.exe"
    if (-not (Test-Path $psexec)) { $psexec = "psexec.exe" }
    & $psexec -accepteula -nobanner -n 5 "\\$env:COMPUTERNAME" `
        cmd.exe /c "whoami" 2>&1 | Out-Null
    Add-Record "psexec" "PsExec \\$env:COMPUTERNAME cmd /c whoami"
}

function Invoke-BenignBeacon {
    # R-1071-001: application-layer beacon. Intranet HTA dashboard, opened from
    # the management shell. mshta makes the outbound 443 connection the rule
    # looks for, without any C2.
    Write-Host "  [benign] open intranet HTA dashboard"
    $p = Start-Process mshta.exe -ArgumentList "https://intranet.corp.example/portal.hta" -PassThru
    Start-Sleep -Seconds 4
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Add-Record "beacon" "mshta https://intranet.corp.example/portal.hta"
}

function Invoke-BackgroundNoise {
    # Does not trip a rule on purpose. It gives the context features
    # (event_count, burst_size, peer_rarity) something to measure.
    Write-Host "  [benign] background activity"
    foreach ($exe in @("notepad.exe", "calc.exe")) {
        $p = Start-Process $exe -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 1500
        if ($p) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    Get-ChildItem C:\Windows\System32 -Filter *.dll -ErrorAction SilentlyContinue |
        Select-Object -First 25 | ForEach-Object { $null = $_.Length }
    Add-Record "background" "notepad / calc / directory enumeration"
}

$actions = @(
    "Invoke-BenignLogon",
    "Invoke-BenignEncodedPowerShell",
    "Invoke-BenignScheduledTask",
    "Invoke-BenignDownload",
    "Invoke-BenignRundll32",
    "Invoke-BenignRemoteAccess",
    "Invoke-BenignPsExec",
    "Invoke-BenignBeacon"
)

if ($DryRun) {
    Write-Step "planned benign actions"
    $actions | ForEach-Object { Write-Host "  $_" }
    Write-Host "`nrepetitions: $Count, gap: ${GapSeconds}s"
    return
}

Write-Step "benign capture ($Count rounds)"
for ($i = 0; $i -lt $Count; $i++) {
    $action = $actions[$i % $actions.Count]
    Write-Host "round $($i + 1)/$Count : $action" -ForegroundColor Cyan
    if (-not $OnlyBackground) {
        try { & $action } catch { Write-Warning "  $action failed: $($_.Exception.Message)" }
    }
    Invoke-BackgroundNoise
    if ($i -lt ($Count - 1)) { Start-Sleep -Seconds $GapSeconds }
}

$rows | Export-Csv -Path $log -NoTypeInformation -Encoding UTF8
Write-Step "done"
Write-Host "benign manifest -> $log"
Write-Warning @"
R-1003-001 (LSASS access) has no benign twin here on purpose. Every lab tool
that touches lsass is either an attack test or a credential dumper, so
inventing a "benign" one would fabricate the very label the study is about.
Expect zero deceptive false positives for that rule and say so in the results.
"@
