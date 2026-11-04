# ---------------------------------------------------------------------------
# Install Atomic Red Team on a Windows lab host.
#
#   .\install-atomic.ps1
#   .\install-atomic.ps1 -Update       # refresh the atomics folder
#
# Atomic Red Team is a test-execution library, not malware. It is still
# "attack-like", so run it only on the isolated 192.168.56.0/24 network.
# ---------------------------------------------------------------------------
[CmdletBinding()]
param(
    [string]$InstallRoot = "C:\AtomicRedTeam",
    [switch]$Update
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

# --------------------------------------------------------------- execution policy
Write-Step "Execution policy"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# ------------------------------------------------------------------ nuget / psgallery
Write-Step "PowerShell gallery"
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
}
if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
    Register-PSRepository -Default
}
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

Write-Step "invoke-atomicredteam module"
$mod = Get-Module -ListAvailable -Name invoke-atomicredteam
if (-not $mod) {
    Install-Module -Name invoke-atomicredteam -Scope AllUsers -Force -AllowClobber
} elseif ($Update) {
    Update-Module -Name invoke-atomicredteam -Force
}
Import-Module invoke-atomicredteam -Force

# ---------------------------------------------------------------------- atomics
Write-Step "atomics folder"
New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
$atomicsPath = Join-Path $InstallRoot "atomics"
if ($Update -or -not (Test-Path (Join-Path $atomicsPath "atomics"))) {
    if (Test-Path $atomicsPath) {
        Remove-Item -Recurse -Force $atomicsPath
    }
    # The module's own installer fetches the correct folder layout.
    Install-AtomicRedTeam -getAtomics -Force -ErrorAction Stop
    # Install-AtomicRedTeam defaults to $env:TEMP\AtomicRedTeam; normalise it.
    $found = Get-ChildItem -Path $env:TEMP, $InstallRoot -Directory -Filter "AtomicRedTeam" `
        -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found -and $found.FullName -ne $InstallRoot) {
        Copy-Item -Path $found.FullName -Destination $InstallRoot -Recurse -Force
    }
}

$env:Path = "$InstallRoot;" + $env:Path

# --------------------------------------------------------------------- validation
Write-Step "validation"
$techs = Get-AtomicTechnique -Technique T1059.001
if (-not $techs) {
    throw "Atomic Red Team did not load. Check %TEMP%\AtomicRedTeam and the module import."
}
$count = (Get-ChildItem -Path (Join-Path $InstallRoot "atomics") -Filter "T*.yaml" -Recurse `
    -ErrorAction SilentlyContinue).Count
Write-Host "technique files found: $count"

Write-Host @"

Next steps
  1. .\run-atomics.ps1 -DryRun          # list the tests that would run
  2. .\run-atomics.ps1                  # execute + write ground_truth.csv
  3. .\run-benign.ps1 -Count 24         # generate the benign twin traffic

Defender will block some tests. That is expected and must be reported: a
blocked atomic produces no telemetry, so it is excluded from ground truth
rather than counted as a detection failure.
"@ -ForegroundColor Yellow
