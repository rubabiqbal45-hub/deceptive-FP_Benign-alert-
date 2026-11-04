# ---------------------------------------------------------------------------
# One-command capture-to-results on the Windows host.
#
#   .\export-wazuh.ps1                          # last 6 hours
#   .\export-wazuh.ps1 -Since 2026-02-10T00:00:00
#   .\export-wazuh.ps1 -Source alerts           # rule-matched only
#   .\export-wazuh.ps1 -SkipRun                 # just build the dataset
#
# Requires: Vagrant in PATH, the VMs running, and the repo checked out.
# This is a convenience wrapper; every step is also runnable by hand and the
# README documents the manual sequence.
# ---------------------------------------------------------------------------
[CmdletBinding()]
param(
    [string]$Since = (Get-Date).ToUniversalTime().AddHours(-6).ToString("yyyy-MM-ddTHH:mm:ss"),
    [ValidateSet("archives", "alerts")]
    [string]$Source = "archives",
    [string]$Match = "time+rule",
    [int]$SlackSeconds = 90,
    [string]$OutDir = "lab\out",
    [string]$ResultsDir = "results_lab",
    [switch]$SkipBuild,
    [switch]$SkipRun
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Push-Location $RepoRoot
try {
    function Write-Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

    $alertsFile = if ($Source -eq "alerts") { "alerts.json" } else { "archives.json" }
    $alertsPath = Join-Path $OutDir $alertsFile
    $truthPath  = Join-Path $OutDir "ground_truth.csv"
    $dataPath   = Join-Path $OutDir "lab_dataset.csv"

    # ------------------------------------------------------------- pull
    Write-Step "pulling $Source from soc-siem since $Since"
    & vagrant ssh soc-siem -c "pull-alerts '$Since' $Source"
    if ($LASTEXITCODE -ne 0) {
        throw "vagrant ssh failed (is soc-siem up? try: vagrant status)"
    }
    if (-not (Test-Path $alertsPath)) {
        throw "expected $alertsPath but it does not exist"
    }
    if ($alertsPath -like "*alerts.json" -and $Source -eq "archives") {
        Write-Warning "manager fell back to alerts.json; check lab-status on the SIEM"
    }

    # --------------------------------------------------------- validate
    Write-Step "capture size"
    $lines = (Get-Content $alertsPath | Measure-Object -Line).Lines
    $sizeMb = [math]::Round((Get-Item $alertsPath).Length / 1MB, 1)
    Write-Host "$alertsPath : $lines lines, $sizeMb MB"
    if (-not (Test-Path $truthPath)) {
        throw @"
Ground truth missing at $truthPath.
Run .\run-atomics.ps1 on the victim first, or copy the file in by hand.
An unlabelled capture cannot be evaluated.
"@
    }

    if ($SkipBuild) { return }

    # --------------------------------------------------------------- build
    Write-Step "building pipeline dataset"
    & python (Join-Path $RepoRoot "lab\bridge\build_dataset.py") `
        --alerts $alertsPath `
        --truth $truthPath `
        --inventory (Join-Path $RepoRoot "lab\inventory") `
        --match $Match `
        --slack-seconds $SlackSeconds `
        --out $dataPath
    if ($LASTEXITCODE -ne 0) { throw "build_dataset.py failed" }

    if ($SkipRun) { return }

    # ----------------------------------------------------------------- run
    Write-Step "running the study on the captured data"
    & python (Join-Path $RepoRoot "run_experiments.py") `
        --source csv --path $dataPath --outdir $ResultsDir
    if ($LASTEXITCODE -ne 0) { throw "run_experiments.py failed" }

    Write-Step "done"
    Write-Host "dataset : $dataPath"
    Write-Host "report  : $(Join-Path $ResultsDir 'report.md')"
    Write-Host @"

Read the report's Limitations section before quoting any number. A 2-3 day
capture is a plumbing test with directional effect sizes, not an enterprise
measurement. Compare it against results/report.md, do not replace it.
"@ -ForegroundColor Yellow
}
finally {
    Pop-Location
}
