# ---------------------------------------------------------------------------
# Execute the Atomic Red Team tests that map onto the thesis rule catalog and
# write the ground-truth schedule the bridge consumes.
#
#   .\run-atomics.ps1 -DryRun
#   .\run-atomics.ps1                       # all techniques in atomics.csv
#   .\run-atomics.ps1 -Technique T1059.001  # one technique, for a smoke test
#
# Ground truth is deliberately *scheduled*, not inferred: we record the wall
# clock window in which each test executed, and the bridge labels an alert as
# malicious when its host, rule and timestamp fall inside such a window.
#
# A test that Defender blocks produces no telemetry. It is still written to
# ground_truth.csv with status=blocked so the omission is visible in the
# results rather than silently inflating precision.
# ---------------------------------------------------------------------------
[CmdletBinding()]
param(
    [string]$Catalog = (Join-Path $PSScriptRoot "atomics.csv"),
    [string]$OutDir = "C:\lab\out",
    [string]$Technique,
    [string]$SiemUrl = "http://192.168.56.10:8088",
    [int]$MaxTestsPerTechnique = 2,
    [int]$TimeoutSeconds = 180,
    [int]$SettleSeconds = 5,
    [switch]$DryRun,
    [switch]$NoUpload
)

$ErrorActionPreference = "Continue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Import-Module invoke-atomicredteam -Force -ErrorAction Stop

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp   = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$runRoot = Join-Path $OutDir "run-$stamp"
New-Item -ItemType Directory -Force -Path $runRoot | Out-Null

$manifest = Join-Path $runRoot "run_manifest.json"
$truth    = Join-Path $OutDir "ground_truth.csv"
$hostName = $env:COMPUTERNAME

function Now-Iso { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }

function Write-Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

# --------------------------------------------------------------- catalog input
$rows = Import-Csv -Path $Catalog
if ($Technique) {
    $rows = $rows | Where-Object { $_.technique -eq $Technique }
}
if (-not $rows) {
    throw "no techniques selected (catalog=$Catalog, technique=$Technique)"
}

# ------------------------------------------------------------ test discovery
function Get-TestPlan {
    param([string]$Technique, [string]$Keyword, [string]$Numbers)

    $objects = Get-AtomicTechnique -Technique $Technique
    if (-not $objects) { return @() }

    $tests = @()
    foreach ($o in $objects) {
        if ($o.atomic_tests) { $tests += $o.atomic_tests }
    }

    $plan = @()
    for ($i = 0; $i -lt $tests.Count; $i++) {
        $t = $tests[$i]
        $win = ($t.supported_platforms -join ",").ToLower()
        if ($win -and $win -notmatch "windows") { continue }
        if ($Numbers) {
            $want = $Numbers.Split(",") | ForEach-Object { $_.Trim() }
            if ($want -notcontains [string]($i + 1)) { continue }
        } elseif ($Keyword) {
            $text = "$($t.name) $($t.description)"
            if ($text -notmatch [regex]::Escape($Keyword)) { continue }
        }
        $plan += [pscustomobject]@{
            Index       = $i + 1
            Name        = $t.name
            Description = $t.description
        }
    }
    return $plan
}

function Test-WasBlocked {
    param([string]$Text)
    if (-not $Text) { return $false }
    return $Text -match "blocked|quarantin|Access is denied|Antivirus|0x80070005|operation did not complete"
}

# -------------------------------------------------------------------- execute
$records = New-Object System.Collections.Generic.List[object]
$executed = 0
$blocked = 0
$failed = 0

foreach ($row in $rows) {
    $tech = $row.technique
    Write-Step "$tech  ($($row.rule_id))"

    try {
        $plan = Get-TestPlan -Technique $tech -Keyword $row.keyword -Numbers $row.test_numbers
    } catch {
        Write-Warning "could not enumerate $tech : $($_.Exception.Message)"
        $failed++
        continue
    }

    if (-not $plan) {
        Write-Warning "no matching test for $tech / keyword '$($row.keyword)'"
        $failed++
        continue
    }

    $plan = $plan | Select-Object -First $MaxTestsPerTechnique

    foreach ($t in $plan) {
        $label = "$tech #$($t.Index) $($t.Name)"
        Write-Host "  -> $label" -ForegroundColor DarkGray

        if ($DryRun) {
            $records.Add([pscustomobject]@{
                run_id = "run-$stamp-$executed"; rule_id = $row.rule_id
                technique = $tech; atomic_test = $t.Index; action = "atomic"
                host = $hostName; start_utc = ""; end_utc = ""
                executor = "Invoke-AtomicTest"; status = "dry-run"
                description = $t.Name
            }) | Out-Null
            $executed++
            continue
        }

        # Prerequisites first: anything they drop on disk happens outside the
        # labelling window on purpose, so the download itself is not counted as
        # part of the technique under test.
        try {
            Invoke-AtomicTest $tech -TestNumbers $t.Index -GetPrereqs `
                -TimeoutSeconds $TimeoutSeconds -ErrorAction SilentlyContinue | Out-Null
        } catch { }

        Start-Sleep -Seconds 2
        $start = Now-Iso
        $status = "executed"
        $output = ""
        try {
            $output = (Invoke-AtomicTest $tech -TestNumbers $t.Index `
                -TimeoutSeconds $TimeoutSeconds -Confirm:$false `
                -ErrorAction Continue 2>&1 | Out-String)
            if (Test-WasBlocked $output) {
                $status = "blocked"
                $blocked++
            } else {
                $executed++
            }
        } catch {
            $status = "failed"
            $output = $_.Exception.Message
            $failed++
        }
        Start-Sleep -Seconds $SettleSeconds
        $end = Now-Iso

        $records.Add([pscustomobject]@{
            run_id = "run-$stamp-$($records.Count)"; rule_id = $row.rule_id
            technique = $tech; atomic_test = $t.Index; action = "atomic"
            host = $hostName; start_utc = $start; end_utc = $end
            executor = "Invoke-AtomicTest"; status = $status
            description = $t.Name
        }) | Out-Null

        # Keep the raw output: it is the evidence for why a test was blocked.
        $safe = ($t.Name -replace "[^A-Za-z0-9._-]", "_")
        Set-Content -Path (Join-Path $runRoot "$tech-$($t.Index)-$safe.log") `
            -Value $output -Encoding UTF8

        try {
            Invoke-AtomicTest $tech -TestNumbers $t.Index -Cleanup `
                -TimeoutSeconds 60 -ErrorAction SilentlyContinue | Out-Null
        } catch { }
        Start-Sleep -Seconds 1
    }
}

# ---------------------------------------------------------------------- output
$columns = "run_id", "rule_id", "technique", "atomic_test", "action", "host",
           "start_utc", "end_utc", "executor", "status", "description"
$records | Select-Object $columns | Export-Csv -Path $truth -NoTypeInformation -Encoding UTF8

$meta = [ordered]@{
    started_utc   = $stamp
    finished_utc  = Now-Iso
    host          = $hostName
    catalog       = $Catalog
    executed      = $executed
    blocked       = $blocked
    failed        = $failed
    dry_run       = [bool]$DryRun
    atomics_module = (Get-Module invoke-atomicredteam).Version.ToString()
    os            = (Get-CimInstance Win32_OperatingSystem).Caption
}
$meta | ConvertTo-Json | Set-Content -Path $manifest -Encoding UTF8

Write-Step "summary"
Write-Host "executed=$executed  blocked=$blocked  failed=$failed"
Write-Host "ground truth -> $truth"

if ($blocked -gt 0) {
    Write-Warning @"
$blocked test(s) look blocked by Defender. Those windows produced no telemetry
and will be reported as 'blocked' in the thesis. If you need them, add
C:\AtomicRedTeam to Defender exclusions and re-run, but say so in the write-up:
an environment with Defender disabled is not an enterprise control environment.
"@
}

# ---------------------------------------------------------------------- upload
if (-not $NoUpload -and -not $DryRun) {
    try {
        Invoke-RestMethod -Uri "$SiemUrl/health" -TimeoutSec 5 | Out-Null
        Invoke-RestMethod -Uri "$SiemUrl/ground_truth" -Method Post `
            -InFile $truth -ContentType "text/csv" -TimeoutSec 30 | Out-Null
        Invoke-RestMethod -Uri "$SiemUrl/manifest" -Method Post `
            -InFile $manifest -ContentType "application/json" -TimeoutSec 30 | Out-Null
        Write-Host "uploaded ground truth to $SiemUrl" -ForegroundColor Green
    } catch {
        Write-Warning "upload failed ($($_.Exception.Message))."
        Write-Host "Copy $truth to the host manually, or re-run with -SiemUrl <ip>."
    }
}
