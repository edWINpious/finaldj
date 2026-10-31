# Demo helpers for the web decoy (Windows PowerShell 5.1+ and PowerShell 7).
#
# Load once per PowerShell window, from ANY folder:
#     . C:\Users\<you>\...\PS4---DJS\services\web\scripts\demo_helpers.ps1
# (note the leading dot and space: "dot-sourcing" keeps the functions in your window)
#
# Then:
#     Last        newest event, readable, with the rules that fired
#     Rules       every event, one line each, with the rules that fired
#     ClearLog    empty the event log before a demo
#     DemoFiles   create the scratch files used by the size/slow/upload cases
#     CleanFiles  delete those scratch files
#
# Paths are resolved relative to this script, so the current folder does not matter.

$script:WebDir  = Split-Path -Parent $PSScriptRoot
$script:EventLog = Join-Path $script:WebDir "data\web-events.jsonl"

function Last {
    if (-not (Test-Path $script:EventLog)) { "No events yet ($script:EventLog)"; return }
    $line = Get-Content $script:EventLog -Tail 1
    if (-not $line) { "Log is empty"; return }
    $e = $line | ConvertFrom-Json
    "path=$($e.request_path)  status=$($e.http_status)  outcome=$($e.outcome)  ip=$($e.source_ip)  campaign=$($e.campaign_id)  tags=$($e.tags -join ',')"
    foreach ($d in $e.raw_evidence_redacted.detections) {
        $tech = ($d.attack | ForEach-Object { $_.technique }) -join ','
        "   RULE $($d.rule) [$($d.confidence)] field=$($d.field) attack=$tech  -> $($d.rationale)"
    }
}

function Rules {
    if (-not (Test-Path $script:EventLog)) { "No events yet ($script:EventLog)"; return }
    Get-Content $script:EventLog | ForEach-Object {
        $e = $_ | ConvertFrom-Json
        $r = ($e.raw_evidence_redacted.detections | ForEach-Object { $_.rule + "(" + $_.confidence + ")" }) -join ", "
        "{0,-28} {1}" -f $e.request_path, $r
    }
}

function ClearLog {
    if (Test-Path $script:EventLog) { Clear-Content $script:EventLog }
    "Event log cleared: $script:EventLog"
}

function DemoFiles {
    Push-Location $script:WebDir
    [IO.File]::WriteAllText((Join-Path $script:WebDir "big.txt"), ("a" * 70000))
    [IO.File]::WriteAllText((Join-Path $script:WebDir "slow.txt"), ("a" * 2000))
    [IO.File]::WriteAllText((Join-Path $script:WebDir "avatar.jpg"), "<?php system(1); ?>")
    [IO.File]::WriteAllBytes((Join-Path $script:WebDir "big.bin"), (New-Object byte[] 1500000))
    Pop-Location
    "Created big.txt, slow.txt, avatar.jpg, big.bin in $script:WebDir (run the demo commands from this folder)"
}

function CleanFiles {
    foreach ($f in "big.txt", "slow.txt", "avatar.jpg", "big.bin", "jar.txt") {
        $p = Join-Path $script:WebDir $f
        if (Test-Path $p) { Remove-Item $p }
    }
    "Scratch files removed"
}

"Demo helpers loaded. Log: $script:EventLog  |  Commands: Last, Rules, ClearLog, DemoFiles, CleanFiles"
