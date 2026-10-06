[CmdletBinding()]
param(
    [string]$ProjectRoot = "D:\graph_sentinel",
    [ValidateRange(0, 64)]
    [int]$SegmentCount = 8,
    [long]$ExpectedArchiveBytes = 7626505158,
    [int]$DownloadTimeoutHours = 10,
    [int]$MaxEvents = 250000,
    [int]$Epochs = 12,
    [int]$Patience = 3
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$staging = Join-Path $ProjectRoot "artifacts\downloads\lanl"
$runtime = Join-Path $ProjectRoot "artifacts\runtime"
$logPath = Join-Path $runtime "lanl-tgn-automation.log"
$authPath = Join-Path $staging "auth.txt.gz"
$redteamPath = Join-Path $staging "redteam.txt.gz"
$assemblingPath = Join-Path $staging "auth.txt.gz.assembling"
$phase16Url = "http://127.0.0.1:8000/api/v1/phase16"

New-Item -ItemType Directory -Path $runtime -Force | Out-Null

function Write-RunLog {
    param([Parameter(Mandatory)][string]$Message)
    $line = "{0} {1}" -f (Get-Date).ToString("o"), $Message
    Add-Content -LiteralPath $logPath -Value $line
}

function Get-ExpectedSegmentLength {
    param([Parameter(Mandatory)][int]$Index)
    $start = [long][math]::Floor($Index * $ExpectedArchiveBytes / $SegmentCount)
    $end = if ($Index -eq $SegmentCount - 1) {
        $ExpectedArchiveBytes - 1
    }
    else {
        [long][math]::Floor(($Index + 1) * $ExpectedArchiveBytes / $SegmentCount) - 1
    }
    return $end - $start + 1
}

try {
    $deadline = (Get-Date).AddHours($DownloadTimeoutHours)
    $archiveReady =
        (Test-Path -LiteralPath $authPath -PathType Leaf) -and
        ((Get-Item -LiteralPath $authPath).Length -eq $ExpectedArchiveBytes)

    if (-not $archiveReady -and $SegmentCount -eq 0) {
        Write-RunLog "Automation started; waiting for the resumable background LANL archive transfer."
        while ($true) {
            if (
                (Test-Path -LiteralPath $authPath -PathType Leaf) -and
                ((Get-Item -LiteralPath $authPath).Length -eq $ExpectedArchiveBytes)
            ) {
                $archiveReady = $true
                break
            }
            if ((Get-Date) -ge $deadline) {
                throw "Timed out after $DownloadTimeoutHours hours waiting for the LANL archive."
            }
            Start-Sleep -Seconds 30
        }
    }

    if (-not $archiveReady -and $SegmentCount -gt 0) {
        Write-RunLog "Automation started; waiting for $SegmentCount LANL authentication segments."
        while ($true) {
            $exitFiles = @(Get-ChildItem -LiteralPath $staging -Filter "segment-*.exit" -File -ErrorAction SilentlyContinue)
            if ($exitFiles.Count -eq $SegmentCount) {
                break
            }
            if ((Get-Date) -ge $deadline) {
                throw "Timed out after $DownloadTimeoutHours hours waiting for LANL download segments."
            }
            Start-Sleep -Seconds 30
        }

        for ($index = 0; $index -lt $SegmentCount; $index++) {
            $suffix = "{0:D2}" -f $index
            $exitPath = Join-Path $staging "segment-$suffix.exit"
            $partPath = Join-Path $staging "auth.part$suffix"
            $exitCode = (Get-Content -LiteralPath $exitPath -Raw).Trim()
            if ($exitCode -ne "0") {
                throw "LANL segment $suffix failed with curl exit code $exitCode."
            }
            $actualLength = (Get-Item -LiteralPath $partPath).Length
            $expectedLength = Get-ExpectedSegmentLength -Index $index
            if ($actualLength -ne $expectedLength) {
                throw "LANL segment $suffix length mismatch: expected $expectedLength, got $actualLength."
            }
        }

        Write-RunLog "All segments passed exit-code and exact-length validation; assembling archive."
        if (Test-Path -LiteralPath $authPath) {
            throw "Refusing to overwrite an existing authentication archive at $authPath."
        }
        if (Test-Path -LiteralPath $assemblingPath) {
            Remove-Item -LiteralPath $assemblingPath -Force
        }

        $output = [System.IO.File]::Open(
            $assemblingPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        try {
            for ($index = 0; $index -lt $SegmentCount; $index++) {
                $partPath = Join-Path $staging ("auth.part{0:D2}" -f $index)
                $input = [System.IO.File]::OpenRead($partPath)
                try {
                    $input.CopyTo($output, 4MB)
                }
                finally {
                    $input.Dispose()
                }
            }
            $output.Flush($true)
        }
        finally {
            $output.Dispose()
        }

        if ((Get-Item -LiteralPath $assemblingPath).Length -ne $ExpectedArchiveBytes) {
            throw "Assembled LANL archive length does not match the official content length."
        }
        Move-Item -LiteralPath $assemblingPath -Destination $authPath
        $archiveReady = $true
    }

    if (-not $archiveReady) {
        throw "The LANL authentication archive is not ready."
    }

    if (-not (Test-Path -LiteralPath $redteamPath -PathType Leaf)) {
        throw "The LANL red-team label archive is missing."
    }

    Write-RunLog "Running complete gzip integrity scans for authentication and label archives."
    $gzipCheck = @'
import gzip
import pathlib
import sys

for raw_path in sys.argv[1:]:
    path = pathlib.Path(raw_path)
    with gzip.open(path, "rb") as stream:
        while stream.read(4 * 1024 * 1024):
            pass
    print(f"gzip-ok {path.name} {path.stat().st_size}")
'@
    & python -c $gzipCheck $authPath $redteamPath | ForEach-Object { Write-RunLog $_ }
    if ($LASTEXITCODE -ne 0) {
        throw "A downloaded LANL archive failed its complete gzip integrity scan."
    }

    $authSha = (Get-FileHash -LiteralPath $authPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $redteamSha = (Get-FileHash -LiteralPath $redteamPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-RunLog "Archive integrity complete; auth_sha256=$authSha redteam_sha256=$redteamSha."

    Push-Location $ProjectRoot
    try {
        Write-RunLog "Running GraphSentinel registration dry run."
        & python -m graphsentinel dataset register --source $staging --require core 2>&1 |
            ForEach-Object { Write-RunLog $_.ToString() }
        if ($LASTEXITCODE -ne 0) {
            throw "GraphSentinel dataset registration dry run failed."
        }

        Write-RunLog "Registering immutable LANL core files with a full contract scan."
        & python -m graphsentinel dataset register --source $staging --require core --execute --full-scan 2>&1 |
            ForEach-Object { Write-RunLog $_.ToString() }
        if ($LASTEXITCODE -ne 0) {
            throw "GraphSentinel full-scan dataset registration failed."
        }
    }
    finally {
        Pop-Location
    }

    Write-RunLog "Registration passed; requesting Phase 16 TGN pipeline execution."
    $body = @{
        max_events = $MaxEvents
        epochs = $Epochs
        patience = $Patience
        device = "auto"
    } | ConvertTo-Json
    $startResponse = Invoke-RestMethod -Uri "$phase16Url/start" -Method Post -ContentType "application/json" -Body $body
    Write-RunLog ("TGN job accepted: {0}" -f $startResponse.job.job_id)

    while ($true) {
        Start-Sleep -Seconds 30
        $status = Invoke-RestMethod -Uri $phase16Url -Method Get
        $state = $status.job.state
        $progress = $status.job.progress
        $stage = $status.job.stage
        Write-RunLog "Training state=$state stage=$stage progress=$progress."
        if ($state -in @("completed", "failed", "rejected")) {
            Write-RunLog ("Terminal job state=$state; promotion={0}; decision={1}" -f $status.promotion.status, $status.promotion.decision)
            if ($state -ne "completed") {
                exit 1
            }
            exit 0
        }
    }
}
catch {
    Write-RunLog ("FAILED: " + $_.Exception.Message)
    exit 1
}
