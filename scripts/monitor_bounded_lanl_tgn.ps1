[CmdletBinding()]
param(
    [string]$ProjectRoot = "D:\graph_sentinel",
    [int]$RefreshSeconds = 15
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$interim = Join-Path $ProjectRoot "data\interim_lanl_bounded"
$features = Join-Path $ProjectRoot "data\processed\features_lanl_bounded"
$baseline = Join-Path $ProjectRoot "artifacts\metrics\baselines_lanl_bounded.json"
$checkpoint = Join-Path $ProjectRoot "artifacts\models\tgn-lanl-bounded.pt"
$training = Join-Path $ProjectRoot "artifacts\metrics\tgn_lanl_bounded_training.json"

while ($true) {
    Clear-Host
    $drive = [System.IO.DriveInfo]::new("D")
    $python = @(Get-Process -Name python -ErrorAction SilentlyContinue | Where-Object {
        $_.StartTime -gt (Get-Date).AddHours(-4)
    })
    $interimFiles = @(Get-ChildItem -LiteralPath $interim -File -Recurse -ErrorAction SilentlyContinue)
    $featureFiles = @(Get-ChildItem -LiteralPath $features -File -Recurse -ErrorAction SilentlyContinue)
    $stage = if (Test-Path -LiteralPath $training) {
        "COMPLETE"
    } elseif (Test-Path -LiteralPath $checkpoint) {
        "TGN checkpoint created; completing report"
    } elseif (Test-Path -LiteralPath $baseline) {
        "TGN training"
    } elseif (Test-Path -LiteralPath $features) {
        "Baseline evaluation"
    } elseif (Test-Path -LiteralPath $interim) {
        "Stage 1/4 - bounded chronological subset"
    } else {
        "Starting pipeline"
    }
    Write-Host "GraphSentinel bounded LANL pipeline monitor" -ForegroundColor Cyan
    Write-Host "Updated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host "Current stage: $stage" -ForegroundColor Yellow
    Write-Host "D: free space: $([math]::Round($drive.AvailableFreeSpace / 1GB, 2)) GB"
    Write-Host "Active Python workers: $($python.Count)"
    Write-Host "Subset Parquet files: $($interimFiles.Count)"
    Write-Host "Feature Parquet files: $($featureFiles.Count)"
    if (Test-Path -LiteralPath $training) {
        Write-Host "Training report: $training" -ForegroundColor Green
        break
    }
    Start-Sleep -Seconds $RefreshSeconds
}

Write-Host "Monitor finished. Press Enter to close."
[void](Read-Host)
