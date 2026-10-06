[CmdletBinding()]
param(
    [string]$ProjectRoot = "D:\graph_sentinel",
    [ValidateRange(2, 100000)]
    [int]$SampleStride = 2048,
    [ValidateRange(0, 100000000)]
    [int]$EndTimestamp = 2600000,
    [ValidateRange(10000, 5000000)]
    [int]$MaxEvents = 500000,
    [ValidateRange(1, 24)]
    [int]$Epochs = 8,
    [ValidateRange(1, 12)]
    [int]$Patience = 2,
    [ValidatePattern("^[a-z0-9_-]+$")]
    [string]$RunName = "lanl_bounded",
    [ValidateSet("cpu", "cuda")]
    [string]$Device = "cpu",
    [string]$PythonExecutable = "python"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Set-Location $ProjectRoot

$interim = "data/interim_$RunName"
$features = "data/processed/features_$RunName"
$idMaps = "artifacts/id_maps_$RunName"
$ingestionReport = "artifacts/reports/ingestion_$RunName.json"
$featureReport = "artifacts/reports/features_$RunName.json"
$baselineReport = "artifacts/metrics/baselines_$RunName.json"
$checkpoint = "artifacts/models/tgn-$RunName.pt"
$trainingReport = "artifacts/metrics/tgn_${RunName}_training.json"

foreach ($path in @($interim, $features, $idMaps, $ingestionReport, $featureReport, $baselineReport, $checkpoint, $trainingReport)) {
    if (Test-Path -LiteralPath $path) {
        throw "Refusing to overwrite an existing bounded-run artifact: $path"
    }
}

Write-Host "[1/4] Building bounded chronological LANL subset..." -ForegroundColor Cyan
& $PythonExecutable -m graphsentinel ingest auth `
    --output $interim `
    --id-maps $idMaps `
    --report $ingestionReport `
    --sample-stride $SampleStride `
    --end-timestamp $EndTimestamp
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[2/4] Building causal temporal features..." -ForegroundColor Cyan
& $PythonExecutable -m graphsentinel features build `
    --input $interim `
    --output $features `
    --report $featureReport
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[3/4] Evaluating baselines..." -ForegroundColor Cyan
& $PythonExecutable -m graphsentinel evaluate baselines `
    --input $features `
    --feature-report $featureReport `
    --output $baselineReport `
    --max-events $MaxEvents `
    --isolation-forest-estimators 100
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[4/4] Training bounded TGN..." -ForegroundColor Cyan
& $PythonExecutable -m graphsentinel train tgn `
    --input $features `
    --feature-report $featureReport `
    --baseline-report $baselineReport `
    --id-maps $idMaps `
    --checkpoint $checkpoint `
    --report $trainingReport `
    --max-events $MaxEvents `
    --epochs $Epochs `
    --patience $Patience `
    --device $Device
exit $LASTEXITCODE
