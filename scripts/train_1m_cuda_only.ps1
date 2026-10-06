[CmdletBinding()]
param(
    [string]$ProjectRoot = "D:\graph_sentinel"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Set-Location $ProjectRoot

$logDirectory = Join-Path $ProjectRoot "artifacts\logs"
$logPath = Join-Path $logDirectory "lanl_1m_cuda_training_only.log"
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
Start-Transcript -Path $logPath -Append | Out-Null

$python = Join-Path $ProjectRoot ".venv-cuda\Scripts\python.exe"
$torchLib = Join-Path $ProjectRoot ".venv-cuda\Lib\site-packages\torch\lib"
$features = "data/processed/features_lanl_1m_cuda"
$idMaps = "artifacts/id_maps_lanl_1m_cuda"
$baseline = "artifacts/metrics/baselines_lanl_1m_cuda.json"
$checkpoint = "artifacts/models/tgn-lanl_1m_cuda.pt"
$report = "artifacts/metrics/tgn_lanl_1m_cuda_training.json"

foreach ($path in @($python, $torchLib, $features, $idMaps, $baseline)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required completed-run artifact is missing: $path" }
}
foreach ($path in @($checkpoint, $report)) {
    if (Test-Path -LiteralPath $path) { throw "Refusing to overwrite an existing training artifact: $path" }
}

$env:PATH = "$torchLib;$env:PATH"
Write-Host "Verifying CUDA access..." -ForegroundColor Cyan
& $python -c "import torch; assert torch.cuda.is_available(), 'PyTorch cannot access CUDA'; print('PyTorch ' + torch.__version__); print('GPU: ' + torch.cuda.get_device_name(0))"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Training TGN on the completed 1-million-event dataset..." -ForegroundColor Cyan
& $python -m graphsentinel train tgn `
    --input $features `
    --feature-report "artifacts/reports/features_lanl_1m_cuda.json" `
    --baseline-report $baseline `
    --id-maps $idMaps `
    --checkpoint $checkpoint `
    --report $report `
    --max-events 1000000 `
    --epochs 8 `
    --patience 2 `
    --device cuda
exit $LASTEXITCODE
