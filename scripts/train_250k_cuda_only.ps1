[CmdletBinding()]
param(
    [string]$ProjectRoot = "D:\graph_sentinel"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Set-Location $ProjectRoot

$logDirectory = Join-Path $ProjectRoot "artifacts\logs"
$logPath = Join-Path $logDirectory "lanl_250k_cuda_training.log"
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
Start-Transcript -Path $logPath -Append | Out-Null

$python = Join-Path $ProjectRoot ".venv-cuda\Scripts\python.exe"
$torchLib = Join-Path $ProjectRoot ".venv-cuda\Lib\site-packages\torch\lib"
$features = "data/processed/features_lanl_bounded"
$idMaps = "artifacts/id_maps_lanl_bounded"
$baseline = "artifacts/metrics/baselines_lanl_bounded.json"
$checkpoint = "artifacts/models/tgn-lanl_250k_cuda.pt"
$report = "artifacts/metrics/tgn_lanl_250k_cuda_training.json"

foreach ($path in @($python, $torchLib, $features, $idMaps, $baseline, "artifacts/reports/features_lanl_bounded.json")) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required completed-run artifact is missing: $path" }
}
foreach ($path in @($checkpoint, $report)) {
    if (Test-Path -LiteralPath $path) { throw "Refusing to overwrite an existing training artifact: $path" }
}

$env:PATH = "$torchLib;$env:PATH"
$env:PYTHONNOUSERSITE = "1"
Write-Host "Verifying CUDA access..." -ForegroundColor Cyan
& $python -c "import torch; assert torch.cuda.is_available(), 'PyTorch cannot access CUDA'; print('PyTorch ' + torch.__version__); print('GPU: ' + torch.cuda.get_device_name(0))"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$started = Get-Date
Write-Host ("Started {0}" -f $started.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor Cyan
Write-Host "Subset: 249,856 LANL events, all 702 red-team positives kept, normals sampled across the attack window." -ForegroundColor Cyan
Write-Host "GPU: RTX 3050 6GB. 12 epochs max, early stop after 3 stale validation epochs." -ForegroundColor Cyan
Write-Host "Rough completion window: 50-90 minutes if early stopping fires; up to about 2.5 hours for all 12 epochs." -ForegroundColor Yellow
Write-Host ("Likely finish around {0} (use {1} if it runs the full 12 epochs)." -f $started.AddMinutes(75).ToString("HH:mm"), $started.AddMinutes(150).ToString("HH:mm")) -ForegroundColor Yellow

Write-Host "Starting 250K-event TGN training on GPU..." -ForegroundColor Cyan
& $python -u -m graphsentinel train tgn `
    --input $features `
    --feature-report "artifacts/reports/features_lanl_bounded.json" `
    --baseline-report $baseline `
    --id-maps $idMaps `
    --checkpoint $checkpoint `
    --report $report `
    --max-events 250000 `
    --epochs 12 `
    --patience 3 `
    --device cuda
$exitCode = $LASTEXITCODE
Write-Host ("Finished {0}; elapsed {1:N1} minutes; exit $exitCode" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), ((Get-Date) - $started).TotalMinutes)
exit $exitCode
