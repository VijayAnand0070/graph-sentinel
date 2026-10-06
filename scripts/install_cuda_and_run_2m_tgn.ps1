[CmdletBinding()]
param(
    [string]$ProjectRoot = "D:\graph_sentinel",
    [int]$WheelDownloadProcessId = 4156
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Set-Location $ProjectRoot

$python = Join-Path $ProjectRoot ".venv-cuda\Scripts\python.exe"
$wheel = Join-Path $ProjectRoot "artifacts\installers\torch-2.11.0+cu128-cp313-cp313-win_amd64.whl"
$runScript = Join-Path $ProjectRoot "scripts\run_bounded_lanl_tgn.ps1"
$torchLib = Join-Path $ProjectRoot ".venv-cuda\Lib\site-packages\torch\lib"

if (-not (Test-Path -LiteralPath $python)) { throw "CUDA environment is missing: $python" }
if (-not (Test-Path -LiteralPath $wheel)) { throw "CUDA wheel is missing: $wheel" }

Write-Host "Waiting for the official CUDA PyTorch wheel download..." -ForegroundColor Cyan
$download = Get-Process -Id $WheelDownloadProcessId -ErrorAction SilentlyContinue
if ($null -ne $download) { Wait-Process -Id $WheelDownloadProcessId }

Write-Host "Installing CUDA PyTorch into the isolated environment..." -ForegroundColor Cyan
& $python -m pip install --force-reinstall --no-deps $wheel
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Windows needs the bundled CUDA DLLs available before Python imports PyTorch.
if (-not (Test-Path -LiteralPath $torchLib)) { throw "PyTorch library directory is missing: $torchLib" }
$env:PATH = "$torchLib;$env:PATH"

Write-Host "Verifying CUDA access..." -ForegroundColor Cyan
$verification = & $python -c "import torch; assert torch.cuda.is_available(), 'PyTorch cannot access CUDA'; print(torch.__version__); print(torch.cuda.get_device_name(0))"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$verification | ForEach-Object { Write-Host $_ -ForegroundColor Green }

Write-Host "Starting separate 2-million-event GPU TGN pipeline..." -ForegroundColor Cyan
& $runScript `
    -ProjectRoot $ProjectRoot `
    -SampleStride 256 `
    -EndTimestamp 2600000 `
    -MaxEvents 2000000 `
    -Epochs 8 `
    -Patience 2 `
    -RunName "lanl_2m_cuda" `
    -Device cuda `
    -PythonExecutable $python
exit $LASTEXITCODE
