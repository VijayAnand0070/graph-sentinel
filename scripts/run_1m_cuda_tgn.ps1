[CmdletBinding()]
param(
    [string]$ProjectRoot = "D:\graph_sentinel"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Set-Location $ProjectRoot

$logDirectory = Join-Path $ProjectRoot "artifacts\logs"
$logPath = Join-Path $logDirectory "lanl_1m_cuda_console.log"
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
Start-Transcript -Path $logPath -Append | Out-Null

$python = Join-Path $ProjectRoot ".venv-cuda\Scripts\python.exe"
$torchLib = Join-Path $ProjectRoot ".venv-cuda\Lib\site-packages\torch\lib"
$runScript = Join-Path $ProjectRoot "scripts\run_bounded_lanl_tgn.ps1"

if (-not (Test-Path -LiteralPath $python)) { throw "CUDA environment is missing: $python" }
if (-not (Test-Path -LiteralPath $torchLib)) { throw "PyTorch CUDA libraries are missing: $torchLib" }
$env:PATH = "$torchLib;$env:PATH"

Write-Host "Verifying CUDA access on this machine..." -ForegroundColor Cyan
& $python -c "import torch; assert torch.cuda.is_available(), 'PyTorch cannot access CUDA'; print('PyTorch ' + torch.__version__); print('GPU: ' + torch.cuda.get_device_name(0))"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Starting separate 1-million-event GPU TGN pipeline..." -ForegroundColor Cyan
& $runScript `
    -ProjectRoot $ProjectRoot `
    -SampleStride 512 `
    -EndTimestamp 2600000 `
    -MaxEvents 1000000 `
    -Epochs 8 `
    -Patience 2 `
    -RunName "lanl_1m_cuda" `
    -Device cuda `
    -PythonExecutable $python
exit $LASTEXITCODE
