[CmdletBinding()]
param(
    [string]$ProjectRoot = "D:\graph_sentinel",
    [int]$MaximumHours = 24
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$email = $env:GRAPHSENTINEL_LANL_EMAIL
if ([string]::IsNullOrWhiteSpace($email)) {
    throw "GRAPHSENTINEL_LANL_EMAIL is required in the downloader process environment."
}

$usage = "Training and evaluating a Temporal Graph Network for cybersecurity authentication anomaly detection in the GraphSentinel research project."
$staging = Join-Path $ProjectRoot "artifacts\downloads\lanl"
$target = Join-Path $staging "auth.txt.gz"
$logPath = Join-Path $ProjectRoot "artifacts\runtime\lanl-download-supervisor.log"
$expectedBytes = 7626505158L
$deadline = (Get-Date).AddHours($MaximumHours)

New-Item -ItemType Directory -Path $staging -Force | Out-Null

function Write-DownloadLog {
    param([Parameter(Mandatory)][string]$Message)
    Add-Content -LiteralPath $logPath -Value ("{0} {1}" -f (Get-Date).ToString("o"), $Message)
}

while ((Get-Date) -lt $deadline) {
    if ((Test-Path -LiteralPath $target) -and (Get-Item -LiteralPath $target).Length -eq $expectedBytes) {
        Write-DownloadLog "Official archive content length reached."
        exit 0
    }

    try {
        $query = "email={0}&usage={1}" -f [uri]::EscapeDataString($email), [uri]::EscapeDataString($usage)
        $token = (Invoke-WebRequest -Uri ("https://csr.lanl.gov/data-fence/token?" + $query) -UseBasicParsing -TimeoutSec 30).Content.Trim()
        if ([string]::IsNullOrWhiteSpace($token)) {
            throw "LANL returned an empty access token."
        }

        $source = "https://csr.lanl.gov/data-fence/{0}/cyber1/auth.txt.gz" -f $token
        $before = if (Test-Path -LiteralPath $target) { (Get-Item -LiteralPath $target).Length } else { 0L }
        Write-DownloadLog "Starting or resuming official archive from byte $before."
        & curl.exe --fail --location --retry 20 --retry-all-errors --retry-delay 10 --continue-at - --output $target $source
        $code = $LASTEXITCODE
        $after = if (Test-Path -LiteralPath $target) { (Get-Item -LiteralPath $target).Length } else { 0L }
        Write-DownloadLog "curl exited code=$code bytes=$after."

        if ($code -eq 0 -and $after -eq $expectedBytes) {
            exit 0
        }
    }
    catch {
        Write-DownloadLog ("Retryable transfer error: " + $_.Exception.Message)
    }

    Start-Sleep -Seconds 30
}

Write-DownloadLog "FAILED: download supervisor exceeded the $MaximumHours-hour limit."
exit 1
