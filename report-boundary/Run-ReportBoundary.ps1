param(
    [string]$StudyPath = '',
    [string]$ReviewPath = '',
    [string]$LegacyRejections = ''
)

$ErrorActionPreference = 'Stop'
if ($ReviewPath -and $LegacyRejections) { throw 'Choose one review input.' }
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'Existing .venv\Scripts\python.exe missing. Use the original project environment.'
}
if (-not $StudyPath) {
    $runs = Join-Path $projectRoot 'baseline-runs'
    $candidates = @(Get-ChildItem -LiteralPath $runs -Directory -Filter 'agent-v3-validation-*' |
        Where-Object {
            (Test-Path -LiteralPath (Join-Path $_.FullName 'artifact-sha256.json') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'summary.json') -PathType Leaf)
        } | Sort-Object Name -Descending)
    if ($candidates.Count -eq 0) { throw 'No completed v3 study found. Pass -StudyPath explicitly.' }
    $StudyPath = $candidates[0].FullName
}
$StudyPath = (Resolve-Path -LiteralPath $StudyPath).Path
if ($ReviewPath) { $ReviewPath = (Resolve-Path -LiteralPath $ReviewPath).Path }
if ($LegacyRejections) { $LegacyRejections = (Resolve-Path -LiteralPath $LegacyRejections).Path }
$runs = Join-Path $projectRoot 'baseline-runs'
New-Item -ItemType Directory -Force -Path $runs | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fffffff'
$output = Join-Path $runs "report-boundary-$stamp"
$arguments = @((Join-Path $PSScriptRoot 'report_boundary.py'), '--study', $StudyPath, '--output', $output)
if ($ReviewPath) { $arguments += @('--review-json', $ReviewPath) }
if ($LegacyRejections) { $arguments += @('--import-legacy-rejections', $LegacyRejections) }
Write-Host "Study: $StudyPath"
Write-Host 'Offline publication: zero model calls; existing study remains the input.'
& $python @arguments
if ($LASTEXITCODE -ne 0) { throw "Report stopped with exit code $LASTEXITCODE." }
$archive = "$output.zip"
Compress-Archive -LiteralPath $output -DestinationPath $archive
Write-Host "Saved: $archive"
Write-Host 'Read group-*/report.md. Model responses stay under review-only unless the review gate passes.'
