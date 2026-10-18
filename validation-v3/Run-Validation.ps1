param(
    [string[]]$Model = @('qwen3:8b'),
    [switch]$Full,
    [switch]$Offline,
    [int]$MaxRequests = 8,
    [int]$TimeoutSeconds = 120,
    [string]$Manifest = '',
    [string]$BaseUrl = 'http://localhost:11434/v1'
)

$ErrorActionPreference = 'Stop'
$Model = @($Model | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() })
if (@($Model | Where-Object { -not $_ }).Count -gt 0) { throw 'Model names must be nonempty.' }
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'Existing .venv\Scripts\python.exe missing. Use the original project environment.'
}
if ($MaxRequests -lt 1 -or $MaxRequests -gt 400) { throw 'MaxRequests must be 1..400.' }
if ($TimeoutSeconds -lt 15 -or $TimeoutSeconds -gt 600) { throw 'TimeoutSeconds must be 15..600.' }
$savedLocation = Get-Location
$names = @('PYTHONPATH', 'OPENAI_BASE_URL', 'OPENAI_API_KEY')
$previous = @{}
foreach ($name in $names) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }

function Invoke-ProjectPython {
    param([string[]]$Arguments)
    & $python @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Python stopped with exit code $LASTEXITCODE. Preserve the result directory." }
}

try {
    Set-Location -LiteralPath $projectRoot
    $env:PYTHONPATH = Join-Path $projectRoot 'src'
    $env:OPENAI_BASE_URL = $BaseUrl
    if (-not $env:OPENAI_API_KEY) { $env:OPENAI_API_KEY = 'ollama' }
    Invoke-ProjectPython -Arguments @('-c', 'import mcp, openai, pcap_mcp.validation')
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fffffff'
    $runs = Join-Path $projectRoot 'baseline-runs'
    New-Item -ItemType Directory -Force -Path $runs | Out-Null
    if (-not $Manifest) {
        $inputs = Join-Path $runs "validation-inputs-$stamp"
        Invoke-ProjectPython -Arguments @('-m', 'pcap_mcp.validation', '--generate', $inputs)
        $Manifest = Join-Path $inputs 'manifest.json'
    } else {
        $Manifest = (Resolve-Path -LiteralPath $Manifest).Path
    }
    $output = Join-Path $runs "agent-v3-validation-$stamp"
    $metadataPath = Join-Path $runs "validation-environment-$stamp.json"
    $metadata = @{ mode = 'offline_no_model_calls'; model_identities = @(); backend_context_fixed = $false }
    if (-not $Offline) {
        $uri = [Uri]$BaseUrl
        if ($uri.Scheme -notin @('http', 'https')) { throw 'BaseUrl must be an HTTP URL.' }
        $apiRoot = $uri.GetLeftPart([System.UriPartial]::Authority)
        $version = Invoke-RestMethod -Uri "$apiRoot/api/version" -TimeoutSec 15
        $tags = Invoke-RestMethod -Uri "$apiRoot/api/tags" -TimeoutSec 15
        $identities = @()
        foreach ($requested in $Model) {
            $matches = @($tags.models | Where-Object { $_.name -eq $requested -or $_.model -eq $requested })
            if ($matches.Count -ne 1 -or -not $matches[0].digest) {
                throw "Model $requested is not present with one exact digest. Keep Ollama running and use its exact installed name."
            }
            $identities += @{ name = $requested; digest = $matches[0].digest; details = $matches[0].details }
        }
        $metadata = @{ mode = 'local_ollama'; ollama_version = $version.version; model_identities = $identities; backend_context_fixed = $false }
    }
    $metadata | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $metadataPath -Encoding UTF8
    $arguments = @('-m', 'pcap_mcp.validation', '--prepare', '--manifest', $Manifest,
        '--output', $output, '--max-requests', "$MaxRequests", '--timeout', "$TimeoutSeconds",
        '--environment-json', $metadataPath)
    foreach ($requested in $Model) { $arguments += @('--model', $requested) }
    if ($Full) { $arguments += '--full' }
    Invoke-ProjectPython -Arguments $arguments
    if (-not $Offline) {
        Invoke-ProjectPython -Arguments @('-m', 'pcap_mcp.validation', '--run', $output)
        $finalVersion = Invoke-RestMethod -Uri "$apiRoot/api/version" -TimeoutSec 15
        $finalTags = Invoke-RestMethod -Uri "$apiRoot/api/tags" -TimeoutSec 15
        $identityUnchanged = ($finalVersion.version -eq $metadata.ollama_version)
        foreach ($identity in $metadata.model_identities) {
            $finalMatch = @($finalTags.models | Where-Object { $_.name -eq $identity.name -or $_.model -eq $identity.name })
            if ($finalMatch.Count -ne 1 -or $finalMatch[0].digest -ne $identity.digest) { $identityUnchanged = $false }
        }
        @{ identity_unchanged = $identityUnchanged; ollama_version = $finalVersion.version } |
            ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $output 'backend-final.json') -Encoding UTF8
    }
    Invoke-ProjectPython -Arguments @('-m', 'pcap_mcp.validation', '--replay', $output,
        '--verify-source', '--output', (Join-Path $output 'replay.json'))
    $archive = "$output.zip"
    Compress-Archive -LiteralPath $output -DestinationPath $archive
    Write-Host "Saved: $archive"
    if (-not $Offline -and -not $identityUnchanged) {
        throw 'Model identity or Ollama version changed during the run. Preserve this ZIP; do not treat it as a stable-model comparison.'
    }
    Write-Host 'Send this ZIP for review. Structure/source checks do not automatically approve prose semantics.'
} finally {
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
    Set-Location -LiteralPath $savedLocation
}
