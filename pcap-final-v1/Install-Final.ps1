param([string]$Project = (Join-Path $PSScriptRoot ".."))
$ErrorActionPreference = "Stop"
try {
    $projectRoot = (Resolve-Path -LiteralPath $Project).Path
    $pythonExe = Join-Path $projectRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) { throw "Project Python not found." }
    & $pythonExe -X utf8 -B (Join-Path $PSScriptRoot "run_project.py") --mode check --project $projectRoot
    if ($LASTEXITCODE -ne 0) { throw "Final entry check failed; project documentation was not replaced." }
    foreach ($name in @("README.md", "START-HERE.md")) {
        $source = Join-Path (Join-Path $PSScriptRoot "docs") $name
        $target = Join-Path $projectRoot $name
        if (Test-Path -LiteralPath $target -PathType Leaf) {
            if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash) { continue }
            $baseName = [IO.Path]::GetFileNameWithoutExtension($name)
            $backup = Join-Path $projectRoot ($baseName + ".before-final-20261018.md")
            if (Test-Path -LiteralPath $backup) {
                $backup = Join-Path $projectRoot ($baseName + ".before-final-20261018-" + [Guid]::NewGuid().ToString("N").Substring(0,8) + ".md")
            }
            Copy-Item -LiteralPath $target -Destination $backup
        }
        Copy-Item -LiteralPath $source -Destination $target -Force
    }
    Write-Host "Final delivery installed. Original source and experiment batches are preserved."
    Write-Host "Start with START-HERE.md; daily entry: pcap-final-v1\Run-PCAP.ps1"
    Write-Host "No Ollama generation was requested during installation."
    exit 0
} catch {
    Write-Host ("Stopped: " + $_.Exception.Message)
    exit 2
}
