param(
    [ValidateSet("check", "analyze", "agent", "report", "serve")][string]$Mode = "check",
    [string]$Project = (Join-Path $PSScriptRoot ".."),
    [string]$Capture = "",
    [string]$Goal = "",
    [string]$RunId = "",
    [string]$Tools = "all",
    [string]$AllowedDir = ""
)
$ErrorActionPreference = "Stop"
try {
    $projectRoot = (Resolve-Path -LiteralPath $Project).Path
    $pythonExe = Join-Path $projectRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) { throw "Project Python not found." }
    $parameters = @("-X", "utf8", "-B", (Join-Path $PSScriptRoot "run_project.py"), "--mode", $Mode, "--project", $projectRoot)
    if ($Capture) { $parameters += @("--capture", $Capture) }
    if ($Goal) { $parameters += @("--goal", $Goal) }
    if ($RunId) { $parameters += @("--run-id", $RunId) }
    if ($Tools) { $parameters += @("--tools", $Tools) }
    if ($AllowedDir) { $parameters += @("--allowed-dir", $AllowedDir) }
    Push-Location -LiteralPath $projectRoot
    try {
        & $pythonExe @parameters
        $runExitCode = $LASTEXITCODE
    } finally { Pop-Location }
    exit $runExitCode
} catch {
    Write-Host ("Stopped: " + $_.Exception.Message)
    exit 2
}
