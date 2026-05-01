$ErrorActionPreference = "Stop"

# Get project root directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectRoot = Split-Path -Parent $ScriptDir

# Check for local Go installation
$LocalGoBin = Join-Path $ProjectRoot "go\bin"
if (Test-Path (Join-Path $LocalGoBin "go.exe")) {
    if ($env:PATH -notmatch [regex]::Escape($LocalGoBin)) {
        $env:PATH = "$LocalGoBin;" + $env:PATH
        Write-Host "Using local Go installation at: $LocalGoBin" -ForegroundColor Cyan
    }
}

# Execute the Go script
$env:CGO_ENABLED = "0"
$GoScript = Join-Path $ScriptDir "export_file_transfer.go"
Write-Host "Running script: $GoScript" -ForegroundColor Cyan

go run $GoScript
