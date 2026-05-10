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
$GoScript = Join-Path $ScriptDir "migrate_file_transfer.go"
Write-Host "Running script: $GoScript" -ForegroundColor Cyan

go run $GoScript

# Load JSON into DuckDB using Python script
$ResultsDir = Join-Path $ProjectRoot "temp\results"
$JsonFile = Join-Path $ResultsDir "file_transfer_messages.json"
$DuckDBFile = Join-Path $ResultsDir "chatlog.duckdb"
$PythonScript = Join-Path $ScriptDir "duckdb_loader.py"

if (Test-Path $JsonFile) {
    Write-Host "Loading data into DuckDB via Python..." -ForegroundColor Cyan
    Push-Location $ScriptDir
    uv run $PythonScript $DuckDBFile $JsonFile "file_transfer_messages" --schema-cast "MsgSvrID AS MsgSvrID, CreateTime AS CreateTime, IsSender AS IsSender, Type AS type, SubType AS SubType, StrContent AS StrContent, Title AS Title, Url AS Url"
    Pop-Location
} else {
    Write-Host "JSON file not found. Migration to DuckDB skipped." -ForegroundColor Yellow
}
