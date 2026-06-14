#Requires -Version 5.1
<#
  start.ps1 - GraphRaider launcher (Windows)
  * Creates backend/config.json from the example if it doesn't exist
  * Creates a Python venv if one does not exist
  * Installs Python + Node dependencies
  * Starts the FastAPI backend (port 8000) and Express frontend (port 3000)
  * Opens the browser
#>
Set-StrictMode -Off
$ErrorActionPreference = "Stop"

$scriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvDir     = Join-Path $scriptDir "venv"
$backendDir  = Join-Path $scriptDir "backend"
$frontendDir = Join-Path $scriptDir "frontend"

Write-Host ""
Write-Host "  ===================================================" -ForegroundColor Cyan
Write-Host "   GraphRaider  -  GraphQL Security Tester" -ForegroundColor White
Write-Host "  ===================================================" -ForegroundColor Cyan
Write-Host ""

# 0. Create config.json from example if missing
$configPath  = Join-Path $backendDir "config.json"
$examplePath = Join-Path $backendDir "config.example.json"
if (-not (Test-Path $configPath)) {
    Copy-Item $examplePath $configPath
    Write-Host "  [config] Created backend/config.json from example (git-ignored)." -ForegroundColor Green
} else {
    Write-Host "  [config] Using existing backend/config.json." -ForegroundColor Green
}

# 1. Python venv
if (-not (Test-Path $venvDir)) {
    Write-Host "  [venv] Creating Python virtual environment..." -ForegroundColor Yellow
    python -m venv $venvDir
    if ($LASTEXITCODE -ne 0) { Write-Error "  Failed to create venv. Install Python 3.10+."; exit 1 }
} else {
    Write-Host "  [venv] Found existing venv." -ForegroundColor Green
}

$activate = Join-Path $venvDir "Scripts\Activate.ps1"
if (($null -eq $env:VIRTUAL_ENV) -or ($env:VIRTUAL_ENV -ne $venvDir)) { & $activate }

# 2. Python deps
Write-Host "  [pip] Installing backend dependencies..." -ForegroundColor Yellow
pip install -q -r (Join-Path $backendDir "requirements.txt")
if ($LASTEXITCODE -ne 0) { Write-Error "  pip install failed."; exit 1 }
Write-Host "  [pip] Ready." -ForegroundColor Green

# 3. Node deps
if (-not (Test-Path (Join-Path $frontendDir "node_modules"))) {
    Write-Host "  [npm] Installing frontend dependencies..." -ForegroundColor Yellow
    Push-Location $frontendDir; npm install --silent; $code = $LASTEXITCODE; Pop-Location
    if ($code -ne 0) { Write-Error "  npm install failed. Install Node.js."; exit 1 }
}
Write-Host "  [npm] Ready." -ForegroundColor Green

# 4. Start backend
Write-Host "  [backend] Starting FastAPI on http://localhost:8000 ..." -ForegroundColor Yellow
$be = Start-Process powershell -ArgumentList "-NoExit","-Command","& ..\venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000" `
    -WorkingDirectory $backendDir -PassThru -WindowStyle Normal
Write-Host "  [backend] PID $($be.Id)" -ForegroundColor Green

# 5. Start frontend
Write-Host "  [frontend] Starting Express on http://localhost:3000 ..." -ForegroundColor Yellow
$fe = Start-Process powershell -ArgumentList "-NoExit","-Command","node server.js" `
    -WorkingDirectory $frontendDir -PassThru -WindowStyle Normal
Write-Host "  [frontend] PID $($fe.Id)" -ForegroundColor Green

# 6. Wait for backend + open browser
Start-Sleep -Seconds 3
for ($i = 0; $i -lt 6; $i++) {
    try { if ((Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200) { break } }
    catch { Start-Sleep -Seconds 1 }
}
Write-Host ""
Write-Host "  ---------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  UI        http://localhost:3000" -ForegroundColor Cyan
Write-Host "  Backend   http://localhost:8000" -ForegroundColor Cyan
Write-Host "  ---------------------------------------------------" -ForegroundColor DarkGray
Start-Process "http://localhost:3000"
Write-Host "  Stop with .\kill.ps1 (or close the two PowerShell windows)." -ForegroundColor DarkGray
Write-Host ""
