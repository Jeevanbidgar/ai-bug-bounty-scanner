# AI Bug Bounty Scanner - Desktop App Launcher
# This script starts the Tauri desktop application in development mode

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "AI Bug Bounty Scanner - Desktop App Launcher" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check if Rust is installed
Write-Host "[1/5] Checking Rust installation..." -ForegroundColor Yellow
if (!(Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Rust is not installed!" -ForegroundColor Red
    Write-Host "Please install Rust from: https://rustup.rs/" -ForegroundColor Yellow
    exit 1
}
Write-Host "✓ Rust is installed" -ForegroundColor Green

# Check if Node.js is installed
Write-Host "[2/5] Checking Node.js installation..." -ForegroundColor Yellow
if (!(Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Node.js is not installed!" -ForegroundColor Red
    Write-Host "Please install Node.js from: https://nodejs.org/" -ForegroundColor Yellow
    exit 1
}
Write-Host "✓ Node.js is installed" -ForegroundColor Green

# Check if Python is installed
Write-Host "[3/5] Checking Python installation..." -ForegroundColor Yellow
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Python is not installed!" -ForegroundColor Red
    Write-Host "Please install Python 3.11+ from: https://www.python.org/" -ForegroundColor Yellow
    exit 1
}
$pythonVersion = python --version 2>&1
Write-Host "✓ Python is installed: $pythonVersion" -ForegroundColor Green

# Install frontend dependencies if needed
Write-Host "[4/5] Checking frontend dependencies..." -ForegroundColor Yellow
if (!(Test-Path "frontend/node_modules")) {
    Write-Host "Installing frontend dependencies..." -ForegroundColor Yellow
    Set-Location frontend
    npm install
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install frontend dependencies!" -ForegroundColor Red
        exit 1
    }
    Set-Location ..
}
Write-Host "✓ Frontend dependencies ready" -ForegroundColor Green

# Install backend dependencies if needed
Write-Host "[5/5] Checking backend dependencies..." -ForegroundColor Yellow
python -c "import fastapi" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing backend dependencies..." -ForegroundColor Yellow
    pip install -r requirements.txt --no-build-isolation
    if ($LASTEXITCODE -ne 0) {
        Write-Host "WARNING: Some dependencies may have failed to install" -ForegroundColor Yellow
    }
}
Write-Host "✓ Backend dependencies ready" -ForegroundColor Green

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Starting Tauri Desktop App..." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "The app will:" -ForegroundColor Yellow
Write-Host "  1. Start the frontend dev server (port 3000)" -ForegroundColor Gray
Write-Host "  2. Launch the Tauri window" -ForegroundColor Gray
Write-Host "  3. Automatically start the Python backend (port 8000)" -ForegroundColor Gray
Write-Host ""
Write-Host "Press Ctrl+C to stop the application" -ForegroundColor Yellow
Write-Host ""

# Start Tauri dev mode
Set-Location src-tauri
cargo tauri dev
