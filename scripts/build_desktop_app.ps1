# AI Bug Bounty Scanner - Build Script
# This script builds the Tauri desktop application for distribution

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "AI Bug Bounty Scanner - Build Script" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Stop"

# Check prerequisites
Write-Host "[1/6] Checking prerequisites..." -ForegroundColor Yellow

if (!(Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Rust is not installed!" -ForegroundColor Red
    exit 1
}

if (!(Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Node.js is not installed!" -ForegroundColor Red
    exit 1
}

if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Python is not installed!" -ForegroundColor Red
    exit 1
}

Write-Host "✓ All prerequisites met" -ForegroundColor Green

# Install frontend dependencies
Write-Host "[2/6] Installing frontend dependencies..." -ForegroundColor Yellow
Set-Location frontend
npm install
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to install frontend dependencies!" -ForegroundColor Red
    exit 1
}
Set-Location ..
Write-Host "✓ Frontend dependencies installed" -ForegroundColor Green

# Build frontend
Write-Host "[3/6] Building frontend..." -ForegroundColor Yellow
Set-Location frontend
npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Frontend build failed!" -ForegroundColor Red
    exit 1
}
Set-Location ..
Write-Host "✓ Frontend built successfully" -ForegroundColor Green

# Install backend dependencies
Write-Host "[4/6] Installing backend dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt --no-build-isolation
Write-Host "✓ Backend dependencies installed" -ForegroundColor Green

# Build Tauri application
Write-Host "[5/6] Building Tauri application..." -ForegroundColor Yellow
Write-Host "This may take several minutes..." -ForegroundColor Gray
Set-Location src-tauri
cargo tauri build
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Tauri build failed!" -ForegroundColor Red
    exit 1
}
Set-Location ..
Write-Host "✓ Tauri application built successfully" -ForegroundColor Green

# Display output information
Write-Host "[6/6] Build complete!" -ForegroundColor Yellow
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Build Output Location:" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Windows Installer (.msi):" -ForegroundColor Yellow
Write-Host "  src-tauri/target/release/bundle/msi/" -ForegroundColor Gray
Write-Host ""
Write-Host "Windows Executable (.exe):" -ForegroundColor Yellow
Write-Host "  src-tauri/target/release/ai-bug-bounty-scanner.exe" -ForegroundColor Gray
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "✓ Build successful! You can now distribute the installer." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
