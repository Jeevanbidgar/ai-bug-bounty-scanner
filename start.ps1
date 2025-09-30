# AI Bug Bounty Scanner - One-Click Launcher
# PowerShell version

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   AI Bug Bounty Scanner" -ForegroundColor Green
Write-Host "   Desktop Application Launcher" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan

# Kill existing processes
Write-Host "[CLEANUP] Stopping existing processes..." -ForegroundColor Yellow
Get-Process python, node -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

# Start backend
Write-Host "[1/2] Starting Backend Server..." -ForegroundColor Yellow
$backend = Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; python run.py" -PassThru
Start-Sleep -Seconds 5

# Start desktop app
Write-Host "[2/2] Starting Desktop Application..." -ForegroundColor Yellow
$desktop = Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; npm run dev" -PassThru

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "   Startup Complete!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Two windows opened:" -ForegroundColor White
Write-Host "  1. Backend Server (Python)" -ForegroundColor Gray
Write-Host "  2. Desktop App (Tauri)`n" -ForegroundColor Gray

Write-Host "The desktop window will open in 2-3 minutes." -ForegroundColor Yellow
Write-Host "First launch compiles Rust code.`n" -ForegroundColor Gray

Write-Host "This launcher will close in 5 seconds..." -ForegroundColor DarkGray
Start-Sleep -Seconds 5
