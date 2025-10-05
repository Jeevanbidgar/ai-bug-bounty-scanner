# Git-Pip Installer Recovery Script
# Run this to fix the rebuild loop and restart the dev server

Write-Host "`n🔧 Fixing Git-Pip Installer Rebuild Loop...`n" -ForegroundColor Cyan

# Step 1: Stop any running processes
Write-Host "1️⃣  Checking for running processes..." -ForegroundColor Yellow
$tauriProcess = Get-Process | Where-Object {$_.ProcessName -like "*ai-bug-bounty-scanner*"}
if ($tauriProcess) {
    Write-Host "   Found running process, stopping..." -ForegroundColor Yellow
    $tauriProcess | Stop-Process -Force
    Start-Sleep -Seconds 2
}

# Step 2: Delete problematic directories
Write-Host "`n2️⃣  Removing old tool installations..." -ForegroundColor Yellow

if (Test-Path "src-tauri\tools") {
    Write-Host "   Removing src-tauri\tools..." -ForegroundColor Gray
    Remove-Item -Recurse -Force "src-tauri\tools" -ErrorAction SilentlyContinue
    Write-Host "   ✅ Removed src-tauri\tools" -ForegroundColor Green
}

if (Test-Path "tools\python-tools") {
    Write-Host "   Removing tools\python-tools (will be recreated)..." -ForegroundColor Gray
    Remove-Item -Recurse -Force "tools\python-tools" -ErrorAction SilentlyContinue
    Write-Host "   ✅ Removed tools\python-tools" -ForegroundColor Green
}

# Step 3: Clean Cargo cache (optional but recommended)
Write-Host "`n3️⃣  Cleaning Cargo cache..." -ForegroundColor Yellow
Push-Location src-tauri
cargo clean 2>&1 | Out-Null
Pop-Location
Write-Host "   ✅ Cargo cache cleaned" -ForegroundColor Green

# Step 4: Summary
Write-Host "`n✅ Recovery Complete!`n" -ForegroundColor Green
Write-Host "📋 Summary:" -ForegroundColor Cyan
Write-Host "   • Removed old tool installations from src-tauri" -ForegroundColor White
Write-Host "   • Cleaned build cache" -ForegroundColor White
Write-Host "   • Ready to restart dev server" -ForegroundColor White

# Step 5: Instructions
Write-Host "`n🚀 Next Steps:" -ForegroundColor Cyan
Write-Host "   1. Run: npm run tauri dev" -ForegroundColor Yellow
Write-Host "   2. Wait for app to fully load" -ForegroundColor Yellow
Write-Host "   3. Try installing a tool (e.g., eyewitness)" -ForegroundColor Yellow
Write-Host "   4. App should remain stable now!`n" -ForegroundColor Yellow

Write-Host "📁 New tool location: workspace_root\tools\python-tools\" -ForegroundColor Cyan
Write-Host "   (outside src-tauri, won't trigger rebuilds)`n" -ForegroundColor Gray

Write-Host "💡 Tip: If you see the rebuild loop again, the old directory" -ForegroundColor Magenta
Write-Host "   may still exist. Run this script again.`n" -ForegroundColor Magenta
