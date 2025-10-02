# Fix pipx PATH Issue
# Run this script to automatically fix the PATH issue for pipx tools

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "       pipx PATH Fix Script" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

# Check if .local\bin exists
$localBin = "$env:USERPROFILE\.local\bin"
if (-not (Test-Path $localBin)) {
    Write-Host "`n❌ Directory does not exist: $localBin" -ForegroundColor Red
    Write-Host "   This will be created automatically when you install your first pipx tool." -ForegroundColor Yellow
    exit 1
}

Write-Host "`n✅ Found .local\bin directory: $localBin" -ForegroundColor Green

# Check if already in PATH
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentPath -like "*$localBin*") {
    Write-Host "`n✅ $localBin is already in your PATH!" -ForegroundColor Green
    Write-Host "`n⚠️  You may need to restart your terminal/app for changes to take effect." -ForegroundColor Yellow
    exit 0
}

Write-Host "`n⚠️  $localBin is NOT in your PATH" -ForegroundColor Yellow
Write-Host "`nDo you want to add it to your PATH? (Y/N)" -ForegroundColor Cyan
$response = Read-Host

if ($response -ne 'Y' -and $response -ne 'y') {
    Write-Host "`n❌ Operation cancelled." -ForegroundColor Red
    Write-Host "`nYou can run 'pipx ensurepath' manually instead." -ForegroundColor Yellow
    exit 0
}

Write-Host "`n🔧 Adding $localBin to your PATH..." -ForegroundColor Cyan

try {
    # Add to user PATH
    $newPath = "$currentPath;$localBin"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    
    # Update current session
    $env:PATH = "$env:PATH;$localBin"
    
    Write-Host "`n✅ Successfully added to PATH!" -ForegroundColor Green
    Write-Host "`n📋 Next Steps:" -ForegroundColor Cyan
    Write-Host "   1. Close this PowerShell window" -ForegroundColor White
    Write-Host "   2. Stop the app (Ctrl+C in terminal running 'npm run tauri dev')" -ForegroundColor White
    Write-Host "   3. Open a NEW PowerShell window" -ForegroundColor White
    Write-Host "   4. Start the app again: cd d:\ai-bug-bounty-scanner; npm run tauri dev" -ForegroundColor White
    Write-Host "   5. Test: fierce --help (should work now!)" -ForegroundColor White
    
} catch {
    Write-Host "`n❌ Failed to update PATH: $_" -ForegroundColor Red
    Write-Host "`nTry running: pipx ensurepath" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
