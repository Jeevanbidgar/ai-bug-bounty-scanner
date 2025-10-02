# Cleanup script for removing old pipx installation
# This fixes the "stuck in creating virtual env" issue caused by multiple pipx installations

Write-Host "=== Pipx Cleanup Script ===" -ForegroundColor Cyan
Write-Host ""

$oldPipxPath = "$env:USERPROFILE\pipx"
$newPipxPath = "$env:LOCALAPPDATA\pipx"

# Check if old pipx exists
if (Test-Path $oldPipxPath) {
    Write-Host "Found old pipx installation at: $oldPipxPath" -ForegroundColor Yellow
    
    # List all tools in old venvs
    $venvsPath = Join-Path $oldPipxPath "venvs"
    if (Test-Path $venvsPath) {
        $tools = Get-ChildItem $venvsPath -Directory -ErrorAction SilentlyContinue
        
        if ($tools.Count -gt 0) {
            Write-Host "Found $($tools.Count) tools installed in old location:" -ForegroundColor Yellow
            foreach ($tool in $tools) {
                Write-Host "  - $($tool.Name)"
            }
            Write-Host ""
            
            # Uninstall each tool
            Write-Host "Uninstalling tools from old location..." -ForegroundColor Cyan
            foreach ($tool in $tools) {
                Write-Host "  Uninstalling $($tool.Name)..." -NoNewline
                try {
                    & pipx uninstall $tool.Name 2>&1 | Out-Null
                    Write-Host " OK" -ForegroundColor Green
                } catch {
                    Write-Host " SKIPPED (already removed)" -ForegroundColor Yellow
                }
            }
        } else {
            Write-Host "No tools found in old location." -ForegroundColor Green
        }
    }
    
    Write-Host ""
    Write-Host "Removing old pipx directory..." -ForegroundColor Cyan
    try {
        Remove-Item $oldPipxPath -Recurse -Force -ErrorAction Stop
        Write-Host "Successfully removed old pipx installation!" -ForegroundColor Green
    } catch {
        Write-Host "Failed to remove directory: $_" -ForegroundColor Red
        Write-Host "You may need to manually delete: $oldPipxPath" -ForegroundColor Yellow
    }
} else {
    Write-Host "No old pipx installation found at $oldPipxPath" -ForegroundColor Green
    Write-Host "Nothing to clean up!" -ForegroundColor Green
}

Write-Host ""
Write-Host "Current pipx location: $newPipxPath" -ForegroundColor Cyan

# Check if .local\bin is in PATH
$localBin = "$env:USERPROFILE\.local\bin"
$pathEnv = $env:PATH -split ';'
$inPath = $pathEnv | Where-Object { $_.Trim() -eq $localBin }

Write-Host ""
if ($inPath) {
    Write-Host ".local\bin is in PATH - Good!" -ForegroundColor Green
} else {
    Write-Host ".local\bin is NOT in PATH!" -ForegroundColor Yellow
    Write-Host "Run: pipx ensurepath" -ForegroundColor Cyan
    Write-Host "Then restart your terminal and the app." -ForegroundColor Cyan
}

Write-Host ""
Write-Host "=== Cleanup Complete ===" -ForegroundColor Green
