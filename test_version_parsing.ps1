# Test script to verify version parsing fix
Write-Host "Testing Go version parsing fix..." -ForegroundColor Cyan

# Test 1: Check if go version -m works
Write-Host "`n=== Test 1: go version -m ffuf.exe ===" -ForegroundColor Yellow
$ffufPath = Join-Path $env:USERPROFILE "go\bin\ffuf.exe"
if (Test-Path $ffufPath) {
    $output = & go version -m $ffufPath
    Write-Host $output
    
    # Parse using the new logic (whitespace split)
    $modLine = $output | Where-Object { $_.Trim() -match "^mod\s+" }
    if ($modLine) {
        $parts = $modLine -split '\s+' | Where-Object { $_ -ne '' }
        Write-Host "`nParsed parts:" -ForegroundColor Green
        for ($i = 0; $i -lt $parts.Length; $i++) {
            Write-Host "  [$i] = $($parts[$i])"
        }
        
        if ($parts.Length -ge 3) {
            $version = $parts[2].TrimStart('v')
            Write-Host "`nExtracted version: $version" -ForegroundColor Green
        }
    }
} else {
    Write-Host "ffuf.exe not found at $ffufPath" -ForegroundColor Red
}

# Test 2: Check if go list -m -versions works
Write-Host "`n=== Test 2: go list -m -versions github.com/ffuf/ffuf/v2 ===" -ForegroundColor Yellow
$output = & go list -m -versions github.com/ffuf/ffuf/v2
Write-Host $output

$versions = $output -split '\s+' | Where-Object { $_ -ne '' }
Write-Host "`nAll versions found:" -ForegroundColor Green
$versions | ForEach-Object { Write-Host "  - $_" }

if ($versions.Length -ge 2) {
    $latest = $versions[-1].TrimStart('v')
    Write-Host "`nLatest version: $latest" -ForegroundColor Green
}

Write-Host "`n=== Test Complete ===" -ForegroundColor Cyan
