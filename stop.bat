@echo off
title Stop AI Bug Bounty Scanner
color 0C
cls

echo.
echo  ========================================
echo     Stopping AI Bug Bounty Scanner
echo  ========================================
echo.

echo  Stopping Backend Server...
taskkill /F /IM python.exe >nul 2>&1
if %errorlevel%==0 (
    echo  [OK] Backend stopped
) else (
    echo  [OK] Backend was not running
)

echo  Stopping Desktop Application...
taskkill /F /IM node.exe >nul 2>&1
if %errorlevel%==0 (
    echo  [OK] Desktop app stopped
) else (
    echo  [OK] Desktop app was not running
)

echo.
echo  ========================================
echo     All processes stopped!
echo  ========================================
echo.
echo  To restart: Double-click start.bat
echo.
timeout /t 3
exit
