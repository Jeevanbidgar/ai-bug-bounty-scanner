@echo off
title AI Bug Bounty Scanner - Launcher
color 0A
cls

echo.
echo  ========================================
echo     AI Bug Bounty Scanner v2.0
echo     Desktop Application
echo  ========================================
echo.

:: Kill any existing processes
echo  [1/3] Cleaning up...
taskkill /F /IM python.exe >nul 2>&1
taskkill /F /IM node.exe >nul 2>&1
timeout /t 2 /nobreak >nul

:: Start backend
echo  [2/3] Starting Backend Server...
start "AI Bug Bounty Scanner - Backend" /MIN cmd /k "cd /d %~dp0 && python run.py"
timeout /t 6 /nobreak

:: Start desktop app
echo  [3/3] Launching Desktop Application...
start "AI Bug Bounty Scanner - Desktop" /MIN cmd /k "cd /d %~dp0 && npm run dev"

echo.
echo  ========================================
echo     Application Starting!
echo  ========================================
echo.
echo  Two windows opened (minimized):
echo    1. Backend Server (Python)
echo    2. Desktop Application (Tauri)
echo.
echo  Desktop window will open in:
echo    - First time: 2-3 minutes
echo    - Next time: 5-10 seconds
echo.
echo  To stop: Double-click stop.bat
echo.
echo  ========================================
echo.
timeout /t 5
exit
