@echo off
REM Quick Start Script for Enhanced AI Bug Bounty Scanner
echo.
echo 🚀 Starting Enhanced AI Bug Bounty Scanner...
echo ======================================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python not found! Please install Python 3.8+
    pause
    exit /b 1
)

echo ✅ Python found
echo.

REM Check if enhanced setup has been run
if not exist "enhancements\" (
    echo ⚠️  Enhanced features not detected
    echo Running setup script...
    python setup_enhanced.py
    echo.
)

REM Start the backend
echo 🔧 Starting Backend Server...
start "Backend Server" cmd /k "python backend-app.py"

REM Wait a moment for backend to start
timeout /t 3 /nobreak >nul

REM Start the frontend
echo 🌐 Starting Frontend Server...
start "Frontend Server" cmd /k "python -m http.server 3000"

REM Wait a moment for frontend to start
timeout /t 2 /nobreak >nul

REM Open browser
echo 🌍 Opening Browser...
start http://localhost:3000

echo.
echo ✅ Enhanced AI Bug Bounty Scanner Started!
echo.
echo 📋 Available Interfaces:
echo    Frontend: http://localhost:3000
echo    Backend API: http://localhost:5000
echo.
echo 💡 Enhanced Features Active:
echo    🔬 Advanced Security Testing
echo    🛡️  Triple Threat Intelligence (AbuseIPDB + Shodan + VirusTotal)
echo    🔍 SSL/TLS Analysis
echo    🚨 CVE Integration
echo    🌐 Internet Device Intelligence
echo    🦠 Malware Detection
echo    📊 Enhanced Reporting
echo.
echo Press any key to close this window...
pause >nul
