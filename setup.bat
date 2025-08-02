@echo off
echo.
echo ========================================
echo  AI Bug Bounty Scanner - Setup
echo ========================================
echo.

cd /d "%~dp0"

echo Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

echo.
echo Installing Python dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Error: Failed to install Python dependencies
    pause
    exit /b 1
)

echo.
echo Installing python-dotenv for environment configuration...
pip install python-dotenv
if %errorlevel% neq 0 (
    echo Warning: Failed to install python-dotenv
)

echo.
echo Validating environment configuration...
python utils\validate_env.py

echo.
echo ========================================
echo Setup completed!
echo.
echo Next steps:
echo 1. Edit .env file and add your API keys
echo 2. Install security tools (nmap, nikto, etc.)
echo 3. Run: python utils\validate_env.py
echo 4. Start backend: python app.py
echo 5. Start frontend: cd frontend && npm run dev
echo ========================================
echo.
pause
