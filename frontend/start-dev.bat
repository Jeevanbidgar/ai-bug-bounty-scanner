@echo off
echo.
echo ========================================
echo  AI Bug Bounty Scanner - Frontend Dev
echo ========================================
echo.

cd /d "%~dp0"

echo Checking Node.js installation...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Node.js is not installed or not in PATH
    echo Please install Node.js from https://nodejs.org
    pause
    exit /b 1
)

echo Checking npm installation...
npm --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: npm is not installed or not in PATH
    pause
    exit /b 1
)

echo.
echo Installing/updating dependencies...
npm install

if %errorlevel% neq 0 (
    echo Error: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo Starting development server with hot reload...
echo.
echo Frontend will be available at: http://localhost:3000
echo Press Ctrl+C to stop the server
echo.

npm run dev

pause
