#!/bin/bash

# AI Bug Bounty Scanner - Desktop App Launcher (Linux/macOS)
# This script starts the Tauri desktop application in development mode

echo "============================================================"
echo "AI Bug Bounty Scanner - Desktop App Launcher"
echo "============================================================"
echo ""

# Check if Rust is installed
echo "[1/5] Checking Rust installation..."
if ! command -v cargo &> /dev/null; then
    echo "ERROR: Rust is not installed!"
    echo "Please install Rust from: https://rustup.rs/"
    exit 1
fi
echo "✓ Rust is installed"

# Check if Node.js is installed
echo "[2/5] Checking Node.js installation..."
if ! command -v node &> /dev/null; then
    echo "ERROR: Node.js is not installed!"
    echo "Please install Node.js from: https://nodejs.org/"
    exit 1
fi
echo "✓ Node.js is installed"

# Check if Python is installed
echo "[3/5] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python is not installed!"
    echo "Please install Python 3.11+ from your package manager"
    exit 1
fi
PYTHON_VERSION=$(python3 --version)
echo "✓ Python is installed: $PYTHON_VERSION"

# Install frontend dependencies if needed
echo "[4/5] Checking frontend dependencies..."
if [ ! -d "frontend/node_modules" ]; then
    echo "Installing frontend dependencies..."
    cd frontend
    npm install
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install frontend dependencies!"
        exit 1
    fi
    cd ..
fi
echo "✓ Frontend dependencies ready"

# Install backend dependencies if needed
echo "[5/5] Checking backend dependencies..."
python3 -c "import fastapi" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing backend dependencies..."
    pip3 install -r requirements.txt --no-build-isolation
    if [ $? -ne 0 ]; then
        echo "WARNING: Some dependencies may have failed to install"
    fi
fi
echo "✓ Backend dependencies ready"

echo ""
echo "============================================================"
echo "Starting Tauri Desktop App..."
echo "============================================================"
echo ""
echo "The app will:"
echo "  1. Start the frontend dev server (port 3000)"
echo "  2. Launch the Tauri window"
echo "  3. Automatically start the Python backend (port 8000)"
echo ""
echo "Press Ctrl+C to stop the application"
echo ""

# Start Tauri dev mode
cd src-tauri
cargo tauri dev
