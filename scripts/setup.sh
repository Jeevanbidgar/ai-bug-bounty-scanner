#!/bin/bash

# AI Bug Bounty Scanner - Setup Script
# Automates the installation and setup of all components

set -e

echo "🚀 AI Bug Bounty Scanner - Setup Script"
echo "========================================"

# Check requirements
echo "📋 Checking requirements..."

# Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is required but not installed."
    exit 1
fi

# Rust (for Tauri)
if ! command -v rustc &> /dev/null; then
    echo "⚠️  Rust not found. Installing for Tauri desktop app..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
fi

echo "✅ Requirements check passed"

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
pip install -r requirements.txt

# Install Node dependencies
echo "📦 Installing Node dependencies..."
cd frontend
npm install
cd ..

# Build frontend
echo "🔨 Building frontend..."
cd frontend
npm run build
cd ..

# Setup database
echo "🗄️  Initializing database..."
python -c "
import asyncio
from backend.database import init_db

async def setup_db():
    await init_db()
    print('✅ Database initialized successfully')

asyncio.run(setup_db())
"

# Create default configuration
echo "⚙️  Creating default configuration..."
if [ ! -f .env ]; then
    cp .env.example .env 2>/dev/null || echo "No .env.example found, skipping..."
fi

echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Start the backend: python run.py"
echo "2. Start the frontend: cd frontend && npm run dev"
echo "3. Open http://localhost:1420"
echo "4. Try the 'Quick Scan' feature with example.com"
echo ""
echo "📚 Documentation:"
echo "• README.md - Complete project documentation"
echo "• docs/VISION.md - Project vision and roadmap"
echo "• docs/PLUGIN_GUIDE.md - How to add new tools"
