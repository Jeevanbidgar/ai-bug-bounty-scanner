#!/bin/bash

echo "================================"
echo "AI Bug Bounty Scanner - System Check"
echo "================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_command() {
    if command -v $1 &> /dev/null; then
        version=$($1 --version 2>&1 | head -n 1)
        echo -e "${GREEN}???${NC} $1: $version"
        return 0
    else
        echo -e "${RED}???${NC} $1: Not installed"
        return 1
    fi
}

echo "=== Core Requirements ==="
check_command node
check_command npm
check_command rustc
check_command cargo
echo ""

echo "=== Package Managers (Optional but Recommended) ==="
check_command go
check_command python3
check_command pipx
check_command gem
echo ""

echo "=== Security Tools (Will be discovered by app) ==="
check_command subfinder
check_command amass
check_command nmap
check_command nuclei
check_command naabu
check_command httpx
check_command waybackurls
echo ""

echo "=== System Info ==="
echo "OS: $(uname -s)"
echo "Architecture: $(uname -m)"
echo "Kernel: $(uname -r)"
echo ""

echo "=== Tauri Dependencies ==="
if dpkg -l | grep -q libwebkit2gtk-4.1-dev; then
    echo -e "${GREEN}???${NC} libwebkit2gtk-4.1-dev: Installed"
else
    echo -e "${RED}???${NC} libwebkit2gtk-4.1-dev: Not installed"
fi

if dpkg -l | grep -q libgtk-3-dev; then
    echo -e "${GREEN}???${NC} libgtk-3-dev: Installed"
else
    echo -e "${RED}???${NC} libgtk-3-dev: Not installed"
fi
echo ""

echo "=== Project Structure ==="
[ -f "package.json" ] && echo -e "${GREEN}???${NC} package.json exists" || echo -e "${RED}???${NC} package.json missing"
[ -d "src-tauri" ] && echo -e "${GREEN}???${NC} src-tauri/ exists" || echo -e "${RED}???${NC} src-tauri/ missing"
[ -d "frontend" ] && echo -e "${GREEN}???${NC} frontend/ exists" || echo -e "${RED}???${NC} frontend/ missing"
[ -d "node_modules" ] && echo -e "${GREEN}???${NC} node_modules/ exists" || echo -e "${YELLOW}???${NC} node_modules/ missing (run npm install)"
[ -f "src-tauri/Cargo.toml" ] && echo -e "${GREEN}???${NC} Cargo.toml exists" || echo -e "${RED}???${NC} Cargo.toml missing"
echo ""

echo "================================"
echo "System check complete!"
echo "================================"
