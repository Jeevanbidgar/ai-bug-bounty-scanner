#!/usr/bin/env python3
"""
Preflight Checker for AI Bug Bounty Scanner
Validates all runtime dependencies before the application starts
"""

import sys
import subprocess
import platform
import shutil
from pathlib import Path
from typing import List, Tuple, Optional

# ANSI color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(text: str):
    """Print a formatted header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text:^60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}\n")

def print_success(text: str):
    """Print success message"""
    print(f"{Colors.GREEN}[OK]{Colors.END} {text}")

def print_warning(text: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}[WARN]{Colors.END} {text}")

def print_error(text: str):
    """Print error message"""
    print(f"{Colors.RED}[FAIL]{Colors.END} {text}")

def print_info(text: str):
    """Print info message"""
    print(f"{Colors.BLUE}[INFO]{Colors.END} {text}")

def check_command_version(command: str, version_arg: str = "--version") -> Optional[str]:
    """Check if a command exists and return its version"""
    try:
        result = subprocess.run(
            [command, version_arg],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip().split('\n')[0]
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return None

def parse_version(version_str: str) -> Tuple[int, int, int]:
    """Parse version string into tuple of integers"""
    import re
    match = re.search(r'(\d+)\.(\d+)\.(\d+)', version_str)
    if match:
        return tuple(map(int, match.groups()))
    return (0, 0, 0)

def check_python() -> bool:
    """Check Python version"""
    print_info("Checking Python...")
    version = sys.version.split()[0]
    major, minor = sys.version_info.major, sys.version_info.minor
    
    if major >= 3 and minor >= 11:
        print_success(f"Python {version} (>= 3.11 required)")
        return True
    else:
        print_error(f"Python {version} found, but 3.11+ required")
        print_info("Install Python 3.11+:")
        if platform.system() == "Windows":
            print("  → https://www.python.org/downloads/")
        elif platform.system() == "Darwin":
            print("  → brew install python@3.11")
        else:
            print("  → sudo apt install python3.11")
        return False

def check_node() -> bool:
    """Check Node.js version"""
    print_info("Checking Node.js...")
    version_output = check_command_version("node", "--version")
    
    if version_output:
        version = version_output.replace('v', '')
        major = int(version.split('.')[0])
        
        if major >= 18:
            print_success(f"Node.js {version} (>= 18.0 required)")
            return True
        else:
            print_error(f"Node.js {version} found, but 18.0+ required")
    else:
        print_error("Node.js not found")
    
    print_info("Install Node.js 18+ (LTS):")
    if platform.system() == "Windows":
        print("  → https://nodejs.org/")
    elif platform.system() == "Darwin":
        print("  → brew install node")
    else:
        print("  → curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -")
        print("  → sudo apt install -y nodejs")
    return False

def check_rust() -> bool:
    """Check Rust toolchain"""
    print_info("Checking Rust...")
    version_output = check_command_version("rustc", "--version")
    
    if version_output:
        print_success(f"{version_output}")
        
        # Check cargo too
        cargo_version = check_command_version("cargo", "--version")
        if cargo_version:
            print_success(f"{cargo_version}")
            return True
    else:
        print_error("Rust toolchain not found")
    
    print_info("Install Rust:")
    if platform.system() == "Windows":
        print("  → https://www.rust-lang.org/tools/install")
    else:
        print("  → curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
    return False

def check_platform_build_tools() -> bool:
    """Check platform-specific build tools"""
    system = platform.system()
    print_info(f"Checking build tools for {system}...")
    
    if system == "Windows":
        # Check for MSVC (Visual Studio Build Tools)
        vswhere_path = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe")
        if vswhere_path.exists():
            try:
                result = subprocess.run(
                    [str(vswhere_path), "-latest", "-property", "installationVersion"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    print_success(f"Visual Studio Build Tools {result.stdout.strip()[:4]}")
                    return True
            except Exception:
                pass
        
        print_warning("Visual Studio Build Tools not detected")
        print_info("Install Visual Studio Build Tools:")
        print("  → https://visualstudio.microsoft.com/downloads/")
        print("  → Download 'Build Tools for Visual Studio 2022'")
        print("  → Select 'Desktop development with C++' workload")
        return False
        
    elif system == "Darwin":
        # Check for Xcode Command Line Tools
        xcode_check = check_command_version("xcode-select", "-p")
        if xcode_check:
            print_success("Xcode Command Line Tools installed")
            return True
        
        print_error("Xcode Command Line Tools not found")
        print_info("Install Xcode CLI Tools:")
        print("  → xcode-select --install")
        return False
        
    else:  # Linux
        # Check for essential build tools
        gcc_version = check_command_version("gcc", "--version")
        if gcc_version:
            print_success(f"{gcc_version}")
        else:
            print_error("GCC not found")
            print_info("Install build essentials:")
            print("  → sudo apt install build-essential")
            return False
        
        # Check for webkit2gtk (required for Tauri on Linux)
        try:
            result = subprocess.run(
                ["pkg-config", "--exists", "webkit2gtk-4.0"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                print_success("webkit2gtk-4.0 found")
            else:
                print_warning("webkit2gtk-4.0 not found (required for Tauri)")
                print_info("Install webkit2gtk:")
                print("  → sudo apt install libwebkit2gtk-4.0-dev")
                print("  → sudo apt install libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev")
                return False
        except FileNotFoundError:
            print_warning("pkg-config not found")
            return False
        
        return True

def check_git() -> bool:
    """Check Git"""
    print_info("Checking Git...")
    version_output = check_command_version("git", "--version")
    
    if version_output:
        print_success(f"{version_output}")
        return True
    else:
        print_warning("Git not found (optional, but recommended)")
        return True  # Git is optional

def check_python_packages() -> bool:
    """Check critical Python packages"""
    print_info("Checking Python packages...")
    
    required_packages = [
        "fastapi",
        "uvicorn",
        "sqlalchemy",
        "aiosqlite",
        "pydantic",
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package)
            print_success(f"  {package} installed")
        except ImportError:
            missing.append(package)
            print_error(f"  {package} missing")
    
    if missing:
        print_info("Install missing packages:")
        print(f"  → pip install -r requirements.txt")
        return False
    
    return True

def check_node_modules() -> bool:
    """Check if Node modules are installed"""
    print_info("Checking Node modules...")
    
    frontend_node_modules = Path("frontend/node_modules")
    root_node_modules = Path("node_modules")
    
    if frontend_node_modules.exists() and root_node_modules.exists():
        print_success("Node modules installed")
        return True
    else:
        print_warning("Node modules not fully installed")
        print_info("Install Node modules:")
        if not root_node_modules.exists():
            print("  → npm install (in project root)")
        if not frontend_node_modules.exists():
            print("  → cd frontend && npm install")
        return False

def check_security_tools() -> bool:
    """Check for security tools (optional but recommended)"""
    print_info("Checking security tools (optional)...")
    
    tools = {
        "subfinder": "https://github.com/projectdiscovery/subfinder",
        "nuclei": "https://github.com/projectdiscovery/nuclei",
        "naabu": "https://github.com/projectdiscovery/naabu",
        "nmap": "https://nmap.org/download.html",
    }
    
    found = 0
    for tool, url in tools.items():
        if shutil.which(tool):
            version = check_command_version(tool, "-version") or check_command_version(tool, "--version")
            if version:
                print_success(f"  {tool}: {version.split()[0]}")
            else:
                print_success(f"  {tool} found")
            found += 1
        else:
            print_warning(f"  {tool} not found → {url}")
    
    if found == 0:
        print_info("No security tools found. The app will work, but scanning features will be limited.")
        print_info("Install tools using their official documentation.")
    
    return True  # Tools are optional

def check_database() -> bool:
    """Check if database directory is writable"""
    print_info("Checking database directory...")
    
    data_dir = Path("data")
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        test_file = data_dir / ".write_test"
        test_file.touch()
        test_file.unlink()
        print_success(f"Database directory writable: {data_dir.absolute()}")
        return True
    except Exception as e:
        print_error(f"Cannot write to database directory: {e}")
        return False

def main():
    """Run all preflight checks"""
    print_header("AI Bug Bounty Scanner - Preflight Check")
    
    print(f"{Colors.BOLD}Platform:{Colors.END} {platform.system()} {platform.release()}")
    print(f"{Colors.BOLD}Architecture:{Colors.END} {platform.machine()}\n")
    
    checks = [
        ("Python 3.11+", check_python),
        ("Node.js 18+", check_node),
        ("Rust Toolchain", check_rust),
        ("Build Tools", check_platform_build_tools),
        ("Git", check_git),
        ("Python Packages", check_python_packages),
        ("Node Modules", check_node_modules),
        ("Database Directory", check_database),
        ("Security Tools", check_security_tools),
    ]
    
    results = []
    for name, check_func in checks:
        try:
            results.append((name, check_func()))
        except Exception as e:
            print_error(f"Error checking {name}: {e}")
            results.append((name, False))
        print()
    
    # Summary
    print_header("Preflight Check Summary")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        if result:
            print_success(f"{name}")
        else:
            print_error(f"{name}")
    
    print(f"\n{Colors.BOLD}Results: {passed}/{total} checks passed{Colors.END}\n")
    
    # Critical checks (must pass)
    critical_checks = ["Python 3.11+", "Node.js 18+", "Rust Toolchain", "Database Directory"]
    critical_failed = [name for name, result in results if not result and name in critical_checks]
    
    if critical_failed:
        print_error(f"CRITICAL: {len(critical_failed)} required checks failed!")
        print_error("Fix the issues above before starting the application.\n")
        return 1
    
    if passed == total:
        print_success("All checks passed!")
        print_success("You can now run: start.bat (Windows) or ./start.sh (Linux/Mac)\n")
        return 0
    else:
        print_warning(f"{total - passed} optional checks failed.")
        print_info("The application will work, but some features may be limited.\n")
        return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Preflight check cancelled.{Colors.END}\n")
        sys.exit(130)

