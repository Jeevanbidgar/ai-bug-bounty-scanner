# 🚀 Quick Start: Package Manager Installation

## What's New?

Your AI Bug Bounty Scanner now **automatically installs npm and gem** if they're not detected! 

## How It Works

### 🪟 Windows
When you try to install a tool that requires npm or gem:
1. App detects the package manager is missing
2. **Automatically installs via WinGet** (if available)
3. Shows live installation progress
4. Prompts you to restart the app
5. Done! ✅

### 🐧 Linux / 🍎 macOS
1. App detects the package manager is missing
2. Uses your system package manager (apt/Homebrew)
3. May ask for your password (sudo)
4. Shows live installation progress
5. Done! ✅

## What Gets Installed?

### npm (Node.js)
- **Windows**: `OpenJS.NodeJS` via WinGet
- **Linux**: `nodejs` and `npm` via apt
- **macOS**: `node` via Homebrew
- **Includes**: Latest LTS version of Node.js + npm

### gem (Ruby)
- **Windows**: `RubyInstallerTeam.Ruby.3.3` via WinGet
- **Linux**: `ruby` and `ruby-dev` via apt
- **macOS**: `ruby` via Homebrew
- **Includes**: Ruby 3.3 + DevKit for native extensions

## Example: Installing a Tool

### Before (Old Way)
```
❌ npm is not installed
Please visit https://nodejs.org/ to install Node.js
```

### After (New Way - Windows)
```
🔍 Found WinGet. Installing Node.js automatically...
📦 Package: OpenJS.NodeJS
[Installation progress...]
✅ Node.js installed successfully via WinGet
⚠️  Please restart the application
```

### After (New Way - Linux)
```
📦 Installing Node.js via apt...
[sudo] password for user: 
[Installation progress...]
✅ Node.js installed successfully
```

## Troubleshooting

### Windows: WinGet Not Available
If you see "Automatic installation not available", you have options:

**Option 1: Install WinGet** (Recommended)
```powershell
# Install from Microsoft Store
ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1
```

**Option 2: Manual Installation**
```powershell
# Using WinGet (after installing it)
winget install OpenJS.NodeJS

# Or using Chocolatey
choco install nodejs

# Or download directly
# Visit: https://nodejs.org/
```

### Linux: Permission Denied
Make sure you have sudo privileges:
```bash
sudo apt update
sudo apt install nodejs npm
```

### macOS: Homebrew Not Found
Install Homebrew first:
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Then install Node.js:
```bash
brew install node
```

## After Installation

### ⚠️ Important: Restart Required
After npm or gem is installed:
1. **Close the application completely**
2. **Reopen it**
3. The package manager will now be detected
4. You can install tools!

### Verify Installation
In your terminal:
```bash
# Check npm
npm --version

# Check gem
gem --version
```

## Common Questions

### Q: Do I need admin/sudo privileges?
- **Windows**: No! WinGet handles elevation automatically
- **Linux**: Yes, for apt package installation
- **macOS**: Depends on Homebrew setup

### Q: How long does installation take?
- **npm**: 2-5 minutes
- **gem**: 2-4 minutes
- Depends on your internet speed

### Q: Can I cancel the installation?
- Currently, no automatic cancel button
- You can close the terminal window (not recommended)
- Better to let it complete

### Q: What if installation fails?
- App shows manual installation instructions
- Follow the provided steps
- Restart the app after manual installation

### Q: Will this install the latest version?
- **Windows (WinGet)**: Yes, latest stable
- **Linux (apt)**: Distribution's stable version
- **macOS (Homebrew)**: Yes, latest stable

### Q: Can I use my existing installation?
- Yes! If npm/gem is already installed, no action taken
- App uses your existing installation
- Detection system finds it automatically

## Benefits

✅ **No manual downloads** - Everything automatic
✅ **Cross-platform** - Works on Windows, Linux, macOS
✅ **Safe & secure** - Uses official package managers
✅ **Live progress** - See what's happening
✅ **Smart fallback** - Manual options if automation fails

## Support

### Windows Users
- Ensure WinGet is installed (comes with Windows 11)
- Windows 10 users: Install App Installer from Microsoft Store

### Linux Users
- Ensure you have sudo privileges
- Update package lists: `sudo apt update`

### macOS Users
- Ensure Homebrew is installed
- Update Homebrew: `brew update`

## Technical Details

### Package Manager Detection
- Uses dynamic path detection
- Supports `.cmd` and `.bat` files on Windows
- Multi-tier fallback strategy
- No hardcoded paths

### Installation Methods
1. **Primary**: System package manager (WinGet/apt/Homebrew)
2. **Fallback**: Manual instructions with multiple options
3. **Detection**: Automatic verification after installation

### Security
- Official packages only
- Verified publishers
- Signature verification
- Trusted repositories

---

**Need Help?** Check the full documentation in [NPM_GEM_AUTOMATED_INSTALLATION.md](./NPM_GEM_AUTOMATED_INSTALLATION.md)
