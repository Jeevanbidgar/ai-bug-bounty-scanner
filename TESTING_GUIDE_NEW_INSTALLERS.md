# Quick Testing Guide for New Installers

## 🧪 Prerequisites

Before testing, make sure:
1. The application is rebuilt: `npm run tauri dev` (or `npm run tauri build`)
2. You're on a clean system or willing to uninstall test tools afterwards

---

## 🦀 Test 1: CargoInstaller with rustscan

### Expected Behavior
- If Rust not installed → Auto-installs rustup → Installs rustscan
- If Rust installed → Directly installs rustscan
- Live compilation output visible in UI

### Steps
1. Open the application
2. Navigate to **Tools** tab
3. Search for "rustscan"
4. Click on the rustscan card to open details modal
5. Click **Install** button
6. Watch the installation progress

### Expected Output
```
🚀 Starting Cargo installation for rustscan...
[If Rust missing on Linux/macOS]
📦 Rust/Cargo not found. Installing rustup...
Downloading and installing Rust via rustup...
✅ Rust and Cargo installed successfully

📦 Installing rustscan via cargo...
    Updating crates.io index
  Downloaded rustscan v2.3.0
  Downloaded 1 crate (123.4 KB) in 0.52s
   Compiling libc v0.2.139
   Compiling cfg-if v1.0.0
   ...
   Compiling rustscan v2.3.0
    Finished release [optimized] target(s) in 2m 34s
  Installing ~/.cargo/bin/rustscan
   Installed package `rustscan v2.3.0` (executable `rustscan`)
✅ Successfully installed rustscan via cargo
📋 Version: rustscan 2.3.0
```

### Success Criteria
- ✅ Installation completes without errors
- ✅ Version is displayed
- ✅ Tool status changes to "Installed" (green checkmark)
- ✅ "Update" and "Uninstall" buttons appear

### Troubleshooting
- **On Windows**: If Rust not installed, you'll see a download link for rustup-init.exe
- **Slow compilation**: Rust compilation can take several minutes on first install
- **PATH issues**: Restart the application after Rust installation

---

## 🦀 Test 2: CargoInstaller with feroxbuster

### Steps
1. Search for "feroxbuster"
2. Click on the card → Click **Install**
3. Watch installation (should be faster than rustscan since Rust is now installed)

### Expected Output
```
🚀 Starting Cargo installation for feroxbuster...
📦 Installing feroxbuster via cargo...
    Updating crates.io index
  Downloaded feroxbuster v2.10.4
   Compiling feroxbuster v2.10.4
  Installing ~/.cargo/bin/feroxbuster
✅ Successfully installed feroxbuster via cargo
📋 Version: feroxbuster 2.10.4
```

### Success Criteria
- ✅ Faster than rustscan (Rust dependencies cached)
- ✅ No Rust installation step (already done)

---

## 💎 Test 3: GemInstaller with wpscan

### Expected Behavior
- **Linux/macOS**: Auto-installs Ruby if missing
- **Windows**: Prompts to download Ruby from rubyinstaller.org

### Steps
1. Search for "wpscan"
2. Click on the card → Click **Install**
3. Watch installation + database update

### Expected Output (Linux/macOS)
```
🚀 Starting gem installation for wpscan...
[If Ruby missing]
📦 Ruby not found. Installing Ruby...
Installing Ruby via apt...
Reading package lists...
Building dependency tree...
✅ Ruby installed successfully

💎 Installing wpscan via gem...
Fetching wpscan-3.8.25.gem
Successfully installed wpscan-3.8.25
1 gem installed
📡 Updating WPScan database...
✅ WPScan database updated
✅ Successfully installed wpscan via gem
📋 Version: wpscan 3.8.25
```

### Expected Output (Windows)
```
🚀 Starting gem installation for wpscan...
❌ Ruby is not installed.
Please install Ruby from: https://rubyinstaller.org/
After installation, restart the application and try again.
```

### Success Criteria
- ✅ Ruby detected or auto-installed (Linux/macOS)
- ✅ WPScan installed successfully
- ✅ Database updated automatically
- ✅ Clear instructions on Windows if Ruby missing

---

## 📦 Test 4: NpmInstaller with wappalyzer

### Expected Behavior
- **Linux/macOS**: Auto-installs Node.js if missing
- **Windows**: Prompts to download Node.js from nodejs.org

### Steps
1. Search for "wappalyzer"
2. Click on the card → Click **Install**
3. Watch installation

### Expected Output (Linux/macOS)
```
🚀 Starting npm installation for wappalyzer...
[If Node.js missing]
📦 Node.js/npm not found.
Installing Node.js via apt...
✅ Node.js installed successfully

📦 Installing wappalyzer via npm globally...
added 345 packages, and audited 346 packages in 12s
✅ Successfully installed wappalyzer via npm
📋 Version: 6.10.66
```

### Expected Output (Windows)
```
🚀 Starting npm installation for wappalyzer...
❌ Node.js is not installed.
Please install Node.js from: https://nodejs.org/
After installation, restart the application and try again.
```

### Success Criteria
- ✅ Node.js detected or auto-installed (Linux/macOS)
- ✅ Wappalyzer installed globally
- ✅ Clear instructions on Windows if Node.js missing

---

## 🔄 Test 5: Update Functionality

### Steps
1. Wait a few days (or artificially change version in catalog)
2. Click **Update** button on installed tool
3. Watch update process

### Expected Output (rustscan)
```
🔄 Updating rustscan...
📦 Installing rustscan via cargo...
    Updating crates.io index
  Installing ~/.cargo/bin/rustscan
   Replaced package `rustscan v2.3.0` with `rustscan v2.3.1`
✅ Successfully updated rustscan
```

### Success Criteria
- ✅ Update completes successfully
- ✅ New version displayed

---

## 🗑️ Test 6: Uninstall Functionality

### Steps
1. Click **Uninstall** button on installed tool
2. Confirm the action
3. Wait for completion

### Expected Output (rustscan)
```
🗑️ Uninstalling tool: rustscan
Removing ~/.cargo/bin/rustscan
✅ Successfully uninstalled rustscan
```

### Success Criteria
- ✅ Tool removed from system
- ✅ Status changes back to "Not Installed"
- ✅ Install button reappears

---

## 🎨 UI/UX Verification

### Badge Colors
Check that each tool displays the correct badge color:

| Tool | Method | Badge Color | Expected |
|------|--------|-------------|----------|
| rustscan | cargo | 🟠 Orange | `bg-orange-700` |
| feroxbuster | cargo | 🟠 Orange | `bg-orange-700` |
| wpscan | gem | 🔴 Red | `bg-red-700` |
| wappalyzer | npm | 🔴 Red | `bg-red-700` |

### Install Button Visibility
- ✅ Install button shows for cargo/gem/npm methods
- ✅ "One-click install available" indicator present
- ✅ Button disabled during installation
- ✅ Loading spinner visible during installation

---

## 🐛 Common Issues & Solutions

### Issue: "Rust installation verification failed"
**Solution**: Restart the application after Rust install to refresh PATH

### Issue: "Ruby must be installed manually on Windows"
**Solution**: Download from https://rubyinstaller.org/, install, restart app

### Issue: "Node.js must be installed manually on Windows"
**Solution**: Download from https://nodejs.org/, install, restart app

### Issue: Compilation takes forever (rustscan/feroxbuster)
**Solution**: Normal behavior - Rust compiles from source. First install takes 2-5 minutes

### Issue: "Permission denied" on Linux
**Solution**: Some operations need sudo. Installer handles this automatically.

---

## ✅ Final Checklist

After testing all tools:

- [ ] rustscan installs successfully
- [ ] feroxbuster installs successfully
- [ ] wpscan installs successfully (Linux/macOS) or shows clear instructions (Windows)
- [ ] wappalyzer installs successfully (Linux/macOS) or shows clear instructions (Windows)
- [ ] All badge colors display correctly
- [ ] Live output streams to frontend
- [ ] Version numbers display after installation
- [ ] Update button works
- [ ] Uninstall button works
- [ ] Tool status updates correctly (Not Installed → Installing → Installed)

---

## 📊 Performance Expectations

| Tool | Platform | Expected Time |
|------|----------|---------------|
| rustscan | First install | 2-5 minutes |
| rustscan | Subsequent | 1-3 minutes |
| feroxbuster | Any | 2-4 minutes |
| wpscan | Any | 30-60 seconds |
| wappalyzer | Any | 10-20 seconds |

**Note**: Rust tools (rustscan, feroxbuster) compile from source, so they take longer than Ruby/Node.js tools which use pre-built binaries.

---

## 🎯 Success Definition

**All tests pass if**:
- ✅ 4/4 tools install successfully (or show clear guidance on Windows)
- ✅ Live output streams work
- ✅ Version checking works
- ✅ Update/Uninstall work
- ✅ UI updates correctly
- ✅ No compilation errors
- ✅ No runtime crashes

---

*Ready to test? Start with rustscan on Linux/macOS for the best experience!*
