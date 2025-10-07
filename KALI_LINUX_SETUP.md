# 🐧 Kali Linux Setup - Cross-Platform Testing

**Date**: October 6, 2025  
**Environment**: Kali GNU/Linux Rolling 2025.3  
**Kernel**: 6.12.38+kali-amd64  
**Purpose**: Test Phase 1 cross-platform compatibility on Linux

---

## ✅ Installation Summary

### **System Information**
- **OS**: Kali GNU/Linux Rolling 2025.3
- **Architecture**: x86_64 (amd64)
- **Node.js**: v20.19.2 ✅
- **npm**: 9.2.0 ✅
- **Rust**: 1.90.0 ✅ (newly installed)
- **Cargo**: 1.90.0 ✅ (newly installed)

---

## 📦 Installed Dependencies

### **Core Requirements** ✅
- [x] **Node.js 20.19.2** - Pre-installed
- [x] **npm 9.2.0** - Pre-installed  
- [x] **Rust 1.90.0** - Installed via rustup
- [x] **Cargo 1.90.0** - Installed with Rust

### **Tauri System Dependencies** ✅
```bash
sudo apt install -y \
  libwebkit2gtk-4.1-dev \
  libgtk-3-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  patchelf
```

**Installed Packages** (139 total):
- `libwebkit2gtk-4.1-dev` - WebKit GTK development files
- `libgtk-3-dev` - GTK 3 development files
- `libayatana-appindicator3-dev` - App indicator support
- `librsvg2-dev` - SVG rendering library
- `patchelf` - ELF binary patcher
- Plus 134 dependencies

### **Package Managers** ✅
- [x] **Go 1.24.4** - Pre-installed (for go install tools)
- [x] **Python 3.13.6** - Pre-installed
- [x] **pipx 1.7.1** - Pre-installed (for Python tools)
- [x] **gem 3.6.7** - Pre-installed (Ruby gems)
- [x] **npm 9.2.0** - Pre-installed (Node packages)
- [x] **cargo 1.90.0** - Installed (Rust packages)
- [x] **apt** - System package manager (Kali/Debian)

---

## 🛡️ Security Tools (Pre-installed on Kali)

### **Available Tools** (18/24 checked) ✅
- ✅ **subfinder** - Subdomain discovery
- ✅ **amass** - DNS enumeration
- ✅ **nmap** - Network scanner
- ✅ **nuclei** - Vulnerability scanner
- ✅ **naabu** - Port scanner
- ✅ **httpx** - HTTP toolkit
- ✅ **sqlmap** - SQL injection tool
- ✅ **nikto** - Web server scanner
- ✅ **gobuster** - Directory brute-forcer
- ✅ **ffuf** - Web fuzzer
- ✅ **masscan** - Fast port scanner
- ✅ **dnsx** - DNS toolkit
- ✅ **whatweb** - Web fingerprinting
- ✅ **wpscan** - WordPress scanner

### **Missing Tools** (Can be installed via app)
- ❌ **rustscan** - (cargo install available)
- ❌ **feroxbuster** - (cargo install available)
- ❌ **waybackurls** - (go install available)
- ❌ **gau** - (go install available)

---

## 🔧 Setup Steps Performed

### **1. Install Rust & Cargo**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
```

### **2. Install Tauri Dependencies**
```bash
sudo apt update
sudo apt install -y libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev patchelf
```

### **3. Install Node.js Dependencies**
```bash
# Root project
npm install

# Frontend
cd frontend && npm install
cd ..
```

### **4. Fix Permissions**
```bash
chmod +x node_modules/.bin/tauri
chmod +x check_system.sh
```

---

## ✅ System Verification

### **System Check Results**
```
=== Core Requirements ===
✓ node: v20.19.2
✓ npm: 9.2.0
✓ rustc: rustc 1.90.0
✓ cargo: cargo 1.90.0

=== Package Managers ===
✓ go: go1.24.4
✓ python3: Python 3.13.6
✓ pipx: 1.7.1
✓ gem: 3.6.7

=== Tauri Dependencies ===
✓ libwebkit2gtk-4.1-dev: Installed
✓ libgtk-3-dev: Installed

=== Project Structure ===
✓ package.json exists
✓ src-tauri/ exists
✓ frontend/ exists
✓ node_modules/ exists
✓ Cargo.toml exists
```

---

## 🚀 Running the Application

### **Development Mode**
```bash
source $HOME/.cargo/env
npm run tauri dev
```

This will:
1. Compile the Rust backend (first time ~5-10 minutes)
2. Start the frontend Vite dev server
3. Launch the desktop application
4. Enable hot-reload for frontend changes

### **Build for Production**
```bash
npm run tauri build
```

Binary location: `src-tauri/target/release/ai-bug-bounty-scanner`

---

## 🔍 Testing Checklist

### **Phase 1 Cross-Platform Validation**

#### **Tool Discovery System** 🧪
- [ ] Launch application
- [ ] Navigate to Tools page
- [ ] Click "Refresh Status"
- [ ] Verify 18+ tools detected automatically
- [ ] Check version numbers displayed correctly
- [ ] Verify installation status indicators

#### **Package Manager Detection** 🧪
- [ ] Open Package Managers panel
- [ ] Verify apt detected (not WinGet)
- [ ] Verify Go detected at correct path
- [ ] Verify pipx detected
- [ ] Verify npm, gem, cargo detected
- [ ] Check status indicators (green = available)

#### **Tool Installation** 🧪
- [ ] Find a missing tool (rustscan, feroxbuster, etc.)
- [ ] Click "Install" button
- [ ] Watch real-time installation progress
- [ ] Verify tool installs successfully
- [ ] Refresh and confirm tool shows as "installed"
- [ ] Test with different package managers

#### **Cross-Platform Differences** 🧪
- [ ] Verify no Windows-specific code running (.cmd/.bat files)
- [ ] Check PATH detection works on Linux
- [ ] Verify Go tools installed to `~/go/bin/`
- [ ] Verify pipx tools work correctly
- [ ] Check apt package manager integration
- [ ] Test manual installation with git clone

#### **UI/UX on Linux** 🧪
- [ ] Application launches without errors
- [ ] Native window decorations work
- [ ] Fonts render correctly
- [ ] Icons display properly
- [ ] Colors and themes look good
- [ ] Responsive layout works
- [ ] No console errors in DevTools

---

## 🐛 Known Issues

### **Locale Warning**
```
perl: warning: Setting locale failed.
perl: warning: Falling back to the standard locale ("C").
```
**Impact**: None - cosmetic warning during apt operations  
**Fix**: Not required for application functionality

### **npm Deprecation Warnings**
```
npm WARN deprecated inflight@1.0.6
npm WARN deprecated eslint@8.57.1
```
**Impact**: None - dev dependencies only  
**Fix**: Will be addressed in future dependency updates

### **npm Audit Findings**
```
2 moderate severity vulnerabilities
```
**Impact**: Dev dependencies, no runtime impact  
**Action**: Review and update in next maintenance cycle

---

## 📝 Differences from Windows

### **Package Managers**
| Windows | Linux (Kali) |
|---------|--------------|
| WinGet | apt |
| npm (via .cmd) | npm (direct) |
| gem (via .cmd) | gem (direct) |
| go install | go install |
| pipx | pipx |
| cargo | cargo |

### **Tool Locations**
| Windows | Linux |
|---------|-------|
| `%USERPROFILE%\go\bin\` | `~/go/bin/` |
| `%APPDATA%\Local\pipx\` | `~/.local/bin/` |
| `%USERPROFILE%\.cargo\bin\` | `~/.cargo/bin/` |

### **Executables**
| Windows | Linux |
|---------|-------|
| `tool.exe` | `tool` |
| `tool.cmd` | N/A |
| `tool.bat` | N/A |

---

## 🎯 Next Steps

### **Immediate** (This Session)
1. ✅ Complete system setup
2. ⏳ Run `cargo check` to verify Rust compilation
3. ⏳ Run `npm run tauri dev` to launch app
4. ⏳ Test Phase 1 functionality
5. ⏳ Document any cross-platform bugs

### **Short-term** (Next Session)
- Test tool installation for each package manager
- Verify tool discovery works for all 57 cataloged tools
- Check manual installation flow (git clone + setup)
- Test real-time installation progress streaming
- Validate PATH detection on Linux

### **Medium-term** (Phase 2)
- Begin Phase 2: Tool Execution Engine
- Implement `executor.rs` for Linux
- Test command execution with Linux paths
- Verify output streaming works on Linux
- Ensure cross-platform compatibility maintained

---

## 🔗 Resources

### **Documentation**
- [Tauri Linux Prerequisites](https://tauri.app/v1/guides/getting-started/prerequisites#linux)
- [Rust Installation](https://www.rust-lang.org/tools/install)
- [Kali Linux Tools](https://www.kali.org/tools/)

### **Project Files**
- `check_system.sh` - System verification script
- `READY_TO_USE.md` - Phase 1 status (updated needed)
- `README.md` - Project overview
- `IMPLEMENTATION_STATUS.md` - Overall progress

---

## 📊 Setup Metrics

- **Time to Setup**: ~15-20 minutes
- **Download Size**: ~95.4 MB (apt packages)
- **Disk Space Used**: ~135 MB (Tauri dependencies)
- **Compilation Time**: ~5-10 minutes (first Rust build)
- **Pre-installed Tools**: 18/24 security tools

---

## ✅ Success Criteria

**Setup is successful when:**
- [x] All core requirements installed (Node, Rust, npm, cargo)
- [x] All Tauri dependencies installed (webkit, gtk, etc.)
- [x] All npm packages installed (no errors)
- [ ] `cargo check` passes without errors ⏳
- [ ] `npm run tauri dev` launches application ⏳
- [ ] Application detects Linux environment correctly ⏳
- [ ] Tools page shows Kali-installed tools ⏳
- [ ] No Windows-specific errors in console ⏳

---

**Status**: 🟡 Setup Complete - Application Testing In Progress  
**Last Updated**: October 6, 2025  
**Platform**: Kali Linux 2025.3 (x86_64)
