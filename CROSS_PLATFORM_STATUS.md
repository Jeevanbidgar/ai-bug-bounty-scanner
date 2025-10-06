# 🐧 Cross-Platform Testing Status - Kali Linux

**Date**: October 6, 2025  
**Platform**: Kali GNU/Linux Rolling 2025.3  
**Status**: ⚠️ **BLOCKED** - Dependency Compatibility Issue

---

## 📊 Summary

**Phase 1** was developed and tested on **Windows**. Cross-platform testing on **Kali Linux** has revealed a **dependency compatibility issue** with webkit2gtk versions.

### **Status Overview**
- ✅ **Node.js Environment**: Fully working
- ✅ **Package Managers**: All 7 detected correctly  
- ✅ **Security Tools**: 18/24 pre-installed on Kali
- ⚠️ **Rust/Tauri Build**: **BLOCKED** by webkit2gtk version mismatch

---

## ❌ Current Blocker: webkit2gtk Version Incompatibility

###  **The Problem**

**Tauri 1.6** (used in this project) expects:
- `libsoup-2.4` (older version)
- `webkit2gtk-4.0` (older API)

**Kali Linux 2025.3** provides:
- `libsoup-3.0` (newer version, breaking changes)
- `webkit2gtk-4.1` (newer API)

**Result**: Cargo build fails with error:
```
error: failed to run custom build command for `soup2-sys v0.2.0`
The system library `libsoup-2.4` required by crate `soup2-sys` was not found.
```

### **Why This Happened**

1. **Debian/Kali moved to libsoup3**: Debian Sid and Kali Rolling have migrated to libsoup-3.0
2. **Tauri 1.x uses webkit2gtk-4.0**: Tauri 1.6 was built for the older webkit API
3. **No backwards compatibility**: The older libsoup-2.4-dev package is no longer available in Kali repos

---

## ✅ What's Working on Linux

### **System Setup** ✅
- Node.js 20.19.2
- npm 9.2.0  
- Rust 1.90.0
- Cargo 1.90.0
- All Tauri dependencies installed (except libsoup-2.4)

### **Package Managers** ✅
- Go 1.24.4
- Python 3.13.6
- pipx 1.7.1
- gem 3.6.7
- npm 9.2.0
- cargo 1.90.0
- apt (Debian package manager)

### **Security Tools** ✅ (18 pre-installed)
- subfinder v2.6.0
- amass v4.2.0
- nmap 7.95
- nuclei v3.4.10
- naabu
- httpx
- sqlmap
- nikto
- gobuster
- ffuf
- masscan
- dnsx
- whatweb
- wpscan
- And more...

---

## 🔧 Solutions (3 Options)

### **Option 1: Upgrade to Tauri 2.x** ✅ **RECOMMENDED**

**Approach**: Migrate project from Tauri 1.6 to Tauri 2.x

**Pros:**
- ✅ Tauri 2.x supports webkit2gtk-4.1 and libsoup3
- ✅ Better performance and features
- ✅ Future-proof (Tauri 1.x is aging)
- ✅ Better cross-platform support

**Cons:**
- ⚠️ Breaking API changes (requires code updates)
- ⚠️ Time investment: 2-4 hours
- ⚠️ Testing required on both Windows and Linux

**Steps:**
1. Update `Cargo.toml`: `tauri = "2.0"`
2. Update `tauri.conf.json` (v2 format)
3. Update frontend: `@tauri-apps/api` v2
4. Fix breaking API changes in Rust code
5. Test on both platforms

**Effort**: Medium (2-4 hours)

---

### **Option 2: Use Older Debian-based Distribution** ⚠️ **WORKAROUND**

**Approach**: Test on Ubuntu 22.04 LTS or Debian 11 (which still has libsoup-2.4)

**Pros:**
- ✅ No code changes required
- ✅ Quick workaround for testing

**Cons:**
- ❌ Not a real solution
- ❌ Kali users won't be able to build
- ❌ Problem will occur on newer Ubuntu/Debian too

**Not Recommended** - This just delays the problem

---

### **Option 3: Install libsoup2.4 from Source** ❌ **NOT RECOMMENDED**

**Approach**: Manually compile and install libsoup-2.4 on Kali

**Pros:**
- ✅ No code changes

**Cons:**
- ❌ Complex build process
- ❌ Potential system conflicts
- ❌ Not distributable (users can't easily replicate)
- ❌ Maintenance nightmare

**Not Recommended** - Too much hassle, not sustainable

---

## 🎯 Recommended Action Plan

### **Phase 1: Migrate to Tauri 2.x** (2-4 hours)

**Why:** This solves the issue permanently and modernizes the stack

**Tasks:**
1. ✅ **Update Cargo.toml dependencies**
   ```toml
   tauri = { version = "2.0" }
   tauri-build = { version = "2.0" }
   ```

2. ✅ **Update tauri.conf.json to v2 format**
   - Restructure configuration
   - Update capabilities/permissions
   - Update bundle settings

3. ✅ **Update frontend dependencies**
   ```bash
   cd frontend
   npm install @tauri-apps/api@^2.0.0
   npm install @tauri-apps/cli@^2.0.0
   ```

4. ✅ **Fix Rust API changes**
   - `Manager::emit` → `Manager::emit_to`
   - `Window::emit` API changes
   - Command handler updates

5. ✅ **Test on Windows**
   - Verify no regressions
   - Test all Phase 1 features

6. ✅ **Test on Linux**
   - Build successfully
   - Test all Phase 1 features

### **Phase 2: Cross-Platform Validation** (1-2 hours)

1. Document Windows-specific vs Linux-specific behaviors
2. Test tool discovery on both platforms
3. Test package manager detection
4. Verify tool installation flows
5. Document any platform-specific quirks

---

## 📝 Migration Guide: Tauri 1.6 → 2.x

### **Breaking Changes to Address**

#### **1. Configuration File**
- Rename: `tauri.conf.json` → `tauri.conf.json` (v2 format)
- Restructure allowlist → permissions/capabilities

#### **2. Rust API Changes**
```rust
// OLD (Tauri 1.x)
app.emit_all("event-name", payload)?;
window.emit("event-name", payload)?;

// NEW (Tauri 2.x)
app.emit_to("main", "event-name", payload)?;
window.emit("event-name", payload)?;
```

#### **3. Frontend API Changes**
```typescript
// OLD (Tauri 1.x)
import { invoke } from '@tauri-apps/api/tauri';

// NEW (Tauri 2.x)
import { invoke } from '@tauri-apps/api/core';
```

#### **4. Package.json Scripts**
```json
{
  "scripts": {
    "tauri": "tauri",
    "dev": "tauri dev",
    "build": "tauri build"
  }
}
```

---

## 🔍 Testing Checklist (Post-Migration)

### **Windows Testing** ✅
- [ ] Application builds successfully
- [ ] Tool discovery detects tools
- [ ] Package managers detected (WinGet, npm, gem, etc.)
- [ ] Tool installation works
- [ ] Real-time progress streaming works
- [ ] No console errors

### **Linux Testing** ✅
- [ ] Application builds successfully
- [ ] Tool discovery detects tools  
- [ ] Package managers detected (apt, npm, gem, etc.)
- [ ] Tool installation works
- [ ] Real-time progress streaming works
- [ ] No console errors

### **Cross-Platform Validation** ✅
- [ ] Same features work on both platforms
- [ ] No platform-specific bugs
- [ ] Documentation updated for both platforms

---

## 📊 Effort Estimation

| Task | Time | Priority |
|------|------|----------|
| Update Cargo.toml | 15 min | High |
| Update tauri.conf.json | 30 min | High |
| Update frontend deps | 15 min | High |
| Fix Rust API changes | 1-2 hours | High |
| Test on Windows | 30 min | High |
| Test on Linux | 30 min | High |
| Document changes | 30 min | Medium |
| **TOTAL** | **3-4 hours** | - |

---

## 🎯 Expected Outcome

**After Tauri 2.x Migration:**
- ✅ Builds on Windows (existing behavior maintained)
- ✅ Builds on Kali Linux (NEW capability)
- ✅ Builds on Ubuntu 24.04+ (NEW capability)
- ✅ Future-proof for modern Linux distros
- ✅ Better performance and features
- ✅ Maintained API compatibility for Phase 2+

---

## 📚 Resources

### **Tauri 2.x Documentation**
- [Tauri 2.0 Migration Guide](https://tauri.app/v2/guides/upgrade/v2/)
- [Tauri 2.0 API Docs](https://tauri.app/v2/reference/)
- [Configuration v2](https://tauri.app/v2/reference/config/)

### **webkit2gtk Information**
- [WebKitGTK Releases](https://webkitgtk.org/)
- [Tauri Linux Prerequisites](https://tauri.app/v2/guides/getting-started/prerequisites#linux)

---

## 💡 Key Insights

### **Why Cross-Platform Testing is Critical**

This blocker demonstrates:
1. **Dependencies evolve**: Linux distributions update libraries
2. **Test early, test often**: Waiting until Phase 7 would be catastrophic
3. **Upstream matters**: Tauri version choice affects compatibility
4. **LTS isn't enough**: Even rolling releases can break things

### **Lessons Learned**

1. ✅ **Phase 1 architecture is solid**: The problem is in the build toolchain, not our code
2. ✅ **Kali is a great test platform**: It exposes cutting-edge library issues
3. ✅ **Tauri 2.x is the path forward**: Modern stack for modern distros
4. ✅ **18 tools pre-installed**: Kali is actually an excellent platform for this app

---

## 🚀 Next Steps

### **Immediate (This Session)**
1. ⏳ Decide: Migrate to Tauri 2.x now, or test on older distro first?
2. ⏳ If migrating: Start with Cargo.toml update
3. ⏳ If testing elsewhere: Spin up Ubuntu 22.04 VM

### **Short-term (Next Session)**
- Complete Tauri 2.x migration
- Test on both Windows and Linux
- Document platform-specific behaviors
- Update README with Linux setup instructions

### **Medium-term (Phase 2)**
- Ensure tool execution works cross-platform
- Test command execution on Linux paths
- Validate package manager auto-installation

---

## 📞 Decision Required

**Question**: Do you want to:

**A)** Migrate to Tauri 2.x now (3-4 hours investment, future-proof)  
**B)** Test on Ubuntu 22.04 LTS first (quick workaround, not a real solution)  
**C)** Continue with Windows-only development for now, defer Linux support

**Recommendation**: **Option A** - Migrate to Tauri 2.x  
- Solves problem permanently
- Modernizes stack
- Only 3-4 hours of work
- Better for Phase 2+ development

---

**Status**: ⏸️ **PAUSED** - Awaiting decision on Tauri 2.x migration  
**Blocker**: libsoup-2.4 not available on Kali Linux 2025.3  
**Solution**: Upgrade to Tauri 2.x (webkit2gtk-4.1 + libsoup3 support)  
**Last Updated**: October 6, 2025
