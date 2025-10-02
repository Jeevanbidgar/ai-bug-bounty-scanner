# Phase 9 Testing Guide - Pipx/Apt/WinGet Installation

## ✅ What's Been Fixed

### Critical Bug Fix - Installation Hanging
**Problem**: All pipx/apt/winget installations were hanging indefinitely ("buffering" forever)

**Root Cause**: 
```rust
// OLD CODE (DEADLOCK):
.spawn() → child.wait().await → child.stderr.take() → read_to_string() ❌ HANGS
```

**Fix Applied**:
```rust
// NEW CODE (WORKS):
.output().await → String::from_utf8_lossy(&output.stderr) ✅
```

**Files Fixed**:
- `src-tauri/src/tools/package_managers/pipx_manager.rs`
- `src-tauri/src/tools/package_managers/apt_manager.rs`
- `src-tauri/src/tools/package_managers/winget_manager.rs`

### Additional Fixes
1. **WinGet Detection** - 3-method fallback (now shows as available)
2. **Pipx Tool Discovery** - Added `%USERPROFILE%\.local\bin` to search paths
3. **TypeScript Types** - Fixed 'winget' vs 'WinGet' serialization mismatch

## 🧪 How to Test (IMPORTANT: Read This!)

### ⚠️ Critical Testing Notes

1. **Installations Take Time** - This is NORMAL behavior:
   - **pipx (git repos)**: 30-60 seconds (clones repo + installs dependencies)
   - **pipx (PyPI)**: 10-30 seconds
   - **winget**: 10-30 seconds (may show UAC prompt)

2. **"Installing..." State is Normal**:
   - OLD BUG: Hung forever, never completed
   - NEW BEHAVIOR: Shows "Installing...", completes after 30-60s ✅

3. **DO NOT INTERRUPT**:
   - Don't refresh the page
   - Don't stop the terminal
   - Don't click Cancel
   - Just wait patiently ⏱️

## Test Plan

### Test 1: Verify fierce (Already Installed)
**Expected**: fierce.exe exists in `%USERPROFILE%\.local\bin`

```powershell
# Verify fierce is installed
Get-ChildItem "$env:USERPROFILE\.local\bin\fierce.exe"
```

**In App**:
1. Open http://localhost:5173
2. Go to **Tools** tab
3. Search for "fierce"
4. Should show: **Status: Installed** ✅

**If Not Detected**:
- Click "Refresh All" button
- Check tool discovery logs in terminal

---

### Test 2: Install xsstrike via pipx
**Duration**: 30-60 seconds (git clone + dependencies)

**Steps**:
1. Go to **Tools** tab
2. Search for "xsstrike"
3. Current status should be: **Not Installed**
4. Click **"Install"** button
5. **UI shows**: "Installing..." with spinner 🔄
6. **WAIT WITHOUT INTERRUPTING** ⏱️ (30-60 seconds)
7. **Expected outcome**:
   - Success notification appears
   - Status changes to: **Installed** ✅
   - Tool appears in installed tools list

**Check Installation**:
```powershell
# Verify xsstrike is in .local\bin
Get-ChildItem "$env:USERPROFILE\.local\bin\xsstrike*"

# Test running it
xsstrike --help
```

**If Fails**:
- Check backend logs in terminal
- Look for error messages from pipx
- Verify: `pipx --version` works

---

### Test 3: Install jq via WinGet
**Duration**: 10-30 seconds (may show UAC)

**Steps**:
1. Go to **Tools** tab
2. Search for "jq"
3. Current status should be: **Not Installed**
4. Click **"Install"** button
5. **MAY SHOW**: UAC prompt - Click "Yes" to allow ✅
6. **UI shows**: "Installing..." with spinner 🔄
7. **WAIT WITHOUT INTERRUPTING** ⏱️ (10-30 seconds)
8. **Expected outcome**:
   - Success notification appears
   - Status changes to: **Installed** ✅

**Check Installation**:
```powershell
# Verify jq is installed
jq --version

# Should output something like: jq-1.7.1
```

**If UAC Prompt Appears**:
- This is NORMAL for winget installations
- Click "Yes" to allow installation
- Wait for completion

**If Fails**:
- WinGet may require running from regular terminal
- Try: Open regular PowerShell → `winget install --id jqlang.jq`
- If that works but UI doesn't, check backend logs

---

### Test 4: Update Existing Tool
**Steps**:
1. Go to **Tools** tab
2. Select an already installed tool (e.g., fierce)
3. Click **"Update"** button
4. Wait 10-30 seconds ⏱️
5. Should show: "Already up to date" or "Successfully updated"

---

### Test 5: Uninstall Tool
**Steps**:
1. Go to **Tools** tab
2. Select installed tool (e.g., xsstrike)
3. Click **"Uninstall"** button
4. Confirm the prompt
5. Wait 5-15 seconds ⏱️
6. Status should change to: **Not Installed** ✅

**Verify Removal**:
```powershell
# Check .local\bin
Get-ChildItem "$env:USERPROFILE\.local\bin\xsstrike*"
# Should show: Cannot find path (file deleted) ✅
```

---

## 🔍 Debugging

### Check Package Manager Detection
1. Go to **Settings** → **Package Manager Test**
2. Click **"Detect Package Managers"**
3. Should show:
   - ✅ **go install** - v1.24.5 (Available)
   - ✅ **pipx** - v1.8.0 (Available)
   - ❌ **APT** - Not available (Windows)
   - ✅ **WinGet** - v1.26.510 (Available)

### Check Backend Logs
Terminal running `npm run tauri dev` should show:
```
🔍 Detecting available package managers...
✅ Detection complete:
  ✓ go install - v1.24.5
  ✓ pipx - v1.8.0
  ✗ APT - APT is only available on Linux
  ✓ WinGet - v1.26.510
```

### Check Tool Discovery Paths
Backend should search these paths on Windows:
```
C:\Windows\System32
C:\Program Files\Git\cmd
%USERPROFILE%\scoop\shims
%USERPROFILE%\AppData\Local\Microsoft\WindowsApps
%USERPROFILE%\.local\bin          ← NEW: pipx tools
%USERPROFILE%\go\bin              ← NEW: go install tools
```

### Manual Package Manager Tests

**Test pipx manually**:
```powershell
# Check version
pipx --version

# Install test tool
pipx install httpie

# Verify installation
Get-ChildItem "$env:USERPROFILE\.local\bin\http.exe"

# Uninstall
pipx uninstall httpie
```

**Test WinGet manually** (from regular PowerShell):
```powershell
# Check version
winget --version

# Search for tool
winget search jq

# Install tool
winget install --id jqlang.jq --accept-package-agreements --accept-source-agreements

# Verify
jq --version
```

---

## 📊 Expected Results

### ✅ Success Criteria
- [ ] WinGet detected as available (v1.26.510)
- [ ] fierce shows as "Installed" (already in .local\bin)
- [ ] xsstrike installs successfully via pipx (30-60s)
- [ ] jq installs successfully via winget (10-30s)
- [ ] Update button works on installed tools
- [ ] Uninstall button works and removes tools
- [ ] No infinite "Installing..." hangs ✅
- [ ] All installations complete within expected time

### ❌ Known Limitations
- **WinGet from PowerShell**: May not work directly from PowerShell (use app UI)
- **UAC Prompts**: WinGet may require admin elevation
- **Git Clone Time**: xsstrike takes longer (large repo with dependencies)
- **First Install Delay**: pipx first install may take longer (venv creation)

---

## 🐛 If Problems Persist

### Installation Still Hanging
1. Check terminal for error messages
2. Verify package manager works manually:
   ```powershell
   pipx install httpie  # Should complete in 10-30s
   ```
3. If manual install hangs, problem is with pipx/system, not app

### Tool Not Detected After Install
1. Click "Refresh All" button in Tools tab
2. Check if tool is in expected path:
   ```powershell
   # For pipx tools
   Get-ChildItem "$env:USERPROFILE\.local\bin"
   
   # For go install tools
   Get-ChildItem "$env:USERPROFILE\go\bin"
   ```
3. Verify tool is in PATH:
   ```powershell
   Get-Command xsstrike
   ```

### WinGet Installation Fails
1. Open regular PowerShell (as admin)
2. Try manual install:
   ```powershell
   winget install --id jqlang.jq
   ```
3. If works manually but not in app:
   - Check backend logs for error message
   - Verify WinGet detection shows available
   - May need to run app as admin

---

## 📝 Test Results Template

```markdown
## Phase 9 Test Results

**Date**: [Date]
**Tester**: [Name]
**System**: Windows 11/10

### Package Manager Detection
- [ ] go install: Detected (version: ___)
- [ ] pipx: Detected (version: ___)
- [ ] APT: Not available (Windows)
- [ ] WinGet: Detected (version: ___)

### Installation Tests
- [ ] fierce: Already installed (verified in .local\bin)
- [ ] xsstrike (pipx): Installed successfully (time: ___s)
- [ ] jq (winget): Installed successfully (time: ___s)

### Update Tests
- [ ] Update fierce: Works (status: ___)
- [ ] Update xsstrike: Works (status: ___)

### Uninstall Tests
- [ ] Uninstall xsstrike: Removed successfully
- [ ] Uninstall jq: Removed successfully

### Issues Found
- (List any issues here)

### Overall Result
- [ ] ✅ All tests passed
- [ ] ⚠️ Partial success (list failures)
- [ ] ❌ Major issues (describe)
```

---

## 🎉 Next Steps After Testing

If all tests pass:
1. Mark Phase 9 as **COMPLETE** ✅
2. Move to **Phase 10**: Dashboard Implementation
   - Connect Quick Recon widget to workflow execution
   - Fix Tools counter (show installed/total)
   - Add real-time scan progress
   - System metrics display

If tests fail:
1. Document specific failure scenarios
2. Check backend logs for error messages
3. Test package managers manually to isolate issue
4. Review fix implementation in manager files
