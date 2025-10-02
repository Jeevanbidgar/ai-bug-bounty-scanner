# Manual Testing Guide - Phase 8 Frontend Integration

## Overview
This guide walks you through testing the complete one-click tool installation system.

## Prerequisites

### 1. Environment Setup
- ✅ Go installed and in PATH
- ✅ GOPATH/bin in system PATH
- ✅ Node.js/npm installed
- ✅ Rust/Cargo installed
- ✅ All dependencies installed

### 2. Verify Backend Build
```powershell
cd src-tauri
cargo build
# Should compile with 0 errors
```

### 3. Verify Frontend Build
```powershell
cd frontend
npm install
npm run type-check
# Should show 0 TypeScript errors
```

---

## Testing Procedure

### Step 1: Start the Application (5 minutes)

#### Terminal 1 - Frontend Dev Server
```powershell
cd frontend
npm run dev
```
**Expected Output:**
```
VITE v5.x.x  ready in xxx ms
➜  Local:   http://localhost:5173/
➜  Network: use --host to expose
```

#### Terminal 2 - Tauri Dev Mode
```powershell
cd src-tauri
cargo tauri dev
```
**Expected Output:**
```
Compiling app v0.1.0
    Finished dev [unoptimized + debuginfo]
Running `target\debug\app.exe`
```

**✅ Success Criteria:**
- Application window opens
- No console errors
- Dashboard loads correctly

---

### Step 2: Navigate to Tools Page (2 minutes)

1. Click **"Tools"** in the sidebar navigation
2. Wait for tools page to load

**✅ Success Criteria:**
- See tool grid with 57 tools
- Tools show installation status (❌ Not Installed / ✅ Installed)
- No errors in browser console (F12)

---

### Step 3: Test Tool Detail Modal (3 minutes)

1. **Find a Go tool** - Look for these (they have one-click install):
   - subfinder
   - httpx
   - nuclei
   - ffuf
   - naabu

2. **Click on "subfinder" tool card**

**✅ Success Criteria:**
- Modal opens with tool details
- Shows tool name, description, category
- Installation Details section shows:
  - Install Method: **go** (green badge)
  - Go Module: `github.com/projectdiscovery/subfinder/v2/cmd/subfinder`
  - Indicator: "✅ One-click install available"
- Footer shows buttons:
  - If NOT installed: **Install subfinder** button (green, Download icon)
  - **Recheck Status** button
  - **Close** button

---

### Step 4: Test Installation Flow (5-10 minutes)

This is the **MAIN TEST** for Phase 8!

#### 4A. Install subfinder

1. **Click "Install subfinder"** button

**Expected Behavior:**
- Button changes to "Installing..." with spinner ⏳
- Button becomes disabled
- Progress indicator shows

2. **Wait for installation** (20-60 seconds depending on network)

**Expected Behavior:**
- Go downloads module
- Compiles binary
- Installs to GOPATH/bin

3. **Success notification appears**

**✅ Success Criteria:**
- Toast notification: "✅ subfinder installed successfully!"
- Button changes back to normal
- Tool status auto-refreshes

4. **Verify UI updates**

**✅ Success Criteria:**
- Install button DISAPPEARS
- **Update subfinder** button appears (blue, ArrowUpCircle icon)
- **Uninstall subfinder** button appears (red, Trash2 icon)
- Tool card shows: ✅ Installed
- Version number appears (e.g., "v2.6.3")

#### 4B. Verify Binary Installation

Open a **NEW PowerShell terminal**:
```powershell
# Check binary exists
where.exe subfinder
# Should show: C:\Users\<YourName>\go\bin\subfinder.exe

# Test tool runs
subfinder -version
# Should show version number

# Quick test
subfinder -d example.com -silent
# Should find subdomains
```

**✅ Success Criteria:**
- Binary found in GOPATH/bin
- Tool executes without errors
- Version command works

---

### Step 5: Test Recheck Status (2 minutes)

1. Close the modal if open
2. Click on subfinder tool card again
3. Click **"Recheck Status"** button

**Expected Behavior:**
- Button shows "Rechecking..." with spinner
- Tool detection runs
- Status updates

**✅ Success Criteria:**
- Tool still shows: ✅ Installed
- Version is displayed
- No errors

---

### Step 6: Test Update Tool (3 minutes)

1. Click **"Update subfinder"** button

**Expected Behavior:**
- Button changes to "Updating..." with spinner
- Reinstalls with `@latest` version
- May show same version if already latest

**✅ Success Criteria:**
- Success notification: "✅ subfinder updated successfully!"
- Tool status refreshes
- Still shows as ✅ Installed
- Version displayed (may be same)

---

### Step 7: Test Uninstall Tool (3 minutes)

1. Click **"Uninstall subfinder"** button

**Expected Behavior:**
- Confirmation dialog appears: "Are you sure you want to uninstall subfinder?"

2. Click **"Cancel"** first (test cancellation)

**✅ Success Criteria:**
- Nothing happens
- Tool still installed
- Modal remains open

3. Click **"Uninstall subfinder"** again
4. This time click **"Confirm"** or **"Uninstall"**

**Expected Behavior:**
- Button shows "Uninstalling..." with spinner
- Binary removed from GOPATH/bin
- Status refreshes

**✅ Success Criteria:**
- Success notification: "✅ subfinder uninstalled successfully!"
- Update/Uninstall buttons DISAPPEAR
- **Install subfinder** button REAPPEARS
- Tool card shows: ❌ Not Installed
- Version disappears

#### Verify Uninstall Worked
```powershell
where.exe subfinder
# Should show: INFO: Could not find files for the given pattern(s).

subfinder -version
# Should show: command not found
```

---

### Step 8: Test Multiple Tools (10 minutes)

Repeat Steps 4-7 with different Go tools:

1. **httpx** - HTTP toolkit
2. **nuclei** - Vulnerability scanner
3. **ffuf** - Web fuzzer
4. **naabu** - Port scanner

**✅ Success Criteria:**
- All tools install successfully
- All show correct status
- All can be updated
- All can be uninstalled
- No errors in console

---

### Step 9: Test Edge Cases (5 minutes)

#### 9A. Install Already Installed Tool

1. Install a tool (e.g., httpx)
2. Manually reinstall via command line:
   ```powershell
   go install github.com/projectdiscovery/httpx/cmd/httpx@latest
   ```
3. In UI, click on httpx
4. Should show as ✅ Installed (not Install button)

**✅ Success Criteria:**
- UI correctly detects already-installed tool
- Shows Update/Uninstall buttons

#### 9B. Test Manual-Only Tools

1. Click on a non-Go tool (e.g., sqlmap, nikto, dirb)
2. Modal opens

**✅ Success Criteria:**
- Install Method badge shows: **manual** (gray)
- Indicator: "⚠️ Manual installation required"
- NO Install/Update/Uninstall buttons shown
- Only shows manual installation commands
- Recheck Status button still works

#### 9C. Test Network Failure Simulation

1. Disconnect internet
2. Try to install a new tool
3. Should fail gracefully

**✅ Success Criteria:**
- Error notification: "❌ Failed to install..."
- Button returns to normal state
- No application crash
- Can retry after reconnecting

---

### Step 10: Test Error Handling (5 minutes)

#### 10A. Invalid Tool Name

Open browser console (F12) and run:
```javascript
// This tests the API directly
const api = window.apiService || { installTool: async (name) => {
  const { invoke } = await import('@tauri-apps/api/core');
  return invoke('install_tool', { toolName: name });
}};

api.installTool('nonexistent-tool-xyz')
  .then(r => console.log('Result:', r))
  .catch(e => console.error('Error:', e));
```

**✅ Success Criteria:**
- Error caught and logged
- Application doesn't crash
- Error message is user-friendly

---

## Test Results Checklist

### Core Functionality ✅
- [ ] Application starts without errors
- [ ] Tools page loads with 57 tools
- [ ] Tool cards display correctly
- [ ] Modal opens when clicking tool cards
- [ ] Installation info loads correctly

### Install Button ✅
- [ ] Install button appears for non-installed Go tools
- [ ] Clicking Install shows progress spinner
- [ ] Tool installs successfully (binary in GOPATH/bin)
- [ ] Success notification appears
- [ ] Tool status auto-updates to "Installed"
- [ ] Install button replaced with Update/Uninstall buttons
- [ ] Version number appears

### Update Button ✅
- [ ] Update button appears for installed tools
- [ ] Clicking Update shows progress spinner
- [ ] Tool updates successfully
- [ ] Success notification appears
- [ ] Status refreshes correctly

### Uninstall Button ✅
- [ ] Uninstall button appears for installed tools
- [ ] Clicking Uninstall shows confirmation dialog
- [ ] Cancel works (nothing happens)
- [ ] Confirm removes binary from system
- [ ] Success notification appears
- [ ] Status reverts to "Not Installed"
- [ ] Update/Uninstall buttons hidden
- [ ] Install button reappears

### UI/UX ✅
- [ ] Loading spinners work correctly
- [ ] Toast notifications appear and disappear
- [ ] Installation method badge color-coded correctly
- [ ] One-click indicator shows for supported tools
- [ ] Manual indicator shows for unsupported tools
- [ ] Buttons disabled during operations
- [ ] No UI glitches or flickering

### Error Handling ✅
- [ ] Network failures handled gracefully
- [ ] Invalid tool names handled
- [ ] Duplicate installs prevented
- [ ] Error messages user-friendly
- [ ] Application doesn't crash on errors

---

## Performance Testing

### Installation Speed
- Small tools (e.g., anew): **10-30 seconds**
- Medium tools (e.g., subfinder): **30-60 seconds**
- Large tools (e.g., amass): **1-2 minutes**

### UI Responsiveness
- Modal opens: **< 300ms**
- Button clicks: **< 100ms**
- Status refresh: **< 2 seconds**

---

## Known Issues to Watch For

### Issue 1: Go Not in PATH
**Symptom:** "go: command not found"
**Solution:** Add Go to PATH and restart app

### Issue 2: GOPATH/bin Not in PATH
**Symptom:** Tool installs but can't be found
**Solution:** Add GOPATH/bin to PATH

### Issue 3: Network Timeout
**Symptom:** Installation hangs for 2+ minutes
**Solution:** Check internet connection, retry

### Issue 4: Permission Errors (Windows)
**Symptom:** "Access denied" during install
**Solution:** Run as Administrator or check antivirus

---

## Screenshot Checklist

Take screenshots of:
1. ✅ Tools page with 57 tools
2. ✅ Modal with Install button (before install)
3. ✅ Installing progress (spinner active)
4. ✅ Success notification
5. ✅ Modal with Update/Uninstall buttons (after install)
6. ✅ Confirmation dialog for uninstall
7. ✅ Manual-only tool modal (no buttons)

---

## Test Report Template

After testing, document results:

```markdown
# Phase 8 Test Results

**Date:** October 2, 2025
**Tester:** [Your Name]
**Environment:** Windows 11, Go 1.21, Node 20.x

## Tests Executed
- ✅ Tool Installation (5 tools tested)
- ✅ Tool Updates (3 tools tested)
- ✅ Tool Uninstalls (5 tools tested)
- ✅ Edge Cases (all passing)
- ✅ Error Handling (all passing)

## Tools Tested
1. subfinder - ✅ Install/Update/Uninstall working
2. httpx - ✅ Install/Update/Uninstall working
3. nuclei - ✅ Install/Update/Uninstall working
4. ffuf - ✅ Install/Update/Uninstall working
5. naabu - ✅ Install/Update/Uninstall working

## Issues Found
- None / [List any issues]

## Performance
- Average install time: 45 seconds
- UI responsiveness: Excellent
- No crashes or errors

## Conclusion
✅ Phase 8 ready for production / ❌ Needs fixes
```

---

## Quick Test Script (5 minutes)

If you're short on time, run this minimal test:

1. **Start app** - `cargo tauri dev`
2. **Open Tools page** - Click Tools in sidebar
3. **Install subfinder** - Click subfinder → Install subfinder
4. **Verify binary** - `where.exe subfinder` in terminal
5. **Uninstall** - Click Uninstall subfinder → Confirm
6. **Verify removal** - `where.exe subfinder` (should be gone)

**✅ If these 6 steps work, Phase 8 is functional!**

---

## Next Steps After Testing

1. **If all tests pass:**
   - Document results in TEST_RESULTS.md
   - Create test report
   - Move to Phase 9 (pipx/apt/winget support)

2. **If issues found:**
   - Document bugs with screenshots
   - Create issue reports
   - Fix critical bugs before proceeding

---

## Support

If you encounter issues:
1. Check browser console (F12) for errors
2. Check Rust console output
3. Verify Go/GOPATH configuration
4. Test manual `go install` command
5. Check PHASE_8_FRONTEND_COMPLETE.md for troubleshooting

---

**Good luck with testing! 🚀**
