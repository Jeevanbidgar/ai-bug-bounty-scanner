# 🧪 Frontend Integration - Testing Guide

> **Build Status**: ✅ Frontend Build Successful  
> **Date**: October 5, 2025  
> **Ready for Testing**: Manual verification required

---

## 📋 Build Results

### Frontend Build
```bash
✓ TypeScript compilation successful (0 errors)
✓ Vite build successful
✓ Bundle size: 799.15 KB (gzipped: 181.72 KB)
✓ CSS: 38.24 KB (gzipped: 6.82 KB)
✓ Build time: ~18 seconds
```

### Integration Status
| Component | Status | Notes |
|-----------|--------|-------|
| **TypeScript Interfaces** | ✅ | 50+ interfaces, all compiling |
| **API Methods** | ✅ | 40+ methods exposed |
| **Event Hooks** | ✅ | useSystemEvents, useWorkflowEvents |
| **PackageManagerPanel** | ✅ | Fixed imports, toast integration |
| **InstallationProgress** | ✅ | Fixed imports, replaced ScrollArea |
| **ErrorBoundary** | ✅ | Wrapping entire App |
| **Toast System** | ✅ | Using existing useToast hook |

---

## 🎯 Test Plan

### Phase 1: Application Startup ✅
**Goal**: Verify application starts without errors

**Steps**:
1. Run the built application from `src-tauri/target/release/`
2. Check console for startup errors (F12)
3. Verify app loads to Dashboard

**Expected Results**:
- ✅ App window opens
- ✅ No console errors
- ✅ Dashboard loads correctly
- ✅ Navigation menu works

---

### Phase 2: Package Manager Detection 🔍
**Goal**: Test PackageManagerPanel integration

**Location**: Tools Page → Package Managers section (top of page)

**Test 2.1: Manager Detection**
```
Steps:
1. Navigate to Tools page
2. Locate "Package Managers" card at top
3. Observe which managers are detected

Expected Results:
✅ Card displays "X of 4 package managers available"
✅ Available managers show:
   - Green badge "Available"
   - Version number
   - File path
✅ Unavailable managers show:
   - Red badge "Not Available"
   - Error message or "Not found"
   - Install button (if supported)
```

**Test 2.2: Refresh Managers**
```
Steps:
1. Click "Refresh" button in Package Managers card
2. Observe loading state
3. Wait for completion

Expected Results:
✅ Refresh button shows loading spinner
✅ Managers are re-detected
✅ Status updates reflect changes
✅ No console errors
```

**Test 2.3: Install Package Manager** (If any unavailable)
```
Steps:
1. Find unavailable manager with "Install" button
2. Click "Install" button
3. Observe toast notifications
4. Wait for completion

Expected Results:
✅ Toast appears: "Installing..."
✅ Install button disables during installation
✅ Progress feedback shown
✅ On success:
   - Toast: "Installation successful!"
   - Manager auto-refreshes
   - Status changes to "Available"
✅ On failure:
   - Toast: "Installation failed: [error]"
   - Retry option available
```

---

### Phase 3: Event System 🎧
**Goal**: Verify live event streaming

**Test 3.1: Tool Installation Events** (If tool installation available)
```
Steps:
1. Find an uninstalled tool
2. Click "Install" button
3. Observe event notifications

Expected Results:
✅ Toast: "Installing [tool]..."
✅ Progress updates in real-time
✅ Toast: "Installation complete!" OR "Installation failed"
✅ No console errors in event listeners
```

**Test 3.2: Workflow Events** (If workflows available)
```
Steps:
1. Navigate to a workflow execution
2. Start workflow
3. Observe output streaming

Expected Results:
✅ Stdout/stderr appears in real-time
✅ Step progress updates live
✅ Completion notification appears
✅ No event listener memory leaks
```

---

### Phase 4: Error Handling 🛡️
**Goal**: Test error boundary and toast system

**Test 4.1: Error Boundary**
```
Steps:
1. Simulate error (try invalid operations)
2. Observe error UI

Expected Results:
✅ Error boundary catches errors
✅ User-friendly error message appears
✅ "Try Again" button available
✅ "Reload App" button works
✅ Error logged to console (dev mode)
```

**Test 4.2: Toast Notifications**
```
Steps:
1. Trigger various operations (refresh, install, etc.)
2. Observe toast messages

Expected Results:
✅ Success toasts (green) for successful operations
✅ Error toasts (red) for failures
✅ Info toasts (blue) for notifications
✅ Warning toasts (yellow) for warnings
✅ Toasts auto-dismiss after ~3 seconds
✅ Close button works
✅ Multiple toasts stack properly
```

---

### Phase 5: API Integration 🔗
**Goal**: Verify all backend commands work

**Test 5.1: Adapter Commands**
```
Steps:
1. Navigate to Adapters page (if available)
2. Try building commands
3. Check adapter info

Expected Results:
✅ Adapters list loads
✅ Adapter details show correctly
✅ Command building works
✅ No API errors in console
```

**Test 5.2: Tool Discovery**
```
Steps:
1. Navigate to Tools page
2. Click "Refresh Status"
3. Observe tool discovery

Expected Results:
✅ Tools refresh with updated status
✅ Version numbers update
✅ Installed/not installed status accurate
✅ No timeouts or hangs
```

---

## 🐛 Common Issues & Solutions

### Issue 1: Package Managers Not Detected
**Symptoms**: All managers show "Not Available"

**Solutions**:
```bash
# Check system PATH
echo $env:PATH  # Windows PowerShell
echo $PATH      # Linux/Mac

# Verify installations
go version
pipx --version
apt --version      # Linux only
winget --version   # Windows only

# Restart application after installing managers
```

### Issue 2: Events Not Firing
**Symptoms**: No toast notifications, no live updates

**Solutions**:
```
1. Open DevTools (F12)
2. Check Console for errors
3. Look for "Event listener" messages
4. Verify Tauri backend is running
5. Check event payload in Network tab
```

### Issue 3: Toast Not Appearing
**Symptoms**: Operations complete but no notifications

**Solutions**:
```
1. Check if ToastContainer is rendered
2. Verify useToast hook is imported
3. Check console for toast errors
4. Ensure z-index isn't blocked
```

### Issue 4: Build Errors
**Symptoms**: Application won't start

**Solutions**:
```bash
# Clear build cache
cd frontend
npm run build

# Rebuild Tauri
cd ../src-tauri
cargo clean
cargo build --release

# Full rebuild
cd ..
npm run tauri build
```

---

## 📊 Test Checklist

### Startup & Navigation
- [ ] Application starts without errors
- [ ] Dashboard loads correctly
- [ ] Can navigate to all pages
- [ ] No console errors on startup

### Package Manager Panel
- [ ] Panel visible on Tools page
- [ ] Managers detected correctly
- [ ] Status badges display properly
- [ ] Refresh button works
- [ ] Install buttons appear for missing managers
- [ ] Installation process works (if tested)
- [ ] Toast notifications appear

### Event System
- [ ] Tool installation events fire
- [ ] Scan progress updates (if applicable)
- [ ] Workflow output streams (if applicable)
- [ ] No memory leaks from listeners

### Error Handling
- [ ] Error boundary catches errors
- [ ] Error UI is user-friendly
- [ ] Recovery options work
- [ ] Toasts appear for all operations
- [ ] Toasts auto-dismiss correctly

### Performance
- [ ] Page loads quickly (< 3 seconds)
- [ ] No lag during interactions
- [ ] Event updates don't cause stutters
- [ ] Bundle size acceptable (< 1 MB)

### Integration
- [ ] All API methods callable
- [ ] Backend commands respond
- [ ] Data formats match interfaces
- [ ] No type errors in console

---

## 📝 Test Results Template

```markdown
## Test Session: [Date/Time]

### Environment
- OS: [Windows/Linux/Mac]
- Build: [Debug/Release]
- Backend: [Running/Not Running]

### Test Results

#### Package Manager Detection
- Go: [✅ Detected / ❌ Not Found]
- Pipx: [✅ Detected / ❌ Not Found]
- APT: [✅ Detected / ❌ Not Found / N/A]
- WinGet: [✅ Detected / ❌ Not Found / N/A]

#### Installation Test (if performed)
- Manager: [Name]
- Result: [✅ Success / ❌ Failed]
- Duration: [X seconds]
- Errors: [None / List errors]

#### Event System
- Tool events: [✅ Working / ❌ Issues]
- Scan events: [✅ Working / ❌ Issues / N/A]
- Workflow events: [✅ Working / ❌ Issues / N/A]

#### Error Handling
- Error boundary: [✅ Working / ❌ Issues]
- Toast notifications: [✅ Working / ❌ Issues]
- Recovery options: [✅ Working / ❌ Issues]

#### Issues Found
1. [Issue description]
2. [Issue description]

#### Notes
- [Any additional observations]
```

---

## 🚀 Next Steps After Testing

### If All Tests Pass ✅
1. **Deploy to Production**
   - Build release version
   - Test on clean system
   - Create installer package

2. **User Documentation**
   - Create user guide
   - Record demo video
   - Update README

3. **Monitoring**
   - Add analytics (optional)
   - Set up error reporting
   - Monitor performance

### If Issues Found ❌
1. **Document Issues**
   - Screenshot errors
   - Copy console logs
   - Note reproduction steps

2. **Prioritize Fixes**
   - Critical: Blocks core functionality
   - Major: Impacts user experience
   - Minor: Cosmetic or edge cases

3. **Fix & Retest**
   - Make fixes
   - Rebuild application
   - Retest affected areas

---

## 📞 Support

### Console Logs
Always check browser DevTools (F12) for:
- Console errors (red messages)
- Network failures
- Event listener logs

### Backend Logs
Check Tauri backend logs:
```bash
# Windows
%APPDATA%\ai-bug-bounty-scanner\logs\

# Linux
~/.config/ai-bug-bounty-scanner/logs/

# Mac
~/Library/Application Support/ai-bug-bounty-scanner/logs/
```

### Report Issues
When reporting issues, include:
1. Steps to reproduce
2. Expected vs actual behavior
3. Console logs
4. Screenshots
5. System information

---

**Status**: ✅ **READY FOR TESTING**  
**Build**: Successful  
**Integration**: Complete  
**Next**: Manual verification and user acceptance testing
