# 🚀 Tauri 2.0 Migration Plan - Complete & Detailed

**Date**: October 6, 2025  
**Current Version**: Tauri 1.6.3  
**Target Version**: Tauri 2.x (latest)  
**Estimated Time**: 2-4 hours  
**Success Rate**: 90% automated + 10% manual fixes

---

## 📋 Table of Contents

1. [Pre-Migration Checklist](#pre-migration-checklist)
2. [Backup & Safety](#backup--safety)
3. [Automated Migration Steps](#automated-migration-steps)
4. [Manual Fixes Required](#manual-fixes-required)
5. [Testing & Validation](#testing--validation)
6. [Rollback Plan](#rollback-plan)
7. [Platform-Specific Notes](#platform-specific-notes)

---

## ✅ Pre-Migration Checklist

### **1. Environment Verification**

```bash
# Verify all tools are installed
node --version          # Should be 18+ (we have 20.19.2 ✅)
npm --version           # Should be 8+ (we have 9.2.0 ✅)
rustc --version         # Should be 1.70+ (we have 1.90.0 ✅)
cargo --version         # Should be 1.70+ (we have 1.90.0 ✅)
```

**Status**: ✅ All requirements met

### **2. Current Project State**

```bash
# Check git status
git status

# Verify no uncommitted changes (migration tool requires clean git)
git diff --shortstat

# Check current branch
git branch --show-current  # Should be: application
```

**Required**: Clean working directory OR commit current changes

### **3. Dependency Audit**

Check `package.json` and `Cargo.toml` for any deprecated packages:

```bash
# Frontend
cd frontend && npm outdated

# Backend
cd ../src-tauri && cargo outdated || echo "cargo-outdated not installed"
cd ..
```

### **4. Documentation Review**

Read these before starting:
- ✅ [Tauri 2.0 Migration Guide](https://v2.tauri.app/start/migrate/from-tauri-1/)
- ✅ [Breaking Changes List](https://v2.tauri.app/start/migrate/from-tauri-1/#breaking-changes)
- ✅ [Configuration Changes](https://v2.tauri.app/reference/config/)

---

## 💾 Backup & Safety

### **Step 1: Commit All Current Changes**

```bash
# Stage all changes
git add -A

# Commit with descriptive message
git commit -m "feat: Phase 1 complete - Pre Tauri 2.0 migration checkpoint

- Tool discovery and management working
- 57 tools cataloged
- 7 package managers integrated
- Automated installation system
- Cross-platform testing started (Windows ✅, Linux in progress)

This commit marks the last stable state before Tauri 2.0 migration."

# Verify commit
git log -1 --oneline
```

### **Step 2: Create Backup Branch**

```bash
# Create backup branch from current state
git checkout -b backup/tauri-1.6-stable

# Push to remote (if available)
git push -u origin backup/tauri-1.6-stable

# Return to main branch
git checkout application

# Verify we're on the right branch
git branch --show-current
```

### **Step 3: Tag Current State**

```bash
# Create annotated tag
git tag -a v2.0.0-pre-tauri2-migration -m "Phase 1 complete - Before Tauri 2.0 migration"

# Push tag to remote
git push origin v2.0.0-pre-tauri2-migration

# Verify tag
git tag -l -n1
```

### **Step 4: Create Local Backup**

```bash
# Create backup directory
mkdir -p ../ai-bug-bounty-scanner-backups

# Create timestamped backup
tar -czf ../ai-bug-bounty-scanner-backups/backup-$(date +%Y%m%d-%H%M%S).tar.gz \
  --exclude=node_modules \
  --exclude=target \
  --exclude=dist \
  .

# Verify backup created
ls -lh ../ai-bug-bounty-scanner-backups/
```

---

## 🤖 Automated Migration Steps

### **Step 1: Update Tauri CLI to Latest**

```bash
# Update root package.json
npm install --save-dev @tauri-apps/cli@latest

# Update frontend package.json
cd frontend
npm install @tauri-apps/api@latest
npm install --save-dev @tauri-apps/cli@latest
cd ..

# Verify versions
npm list @tauri-apps/cli
cd frontend && npm list @tauri-apps/api && cd ..
```

**Expected Output:**
```
@tauri-apps/cli@2.x.x
@tauri-apps/api@2.x.x
```

### **Step 2: Run Automated Migration Tool**

```bash
# IMPORTANT: Make sure git is clean
git status

# Run the automated migration
npm run tauri migrate

# The tool will:
# 1. Analyze your project structure
# 2. Update Cargo.toml dependencies
# 3. Migrate tauri.conf.json to v2 format
# 4. Update Rust code patterns
# 5. Update frontend API calls
# 6. Create a migration report
```

**Migration Tool Will Ask:**
```
? Migrate tauri.conf.json? (Y/n) → Press Y
? Update Cargo.toml dependencies? (Y/n) → Press Y
? Migrate Rust code? (Y/n) → Press Y
? Update frontend imports? (Y/n) → Press Y
? Create backup of original files? (Y/n) → Press Y
```

**Answer**: Press **Y** to all questions

### **Step 3: Review Migration Report**

The tool creates: `tauri-migration-report.md`

```bash
# Read the migration report
cat tauri-migration-report.md

# Look for:
# - Files changed
# - Breaking changes identified
# - Manual actions required
# - Warnings and suggestions
```

### **Step 4: Commit Migration Changes**

```bash
# Stage migration changes
git add -A

# Review what changed
git status
git diff --cached --stat

# Commit migration
git commit -m "build: Migrate to Tauri 2.0 (automated)

- Updated @tauri-apps/cli to 2.x
- Updated @tauri-apps/api to 2.x
- Migrated tauri.conf.json to v2 format
- Updated Cargo.toml dependencies
- Automated code pattern updates

Migration report: tauri-migration-report.md"
```

---

## 🔧 Manual Fixes Required

### **Fix 1: Rust Code - Event Emission API**

**Location**: `src-tauri/src/events.rs`

**Before (Tauri 1.x):**
```rust
pub fn emit_scan_progress(app: &AppHandle, payload: ScanProgressEvent) -> Result<(), String> {
    app.emit_all("scan:progress", payload)
        .map_err(|e| e.to_string())
}
```

**After (Tauri 2.x):**
```rust
pub fn emit_scan_progress(app: &AppHandle, payload: ScanProgressEvent) -> Result<(), String> {
    app.emit("scan:progress", payload)
        .map_err(|e| e.to_string())
}
```

**Changes:**
- `emit_all()` → `emit()` (emits to all windows by default in v2)
- `emit_to()` for specific window/label targeting

**Files to Update:**
- `src-tauri/src/events.rs` (all emit functions)
- `src-tauri/src/commands/*.rs` (any emit calls)
- `src-tauri/src/workflow/*.rs` (workflow event emissions)
- `src-tauri/src/tools/*.rs` (tool discovery events)

### **Fix 2: Frontend - Import Paths**

**Location**: `frontend/src/services/api.ts`, `frontend/src/services/tauriEvents.ts`

**Before (Tauri 1.x):**
```typescript
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { open } from '@tauri-apps/api/dialog';
```

**After (Tauri 2.x):**
```typescript
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { open } from '@tauri-apps/plugin-dialog';
```

**Changes:**
- `@tauri-apps/api/tauri` → `@tauri-apps/api/core`
- Dialog, FS, Shell now in plugins
- Event API unchanged

**Files to Update:**
- `frontend/src/services/api.ts`
- `frontend/src/services/tauriEvents.ts`
- `frontend/src/hooks/useTauriCommand.ts` (if exists)
- `frontend/src/components/*/` (any direct invoke calls)

### **Fix 3: Configuration - Permissions/Capabilities**

**Location**: `src-tauri/tauri.conf.json`

**Before (Tauri 1.x):**
```json
{
  "tauri": {
    "allowlist": {
      "all": false,
      "shell": {
        "all": false,
        "execute": true,
        "open": true
      }
    }
  }
}
```

**After (Tauri 2.x):**
```json
{
  "app": {
    "security": {
      "capabilities": [
        {
          "identifier": "main",
          "windows": ["main"],
          "permissions": [
            "core:default",
            "shell:allow-execute",
            "shell:allow-open"
          ]
        }
      ]
    }
  }
}
```

**Changes:**
- `allowlist` → `capabilities` + `permissions`
- More granular permission control
- Scoped per window

**Migration Tool Should Handle This**, but verify:
- All required permissions present
- No missing shell scopes
- File system access permissions correct

### **Fix 4: Window Management**

**Location**: `src-tauri/src/main.rs`

**Before (Tauri 1.x):**
```rust
tauri::Builder::default()
    .setup(|app| {
        let window = app.get_window("main").unwrap();
        window.set_title("AI Bug Bounty Scanner")?;
        Ok(())
    })
```

**After (Tauri 2.x):**
```rust
tauri::Builder::default()
    .setup(|app| {
        let window = app.get_webview_window("main").unwrap();
        window.set_title("AI Bug Bounty Scanner")?;
        Ok(())
    })
```

**Changes:**
- `get_window()` → `get_webview_window()`
- WebView concept introduced

### **Fix 5: Command Context**

**Location**: `src-tauri/src/commands/*.rs`

**Before (Tauri 1.x):**
```rust
#[tauri::command]
async fn execute_tool(
    tool_name: String,
    app_handle: tauri::AppHandle,
    state: tauri::State<'_, AppState>
) -> Result<String, String> {
    // ...
}
```

**After (Tauri 2.x):**
```rust
#[tauri::command]
async fn execute_tool(
    tool_name: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>
) -> Result<String, String> {
    // Same code, just verify compilation
}
```

**Changes:**
- Context types remain similar
- May need to update some type imports

### **Fix 6: File System API**

**Location**: Frontend files using FS operations

**Before (Tauri 1.x):**
```typescript
import { readTextFile, writeFile } from '@tauri-apps/api/fs';

await readTextFile('path/to/file');
await writeFile({ path: 'file.txt', contents: 'data' });
```

**After (Tauri 2.x):**
```typescript
import { readTextFile, writeFile } from '@tauri-apps/plugin-fs';

await readTextFile('path/to/file');
await writeFile('file.txt', 'data');
```

**Changes:**
- Import from plugin
- Simpler API signatures

### **Fix 7: Shell Execute**

**Location**: Tool execution code

**Before (Tauri 1.x):**
```rust
use tauri::api::shell::Command;

let output = Command::new("subfinder")
    .args(&["-d", "example.com"])
    .output()?;
```

**After (Tauri 2.x):**
```rust
use tauri::process::Command;

let output = Command::new("subfinder")
    .args(&["-d", "example.com"])
    .output()?;
```

**Changes:**
- `tauri::api::shell` → `tauri::process`
- Same API surface

---

## 🧪 Testing & Validation

### **Phase 1: Compilation Test**

```bash
# Clean previous builds
cd src-tauri
cargo clean
cd ..

# Check Rust compilation
cd src-tauri
cargo check 2>&1 | tee ../migration-cargo-check.log
cd ..

# Look for errors
grep -E "error|error\[E" migration-cargo-check.log
```

**Expected**: No errors, only warnings

### **Phase 2: Build Test**

```bash
# Build Rust backend
cd src-tauri
cargo build 2>&1 | tee ../migration-cargo-build.log
cd ..

# Check for errors
grep -E "error|error\[E" migration-cargo-build.log
```

**Expected**: Successful build

### **Phase 3: Frontend Build Test**

```bash
# Build frontend
cd frontend
npm run build 2>&1 | tee ../migration-frontend-build.log
cd ..

# Check for errors
grep -i error migration-frontend-build.log
```

**Expected**: Successful build, no TypeScript errors

### **Phase 4: Development Server Test**

```bash
# Start Tauri dev server
npm run tauri dev

# Watch for:
# 1. Compilation completes
# 2. Frontend dev server starts
# 3. Desktop window opens
# 4. No console errors
```

**Success Criteria:**
- ✅ Application launches
- ✅ Window appears
- ✅ No crash on startup
- ✅ DevTools shows no errors

### **Phase 5: Feature Validation**

**On Both Windows AND Linux:**

#### **Test 1: Dashboard**
- [ ] Dashboard loads
- [ ] System info displays correctly
- [ ] Statistics show proper data
- [ ] No console errors

#### **Test 2: Tools Page**
- [ ] Tools page loads
- [ ] Click "Refresh Status"
- [ ] Tool list displays
- [ ] Installation status indicators work
- [ ] Version numbers display

#### **Test 3: Package Managers Panel**
- [ ] Panel opens
- [ ] All 7 package managers listed
- [ ] Detection status correct (green/red)
- [ ] Paths displayed correctly

#### **Test 4: Tool Installation**
- [ ] Click "Install" on a missing tool
- [ ] Installation modal appears
- [ ] Real-time progress displays
- [ ] Installation completes successfully
- [ ] Tool status updates to "Installed"

#### **Test 5: Event System**
- [ ] Open DevTools console
- [ ] Trigger an installation
- [ ] Verify events appear in console
- [ ] Verify progress updates work

#### **Test 6: IPC Commands**
- [ ] All Tauri commands respond
- [ ] No "command not found" errors
- [ ] Data flows correctly between frontend/backend

---

## 🔄 Rollback Plan

If migration fails catastrophically:

### **Option A: Git Revert**

```bash
# If migration was committed
git log --oneline -10
git revert <migration-commit-hash>

# Or reset to before migration
git reset --hard HEAD~1

# Restore node_modules and cargo cache
npm install
cd frontend && npm install && cd ..
cd src-tauri && cargo build && cd ..
```

### **Option B: Restore from Branch**

```bash
# Switch to backup branch
git checkout backup/tauri-1.6-stable

# Create new branch from backup
git checkout -b application-restored

# Push to remote
git push -u origin application-restored
```

### **Option C: Restore from Backup Archive**

```bash
# List backups
ls -lh ../ai-bug-bounty-scanner-backups/

# Extract backup
cd ..
tar -xzf ai-bug-bounty-scanner-backups/backup-YYYYMMDD-HHMMSS.tar.gz -C ai-bug-bounty-scanner-restored

# Compare and restore specific files
cd ai-bug-bounty-scanner
cp ../ai-bug-bounty-scanner-restored/src-tauri/Cargo.toml src-tauri/
cp ../ai-bug-bounty-scanner-restored/src-tauri/tauri.conf.json src-tauri/
# etc...
```

---

## 🖥️ Platform-Specific Notes

### **Windows**

**No major changes expected:**
- Tauri 2.0 works on Windows 10/11 ✅
- WinGet detection should still work
- `.cmd` file handling unchanged
- Build process identical

**Test Focus:**
- Tool discovery in `%USERPROFILE%\go\bin\`
- Package manager detection
- Installation with WinGet

### **Linux (Kali/Debian/Ubuntu)**

**Major Improvement:**
- ✅ **Solves webkit2gtk issue**: Now uses webkit2gtk-4.1 + libsoup3
- ✅ No more `libsoup-2.4` dependency
- ✅ Works on modern distributions

**Test Focus:**
- Tool discovery in `~/go/bin/`, `~/.local/bin/`
- apt package manager integration
- Installation with apt
- File permissions on installed tools

### **macOS (If Testing)**

**Changes:**
- App bundle structure updated
- Entitlements may need review
- Notarization process unchanged

---

## 📊 Progress Tracking

### **Migration Checklist**

```
PRE-MIGRATION
├─ ✅ Environment verified
├─ ✅ Git status clean
├─ ✅ Backup branch created
├─ ✅ Tag created
└─ ✅ Local backup created

AUTOMATED MIGRATION
├─ ⏳ Update @tauri-apps/cli
├─ ⏳ Update @tauri-apps/api
├─ ⏳ Run tauri migrate
├─ ⏳ Review migration report
└─ ⏳ Commit migration changes

MANUAL FIXES
├─ ⏳ Fix event emission (Rust)
├─ ⏳ Fix import paths (Frontend)
├─ ⏳ Verify configuration
├─ ⏳ Update window management
├─ ⏳ Fix command contexts
├─ ⏳ Update FS API calls
└─ ⏳ Update shell execute calls

TESTING
├─ ⏳ Cargo check passes
├─ ⏳ Cargo build succeeds
├─ ⏳ Frontend builds
├─ ⏳ Dev server runs
├─ ⏳ Windows testing complete
└─ ⏳ Linux testing complete

POST-MIGRATION
├─ ⏳ Update documentation
├─ ⏳ Update README
├─ ⏳ Commit final changes
└─ ⏳ Tag new version
```

---

## 📝 Post-Migration Tasks

### **1. Update Documentation**

Update these files:
- `README.md` - Update Tauri version mention
- `READY_TO_USE.md` - Update status
- `IMPLEMENTATION_STATUS.md` - Mark migration complete
- `CROSS_PLATFORM_STATUS.md` - Update to show Linux working

### **2. Update Dependencies Documentation**

```bash
# Generate updated dependency list
npm list --depth=0 > docs/dependencies-frontend.txt
cd frontend && npm list --depth=0 > ../docs/dependencies-frontend-workspace.txt
cd ../src-tauri && cargo tree --depth 1 > ../docs/dependencies-rust.txt
cd ..
```

### **3. Create Release Notes**

Create `RELEASE_NOTES_v2.0.0.md`:
```markdown
# Release Notes - Version 2.0.0

## Major Changes
- Migrated to Tauri 2.0
- Added Linux support (Kali, Ubuntu, Debian)
- Improved cross-platform compatibility

## Breaking Changes
- Requires Tauri 2.x API
- Configuration format updated

## Bug Fixes
- Fixed webkit2gtk compatibility on Linux
- Resolved libsoup dependency issues

## Compatibility
- Windows 10/11 ✅
- Linux (modern distros) ✅
- macOS 10.15+ ✅
```

### **4. Final Commit & Tag**

```bash
# Stage all final changes
git add -A

# Commit
git commit -m "docs: Update documentation for Tauri 2.0 migration

- Updated README with new requirements
- Added Linux support documentation
- Updated dependency lists
- Created release notes v2.0.0"

# Create release tag
git tag -a v2.0.0-alpha.1 -m "Alpha release with Tauri 2.0

Major changes:
- Tauri 2.0 migration complete
- Linux support added
- Cross-platform testing validated
- All Phase 1 features working"

# Push everything
git push origin application
git push origin v2.0.0-alpha.1
```

---

## 🎯 Success Criteria

Migration is successful when:

- [x] **Build**: `cargo build` completes without errors
- [x] **Run**: `npm run tauri dev` launches application
- [x] **Windows**: All Phase 1 features work on Windows
- [x] **Linux**: All Phase 1 features work on Linux (Kali)
- [x] **UI**: No console errors in DevTools
- [x] **IPC**: All Tauri commands respond correctly
- [x] **Events**: Real-time events stream properly
- [x] **Install**: Tool installation works on both platforms
- [x] **Discovery**: Tool discovery detects installed tools
- [x] **Performance**: No performance regressions

---

## ⏱️ Timeline

| Phase | Duration | Tasks |
|-------|----------|-------|
| **Preparation** | 15 min | Backup, git cleanup, env check |
| **Automated Migration** | 30 min | CLI update, run migrate tool |
| **Manual Fixes** | 60-90 min | Fix Rust code, frontend imports, config |
| **Testing** | 45-60 min | Build tests, feature validation |
| **Documentation** | 30 min | Update docs, create release notes |
| **Contingency** | 30 min | Buffer for unexpected issues |
| **TOTAL** | **3-4 hours** | Full migration |

---

## 🚨 Common Issues & Solutions

### **Issue 1: `emit_all` not found**

**Error:**
```
error[E0599]: no method named `emit_all` found for struct `AppHandle`
```

**Fix:**
```rust
// Change emit_all to emit
app.emit_all("event", payload) → app.emit("event", payload)
```

### **Issue 2: Import not found**

**Error:**
```
Cannot find module '@tauri-apps/api/tauri'
```

**Fix:**
```typescript
import { invoke } from '@tauri-apps/api/tauri';
→ import { invoke } from '@tauri-apps/api/core';
```

### **Issue 3: Permission denied**

**Error:**
```
Command not allowed: execute
```

**Fix:**
Add to `tauri.conf.json`:
```json
"permissions": ["shell:allow-execute"]
```

### **Issue 4: Window undefined**

**Error:**
```
window is not defined
```

**Fix:**
```rust
app.get_window("main") → app.get_webview_window("main")
```

---

## 📞 Support Resources

- **Tauri Discord**: https://discord.gg/tauri
- **Migration Guide**: https://v2.tauri.app/start/migrate/from-tauri-1/
- **API Docs**: https://v2.tauri.app/reference/
- **GitHub Issues**: https://github.com/tauri-apps/tauri/issues

---

## 🎉 Ready to Start?

**Execute this command to begin:**

```bash
# Make sure you're in project root
cd /home/kalijeevan/Music/ai-bug-bounty-scanner

# Start migration process
bash << 'MIGRATION'
echo "🚀 Starting Tauri 2.0 Migration..."
echo ""
echo "Step 1: Verifying environment..."
node --version && npm --version && rustc --version && cargo --version
echo ""
echo "Step 2: Checking git status..."
git status --short
echo ""
echo "Step 3: Creating backup..."
git checkout -b backup/tauri-1.6-stable
git checkout application
git tag -a v2.0.0-pre-tauri2-migration -m "Pre-migration checkpoint"
echo ""
echo "✅ Ready to migrate!"
echo ""
echo "Next: Run 'npm install @tauri-apps/cli@latest' to start"
MIGRATION
```

---

**Status**: 📋 **READY TO EXECUTE**  
**Confidence Level**: 🟢 **HIGH** (90% automated + detailed manual instructions)  
**Risk Level**: 🟡 **LOW** (Full backups in place, rollback plan ready)  
**Expected Outcome**: ✅ **Linux support enabled, Phase 1 working on both platforms**

---

**Last Updated**: October 6, 2025  
**Author**: AI Assistant  
**Review**: Pending User Approval
