# Cross-Platform Implementation - Action Items

## ✅ Completed
- [x] Tauri 2.0 migration
- [x] Linux deployment working
- [x] Installation issues identified
- [x] Architecture designed

## 🎯 Current Sprint: Cross-Platform Package Manager System

### Phase 1: Core Infrastructure (2-3 days)

#### Step 1.1: Create Module Structure
- [ ] Create `src-tauri/src/tools/installation/` directory
- [ ] Create `mod.rs` with public API
- [ ] Create `strategy.rs` with `InstallationStrategy` trait
- [ ] Create `orchestrator.rs` with strategy selection logic

#### Step 1.2: Implement Strategy Trait
```rust
// File: src/tools/installation/strategy.rs
pub trait InstallationStrategy: Send + Sync {
    fn name(&self) -> &'static str;
    fn priority(&self) -> u8;
    async fn can_install(&self) -> bool;
    async fn install(&self, tool: &ToolDefinition) -> Result<InstallationResult>;
}
```

#### Step 1.3: Create Orchestrator
- [ ] Implement `InstallationOrchestrator`
- [ ] Add strategy registration
- [ ] Add fallback chain logic
- [ ] Add logging/telemetry

### Phase 2: Python Strategies (1 day)

#### Step 2.1: pipx Strategy (Linux/macOS preferred)
- [ ] Create `src/tools/installation/python/pipx_strategy.rs`
- [ ] Implement pipx detection
- [ ] Implement `pipx install git+{repo}`
- [ ] Test on Linux

#### Step 2.2: Venv Strategy (Linux/macOS fallback)
- [ ] Create `src/tools/installation/python/venv_strategy.rs`
- [ ] Implement venv creation
- [ ] Implement pip install in venv
- [ ] Create wrapper scripts in ~/.local/bin

#### Step 2.3: System Pip Strategy (Windows)
- [ ] Create `src/tools/installation/python/system_pip_strategy.rs`
- [ ] Keep existing git+pip logic
- [ ] Platform guard: Windows only

### Phase 3: npm Strategies (1 day)

#### Step 3.1: User-Level npm (All platforms preferred)
- [ ] Create `src/tools/installation/nodejs/user_npm_strategy.rs`
- [ ] Implement `npm install -g --prefix ~/.local`
- [ ] Handle Windows APPDATA path
- [ ] Test on all platforms

#### Step 3.2: Global npm (Sudo fallback)
- [ ] Create `src/tools/installation/nodejs/global_npm_strategy.rs`
- [ ] Implement sudo detection
- [ ] Show user prompt for permission
- [ ] Unix only

### Phase 4: Go Strategies (1 day)

#### Step 4.1: Go Install (Standard)
- [ ] Create `src/tools/installation/golang/go_install_strategy.rs`
- [ ] Keep existing `go install` logic
- [ ] Add error detection for replace directives

#### Step 4.2: Go Build (Source fallback)
- [ ] Create `src/tools/installation/golang/go_build_strategy.rs`
- [ ] Implement git clone + go build
- [ ] Install to $GOPATH/bin
- [ ] Handle replace directives gracefully

### Phase 5: Common Utilities (1 day)

#### Step 5.1: PATH Manager
- [ ] Create `src/tools/installation/common/path_manager.rs`
- [ ] Implement PATH detection
- [ ] Implement shell RC file updates (Linux/macOS)
- [ ] Implement Windows registry updates
- [ ] Add persistence check

#### Step 5.2: Privilege Helper
- [ ] Create `src/tools/installation/common/privilege_helper.rs`
- [ ] Implement sudo availability check
- [ ] Implement write permission check
- [ ] Add user prompt for elevation

#### Step 5.3: Installation Tracker
- [ ] Create database table for installation history
- [ ] Track strategy used per tool
- [ ] Track installation timestamps
- [ ] Add update detection

### Phase 6: Integration (1 day)

#### Step 6.1: Update Commands
- [ ] Update `install_tool` command to use orchestrator
- [ ] Add strategy selection UI
- [ ] Show installation progress per strategy
- [ ] Handle fallback notifications

#### Step 6.2: Update UI
- [ ] Add "Installation Method" badge to each tool
- [ ] Show available strategies dropdown
- [ ] Add "Prefer pipx/npm-user" settings
- [ ] Display PATH status

#### Step 6.3: Update Tool Catalog
- [ ] Add `supported_strategies` field to ToolDefinition
- [ ] Mark Python tools as pipx-compatible
- [ ] Mark npm tools as user-install-compatible
- [ ] Update tool metadata

### Phase 7: Testing (1-2 days)

#### Step 7.1: Unit Tests
- [ ] Test each strategy independently
- [ ] Mock command execution
- [ ] Verify error handling
- [ ] Test priority ordering

#### Step 7.2: Integration Tests
- [ ] Test full installation flow
- [ ] Test fallback chain
- [ ] Test PATH updates
- [ ] Test privilege escalation

#### Step 7.3: Platform Tests
- [ ] Test on Windows 10/11
- [ ] Test on Ubuntu 22.04/24.04
- [ ] Test on Kali Linux 2025
- [ ] Test on macOS (if available)

### Phase 8: Documentation & Release (1 day)

#### Step 8.1: User Documentation
- [ ] Update README with installation methods
- [ ] Add troubleshooting guide
- [ ] Create platform-specific guides
- [ ] Add FAQ

#### Step 8.2: Developer Documentation
- [ ] Document strategy pattern
- [ ] Add code comments
- [ ] Create architecture diagram
- [ ] Update API docs

#### Step 8.3: Release
- [ ] Create release notes
- [ ] Tag version (v2.1.0)
- [ ] Build binaries for all platforms
- [ ] Deploy to GitHub releases

---

## Priority Quick Fixes (Can Do Now)

### Quick Win 1: npm User-Level Install (30 minutes)
```rust
// File: src/tools/package_managers/npm_installer.rs
// Change line ~220:
.args(&["install", "-g", package_name])

// To:
let args = if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
    vec!["install", "-g", package_name, "--prefix", 
         &format!("{}/.local", env::var("HOME").unwrap())]
} else {
    vec!["install", "-g", package_name]
};
.args(&args)
```

### Quick Win 2: pipx Detection & Suggestion (20 minutes)
```rust
// File: src/tools/package_managers/git_pip_installer.rs
// At start of install() method:
#[cfg(target_os = "linux")]
{
    if Command::new("pipx").arg("--version").output().await.is_ok() {
        eprintln!("💡 Tip: pipx is installed! Consider using: pipx install git+{}", git_repo);
    }
}
```

### Quick Win 3: Go Build Fallback (1 hour)
```rust
// File: src/tools/package_managers/go_install.rs
// After go install fails, check error message:
if stderr.contains("replace directives") {
    eprintln!("⚠️  Module uses replace directives, building from source...");
    return self.install_from_source(git_repo, tool_name).await;
}
```

---

## Success Metrics

### Must Have (MVP)
- ✅ All tools install without sudo on Linux
- ✅ No PEP 668 errors for Python tools
- ✅ No permission errors for npm tools
- ✅ trufflehog installs successfully

### Nice to Have
- ✅ Automatic PATH updates
- ✅ Strategy selection in UI
- ✅ Installation history tracking
- ✅ Update detection

### Future Enhancements
- 🔄 Automatic tool updates
- 🔄 Dependency conflict resolution
- 🔄 Parallel installation
- 🔄 Rollback on failure

---

## Timeline

| Week | Phase | Deliverable |
|------|-------|-------------|
| Week 1 Day 1-2 | Phase 1 | Core infrastructure |
| Week 1 Day 3 | Phase 2 | Python strategies |
| Week 1 Day 4 | Phase 3 | npm strategies |
| Week 1 Day 5 | Phase 4 | Go strategies |
| Week 2 Day 1 | Phase 5 | Common utilities |
| Week 2 Day 2 | Phase 6 | Integration |
| Week 2 Day 3-4 | Phase 7 | Testing |
| Week 2 Day 5 | Phase 8 | Release |

**Total: 10 working days** for production-ready cross-platform system

---

## Decision Points

### Option A: Implement Full System (Recommended)
- ⏱️ Time: 10 days
- ✅ Future-proof
- ✅ Maintainable
- ✅ Extensible
- ✅ Professional quality

### Option B: Quick Fixes Only
- ⏱️ Time: 2-3 hours
- ⚠️ Band-aid solution
- ⚠️ Technical debt
- ✅ Works immediately
- ❌ Not scalable

### Option C: Hybrid Approach (Pragmatic)
- ⏱️ Time: 3-4 days
- ✅ Quick wins first
- ✅ Core system next
- ✅ Gradual migration
- ✅ Balanced approach

---

## Recommended Path

**HYBRID APPROACH:**

1. **Today**: Implement Quick Wins (3 hours)
   - npm user-level
   - pipx suggestions
   - go build fallback

2. **This Week**: Core Infrastructure (3 days)
   - Strategy pattern
   - Orchestrator
   - Basic strategies

3. **Next Week**: Polish & Test (2 days)
   - PATH management
   - UI updates
   - Platform testing

**Total: 5-6 days to production-ready system with immediate fixes**

---

**Ready to start?** Which approach do you prefer? 🚀
