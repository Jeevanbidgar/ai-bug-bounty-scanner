# 🔧 Tauri 2.0 Manual Fixes - Quick Reference

**Use this after running the automated migration tool**

---

## 📝 Rust Code Changes

### 1. Event Emission

```rust
// OLD ❌
app.emit_all("event-name", payload)

// NEW ✅
app.emit("event-name", payload)
```

**Files to check:**
- `src-tauri/src/events.rs` (all functions)
- `src-tauri/src/commands/*.rs`
- `src-tauri/src/workflow/*.rs`
- `src-tauri/src/tools/*.rs`

---

### 2. Window Management

```rust
// OLD ❌
app.get_window("main")

// NEW ✅
app.get_webview_window("main")
```

**Files to check:**
- `src-tauri/src/main.rs`
- Any window manipulation code

---

### 3. Shell/Process API

```rust
// OLD ❌
use tauri::api::shell::Command;

// NEW ✅
use tauri::process::Command;
```

**Files to check:**
- `src-tauri/src/runtime/*.rs`
- Tool execution code

---

## 🎨 Frontend TypeScript Changes

### 1. Core API Imports

```typescript
// OLD ❌
import { invoke } from '@tauri-apps/api/tauri';

// NEW ✅
import { invoke } from '@tauri-apps/api/core';
```

**Files to check:**
- `frontend/src/services/api.ts`
- `frontend/src/services/tauriEvents.ts`
- `frontend/src/hooks/*.ts`

---

### 2. Plugin Imports

```typescript
// OLD ❌
import { readTextFile, writeFile } from '@tauri-apps/api/fs';
import { open } from '@tauri-apps/api/dialog';

// NEW ✅
import { readTextFile, writeFile } from '@tauri-apps/plugin-fs';
import { open } from '@tauri-apps/plugin-dialog';
```

**Note:** May need to install plugins:
```bash
npm install @tauri-apps/plugin-fs @tauri-apps/plugin-dialog
```

---

## ⚙️ Configuration Changes

### tauri.conf.json Structure

```json
// OLD ❌
{
  "tauri": {
    "allowlist": {
      "shell": { "execute": true }
    }
  }
}

// NEW ✅
{
  "app": {
    "security": {
      "capabilities": [{
        "identifier": "main",
        "permissions": ["shell:allow-execute"]
      }]
    }
  }
}
```

**The migration tool should handle this automatically**

---

## 🧪 Testing Commands

```bash
# 1. Check Rust compilation
cd src-tauri && cargo check

# 2. Build Rust
cd src-tauri && cargo build

# 3. Build Frontend
cd frontend && npm run build

# 4. Run dev server
npm run tauri dev

# 5. Check for errors
grep -r "emit_all" src-tauri/src/
grep -r "@tauri-apps/api/tauri" frontend/src/
```

---

## 🔍 Common Error Patterns

### Error: `no method named 'emit_all'`
**Fix:** Change `emit_all` to `emit`

### Error: `cannot find module '@tauri-apps/api/tauri'`
**Fix:** Change import to `'@tauri-apps/api/core'`

### Error: `no method named 'get_window'`
**Fix:** Change to `get_webview_window`

### Error: `permission denied: execute`
**Fix:** Add permission to capabilities in tauri.conf.json

---

## ✅ Verification Checklist

```bash
# Run this after making manual fixes:

# 1. Rust compiles
cd src-tauri && cargo check && echo "✅ Rust OK" || echo "❌ Rust FAIL"

# 2. Rust builds
cd src-tauri && cargo build && echo "✅ Build OK" || echo "❌ Build FAIL"

# 3. Frontend compiles
cd ../frontend && npm run build && echo "✅ Frontend OK" || echo "❌ Frontend FAIL"

# 4. Dev server runs
cd .. && timeout 60 npm run tauri dev && echo "✅ Dev OK" || echo "⚠️ Check manually"
```

---

## 📦 Quick Fix Script

Save as `fix-manual-issues.sh`:

```bash
#!/bin/bash

echo "Applying common Tauri 2.0 fixes..."

# Fix emit_all -> emit
find src-tauri/src -name "*.rs" -exec sed -i 's/\.emit_all(/\.emit(/g' {} \;
echo "✓ Fixed emit_all -> emit"

# Fix get_window -> get_webview_window
find src-tauri/src -name "*.rs" -exec sed -i 's/\.get_window(/\.get_webview_window(/g' {} \;
echo "✓ Fixed get_window -> get_webview_window"

# Fix tauri API imports
find frontend/src -name "*.ts" -o -name "*.tsx" -exec sed -i "s|@tauri-apps/api/tauri|@tauri-apps/api/core|g" {} \;
echo "✓ Fixed frontend imports"

echo "Manual fixes applied. Run 'cargo check' to verify."
```

---

**Last Updated:** October 6, 2025
