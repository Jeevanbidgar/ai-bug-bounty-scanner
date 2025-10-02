# Quick Start Guide - Rust Backend

## Prerequisites
- Node.js 18+ installed
- Rust toolchain installed (rustup)
- Windows 10/11 (or appropriate OS)

## Running the Application

### Option 1: Development Mode (Recommended for Testing)

1. **Start the Tauri development server:**
   ```powershell
   npm run tauri dev
   ```
   
   This will:
   - Compile the Rust backend
   - Start the frontend dev server (Vite)
   - Launch the desktop application
   - Enable hot-reload for frontend changes

### Option 2: Build Production Binary

1. **Build the production application:**
   ```powershell
   npm run tauri build
   ```

2. **Find the built application:**
   - Location: `src-tauri/target/release/ai-bug-bounty-scanner.exe`
   - Installer (if configured): `src-tauri/target/release/bundle/`

## Verifying the Setup

### Test Rust Backend
```powershell
cd src-tauri
cargo check     # Fast check for errors
cargo build     # Full build
cargo test      # Run tests (if any)
```

### Test Frontend
```powershell
cd frontend
npm install     # Install dependencies
npm run dev     # Start dev server
npm run build   # Build for production
```

## Using the Application

### 1. Launch the App
```powershell
npm run tauri dev
```

### 2. Create a Scan
- Navigate to "Scans" page
- Click "New Scan"
- Enter target (e.g., `example.com`)
- Select scan type
- Click "Start Scan"

### 3. View Tools
- Navigate to "Tools" page
- Click "Refresh Tools" to discover installed security tools
- Tools will be automatically detected on your system

### 4. Execute Workflows
- Navigate to "Scans" page
- Create a scan with a workflow template
- Execute the workflow
- Monitor progress in real-time

## Architecture Overview

```
┌─────────────────────────────────────┐
│     Frontend (React + Vite)         │
│  - TypeScript                       │
│  - Tailwind CSS                     │
│  - React Query                      │
└──────────────┬──────────────────────┘
               │
               │ Tauri IPC
               │ (Commands + Events)
               │
┌──────────────▼──────────────────────┐
│     Rust Backend (Tauri)            │
│  - Database (SQLx + SQLite)         │
│  - Workflow Engine                  │
│  - Tool Discovery                   │
│  - Command Execution                │
└──────────────┬──────────────────────┘
               │
               │ File System + Process
               │
┌──────────────▼──────────────────────┐
│     Security Tools                  │
│  - Subfinder, Naabu, Nuclei, etc.  │
│  - Installed on system PATH         │
└─────────────────────────────────────┘
```

## Key Differences from Python Backend

| Feature | Python Backend | Rust Backend |
|---------|---------------|--------------|
| **API** | HTTP REST (FastAPI) | Tauri Commands |
| **Real-time** | Socket.IO | Tauri Events |
| **Database** | SQLAlchemy (async) | SQLx |
| **Performance** | ~100ms per request | ~1-5ms per command |
| **Distribution** | Python + dependencies | Single binary |
| **Memory** | ~100MB base | ~20MB base |
| **Startup** | 2-3 seconds | <500ms |

## Debugging

### Enable Rust Debug Logs
```powershell
$env:RUST_LOG="debug"
npm run tauri dev
```

### Enable Frontend Debug
Open DevTools in the Tauri window:
- Right-click → Inspect Element
- Or press F12

### Check Database
```powershell
# Database location (Windows)
sqlite3 $env:APPDATA\com.aibugbountyscanner.app\scanner.db

# List tables
.tables

# Query scans
SELECT * FROM scans;
```

## Troubleshooting

### Issue: "Command not found"
**Solution:** Make sure Rust and Node.js are in your PATH
```powershell
cargo --version
node --version
npm --version
```

### Issue: "Failed to compile Rust code"
**Solution:** Update Rust toolchain
```powershell
rustup update stable
```

### Issue: "Frontend won't connect"
**Solution:** Make sure you're running in Tauri mode, not browser mode
- Use `npm run tauri dev` NOT `npm run dev`

### Issue: "Tools not discovered"
**Solution:** Install security tools and add to PATH
```powershell
# Example: Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Verify it's in PATH
subfinder -version
```

### Issue: "Database errors"
**Solution:** Delete old database and restart
```powershell
Remove-Item $env:APPDATA\com.aibugbountyscanner.app\scanner.db
npm run tauri dev
```

## Development Workflow

### Making Changes

1. **Backend Changes (Rust):**
   - Edit files in `src-tauri/src/`
   - Rust will recompile automatically
   - App will restart

2. **Frontend Changes (TypeScript/React):**
   - Edit files in `frontend/src/`
   - Hot-reload will update immediately
   - No restart needed

3. **Database Changes:**
   - Edit migrations in `src-tauri/src/migrations/`
   - Delete database to apply changes
   - Restart app

### Testing Changes

```powershell
# Test Rust compilation
cd src-tauri
cargo check

# Test frontend build
cd ../frontend
npm run build

# Run full app
cd ..
npm run tauri dev
```

## Next Steps

1. ✅ **You Are Here** - Rust backend is built and ready
2. 🔄 **Integration** - Connect workflow execution to emit events
3. 🧪 **Testing** - Test all features in the UI
4. 🐛 **Bug Fixes** - Fix any integration issues
5. 🚀 **Deployment** - Build production binary

## Resources

- **Tauri Docs**: https://tauri.app/v1/guides/
- **SQLx Docs**: https://docs.rs/sqlx/latest/sqlx/
- **React Query**: https://tanstack.com/query/latest
- **Rust Book**: https://doc.rust-lang.org/book/

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review the `RUST_BACKEND_MIGRATION_SUMMARY.md` file
3. Check Rust compiler errors with `cargo check`
4. Check browser console for frontend errors

---

**Status**: ✅ Backend migration infrastructure complete!
**Next**: Implement scan execution and event emission
