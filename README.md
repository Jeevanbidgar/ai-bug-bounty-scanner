# 🛡️ AI Bug Bounty Scanner

**Professional Security Tool Orchestration Platform** - Cross-Platform Desktop Application

A powerful Tauri-based desktop application for automated security tool installation, management, and orchestration. Supports reconnaissance, penetration testing, and vulnerability scanning with intelligent package manager integration and real-time execution monitoring.

---

## 🚀 Quick Start

### **Run Application**

```bash
npm run tauri dev
```

The application will:
1. Build the Rust backend
2. Start the frontend development server
3. Launch the native desktop application

### **Build for Production**

```bash
npm run tauri build
```

Creates platform-specific installers in `src-tauri/target/release/bundle/`

---

## 📋 Requirements

### **Development**
- **Node.js 18+** - Frontend build system
- **Rust 1.70+** - Backend compilation
- **Windows 10/11, Linux, or macOS** - Cross-platform support

### **Runtime (Auto-installed)**
The application can automatically install these through package managers:
- **Go** - For go install tools (subfinder, nuclei, etc.)
- **Python/pip** - For pipx tools (httpx, sqlmap, etc.)
- **Node.js/npm** - For npm tools (wappalyzer, etc.)
- **Ruby/gem** - For gem tools (WPScan, etc.)
- **Rust/Cargo** - For cargo tools (rustscan, etc.)

---

## 🎯 Features

### **Core Capabilities**
- ✅ **Native Desktop App** - Built with Tauri (Rust) + React
- ✅ **Automatic Tool Installation** - One-click install with package manager auto-detection
- ✅ **7 Package Managers Integrated** - Go, Pipx, npm, gem, Cargo, APT, WinGet
- ✅ **7 Tool-Specific Adapters** - Optimized execution for popular security tools
- ✅ **Real-time Output Streaming** - Live command output with color coding
- ✅ **Cross-Platform** - Windows, Linux, and macOS support
- ✅ **Smart Detection** - Automatically finds tools in PATH and non-standard locations
- ✅ **Error Recovery** - Intelligent fallback strategies and helpful error messages

### **Package Manager Features**
- **Auto-Detection**: Scans system for installed package managers
- **Auto-Installation**: Installs missing package managers (WinGet, apt, brew)
- **Dynamic Path Resolution**: Finds executables even outside PATH
- **Windows Batch File Support**: Properly handles .cmd and .bat executables
- **Cross-Platform Installation**: Platform-specific installation strategies

### **Tool Management**
- **Catalog System**: 30+ pre-configured security tools
- **Installation Status**: Real-time detection of installed tools
- **Version Checking**: Automatic version detection and display
- **Update Notifications**: Alerts for available tool updates
- **Bulk Operations**: Install multiple tools simultaneously

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────┐
│              Tauri Desktop Application               │
│  ┌────────────────────────────────────────────────┐  │
│  │         React Frontend (TypeScript)            │  │
│  │  ┌──────────────┐  ┌──────────────────────┐   │  │
│  │  │   Dashboard  │  │   Tools Management   │   │  │
│  │  │   - Status   │  │   - Install/Update   │   │  │
│  │  │   - Metrics  │  │   - Version Check    │   │  │
│  │  └──────────────┘  └──────────────────────┘   │  │
│  │  ┌──────────────┐  ┌──────────────────────┐   │  │
│  │  │  Adapters    │  │   Package Managers   │   │  │
│  │  │  - Amass     │  │   - npm/gem/cargo    │   │  │
│  │  │  - Nuclei    │  │   - Go/Pipx/APT      │   │  │
│  │  │  - Nmap      │  │   - WinGet           │   │  │
│  │  └──────────────┘  └──────────────────────┘   │  │
│  └────────────────┬───────────────────────────────┘  │
│                   │ Tauri Commands (IPC)             │
│  ┌────────────────▼───────────────────────────────┐  │
│  │           Rust Backend (Tauri Core)            │  │
│  │  ┌──────────────────────────────────────────┐  │  │
│  │  │         Package Manager System           │  │  │
│  │  │  - Detection Engine                      │  │  │
│  │  │  - Installation Manager                  │  │  │
│  │  │  - 7 Package Manager Implementations     │  │  │
│  │  └──────────────────────────────────────────┘  │  │
│  │  ┌──────────────────────────────────────────┐  │  │
│  │  │          Tool Adapter System             │  │  │
│  │  │  - Amass, GAU, Naabu, Nmap, Nuclei      │  │  │
│  │  │  - Waybackurls, Registry                 │  │  │
│  │  │  - Output Parsing & Error Handling       │  │  │
│  │  └──────────────────────────────────────────┘  │  │
│  │  ┌──────────────────────────────────────────┐  │  │
│  │  │        Tool Discovery & Catalog          │  │  │
│  │  │  - 30+ Security Tool Definitions         │  │  │
│  │  │  - Version Detection                     │  │  │
│  │  │  - Installation Status Tracking          │  │  │
│  │  └──────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
                         │
                         ▼
          ┌──────────────────────────┐
          │    Native OS Commands    │
          │  - npm, gem, cargo, go   │
          │  - apt, winget, brew     │
          │  - Security tools        │
          └──────────────────────────┘
```

---

## 🛠️ Supported Tools & Package Managers

### **Package Managers** (7 Integrated)

| Manager | Platform | Status | Use Case |
|---------|----------|--------|----------|
| **Go install** | All | ✅ Full | Go-based security tools (subfinder, nuclei, etc.) |
| **Pipx** | All | ✅ Full | Python CLI tools (httpx, sqlmap, etc.) |
| **npm** | All | ✅ Full | Node.js tools (wappalyzer, etc.) |
| **gem** | All | ✅ Full | Ruby tools (WPScan, etc.) |
| **Cargo** | All | ✅ Full | Rust tools (rustscan, etc.) |
| **APT** | Linux | ✅ Full | System packages (nmap, masscan, etc.) |
| **WinGet** | Windows | ✅ Full | System packages and language runtimes |

### **Security Tools** (30+ Supported)

#### **Subdomain Discovery**
- **subfinder** (Go) - Fast subdomain enumeration
- **amass** (Go) - In-depth DNS enumeration and network mapping
- **assetfinder** (Go) - Subdomain finder

#### **URL Discovery**
- **waybackurls** (Go) - Fetch all URLs from Wayback Machine
- **gau** (Go) - Get All URLs from multiple sources
- **hakrawler** (Go) - Web crawler for gathering URLs

#### **Port Scanning**
- **naabu** (Go) - Fast port scanner
- **nmap** (APT/WinGet) - Network exploration and security auditing
- **masscan** (APT) - Fast TCP port scanner
- **rustscan** (Cargo) - Modern port scanner

#### **Vulnerability Scanning**
- **nuclei** (Go) - Template-based vulnerability scanner
- **httpx** (Pipx) - Fast HTTP toolkit
- **ffuf** (Go) - Fast web fuzzer

#### **Web Application Security**
- **sqlmap** (Pipx) - SQL injection detection
- **wpscan** (gem) - WordPress security scanner
- **nikto** (APT) - Web server scanner

#### **DNS & Network**
- **dnsx** (Go) - Fast DNS toolkit
- **shuffledns** (Go) - DNS resolver wrapper
- **massdns** (APT) - High-performance DNS stub resolver

#### **Content Discovery**
- **gobuster** (Go) - Directory/file brute-forcing
- **feroxbuster** (Cargo) - Recursive content discovery
- **dirsearch** (Pipx) - Web path scanner

### **Tool Adapters** (7 Implemented)

Specialized execution wrappers for optimal tool performance:

1. **Amass Adapter** - Advanced DNS enumeration with passive/active modes
2. **GAU Adapter** - URL collection from multiple archive sources
3. **Naabu Adapter** - High-speed port scanning with SYN/CONNECT modes
4. **Nmap Adapter** - Comprehensive network scanning with script support
5. **Nuclei Adapter** - Template-based vulnerability scanning
6. **Waybackurls Adapter** - Historical URL discovery
7. **Registry Adapter** - Centralized adapter management and coordination

---

## 📖 Usage

### **First Launch**

```bash
# Install dependencies
npm install

# Run application
npm run tauri dev
```

**First launch takes 2-5 minutes** (Rust compilation)  
**Subsequent launches take 5-10 seconds**

### **Main Interface**

#### **Dashboard**
- System health monitoring
- Package manager status (npm, gem, cargo, go, pipx, apt, winget)
- Quick statistics and metrics
- Recent activity feed

#### **Tools Page**
- Browse 30+ security tools
- View installation status
- One-click installation via package managers
- Tool descriptions and documentation links
- Version information

#### **Package Managers Panel**
- View all 7 package managers
- Check installation status
- Auto-install missing managers
- Version and path information

#### **Adapters Page**
- Explore tool-specific adapters
- View adapter capabilities
- Monitor adapter registry
- Debug adapter execution

### **Installing Tools**

1. Navigate to **Tools** page
2. Find the tool you want
3. Click **Install** button
4. Watch real-time installation progress
5. Tool becomes available immediately

**Supported Installation Methods**:
- ✅ One-click install via UI
- ✅ Auto-selects best package manager
- ✅ Falls back to alternatives if needed
- ✅ Streams output in real-time
- ✅ Handles errors gracefully

### **Package Manager Auto-Installation**

If a package manager is missing, the app can install it:

**Windows**:
- npm/Node.js → via WinGet
- gem/Ruby → via WinGet
- Go → via WinGet or manual download

**Linux**:
- npm/Node.js → via APT
- gem/Ruby → via APT
- Go → via APT or official installer

**macOS**:
- npm/Node.js → via Homebrew
- gem/Ruby → via Homebrew
- Go → via Homebrew

### **Running Tools**

Currently focused on installation and management. Scan orchestration coming soon!

---

## 🔧 Development

### **Project Setup**

```bash
# Clone repository
git clone <your-repo-url>
cd ai-bug-bounty-scanner

# Install frontend dependencies
npm install

# Install Rust (if not installed)
# Windows: https://rustup.rs/
# Linux/Mac: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Run in development mode
npm run tauri dev
```

### **Development Workflow**

```bash
# Frontend development (with hot reload)
npm run dev

# Backend (Rust) development
cd src-tauri
cargo build

# Run full application
npm run tauri dev

# Check for errors
cargo check
```

### **Project Structure**

```
ai-bug-bounty-scanner/
├── frontend/                    # React frontend
│   ├── src/
│   │   ├── components/         # React components
│   │   │   ├── AdapterExplorer.tsx
│   │   │   ├── PackageManagerPanel.tsx
│   │   │   ├── InstallationProgress.tsx
│   │   │   └── ...
│   │   ├── pages/              # Page components
│   │   │   ├── Dashboard.tsx
│   │   │   ├── ToolsPage.tsx
│   │   │   ├── AdaptersPage.tsx
│   │   │   └── ...
│   │   ├── hooks/              # Custom React hooks
│   │   ├── services/           # API services
│   │   └── App.tsx             # Main app component
│   └── package.json
│
├── src-tauri/                   # Rust backend
│   ├── src/
│   │   ├── main.rs             # Entry point & Tauri setup
│   │   ├── commands/           # Tauri command handlers
│   │   │   └── mod.rs          # Tool & package manager commands
│   │   ├── tools/              # Tool management system
│   │   │   ├── catalog.rs      # Tool definitions
│   │   │   ├── discovery.rs    # Tool detection
│   │   │   └── package_managers/
│   │   │       ├── detection.rs      # Package manager detection
│   │   │       ├── npm_installer.rs  # npm integration
│   │   │       ├── gem_installer.rs  # gem integration
│   │   │       ├── cargo_installer.rs
│   │   │       ├── go_install.rs
│   │   │       ├── pipx_manager.rs
│   │   │       ├── apt_manager.rs
│   │   │       └── winget_manager.rs
│   │   ├── adapters/           # Tool-specific adapters
│   │   │   ├── amass.rs
│   │   │   ├── nmap.rs
│   │   │   ├── nuclei.rs
│   │   │   └── ...
│   │   └── runtime/            # Execution engine
│   ├── Cargo.toml              # Rust dependencies
│   └── tauri.conf.json         # Tauri configuration
│
├── data/                        # Application data
│   └── tool_discovery_cache.json
│
├── docs/                        # Documentation
│   ├── NPM_GEM_DETECTION_FIX_COMPLETE.md
│   ├── PACKAGE_MANAGER_INTEGRATION.md
│   ├── ADAPTER_SYSTEM.md
│   └── ...
│
└── README.md                    # This file
```

---

## 📊 Tech Stack

### **Frontend**
- **React 18** - Modern UI framework
- **TypeScript** - Type-safe development
- **Vite** - Lightning-fast build tool
- **Tailwind CSS** - Utility-first styling
- **Lucide React** - Beautiful icons

### **Backend (Rust)**
- **Tauri 1.x** - Native desktop framework
- **tokio** - Async runtime
- **serde** - Serialization/deserialization
- **anyhow** - Error handling
- **async-trait** - Async traits

### **Desktop Integration**
- **Native Window** - Platform-specific UI
- **IPC (Inter-Process Communication)** - Frontend ↔ Backend
- **System Commands** - Execute package managers and tools
- **File System Access** - Read/write local data

### **Package Manager Integration**
- **Dynamic Detection** - Finds managers in PATH and custom locations
- **Cross-Platform** - Windows, Linux, macOS support
- **Auto-Installation** - Installs missing dependencies
- **Streaming Output** - Real-time command output

---

## 🔒 Security Features

- ✅ **Sandboxed Execution** - Tauri security model
- ✅ **Command Validation** - Input sanitization for all tool executions
- ✅ **Path Resolution** - Prevents path traversal attacks
- ✅ **Resource Limits** - Timeout and memory constraints
- ✅ **Error Isolation** - Failures don't crash the app
- ✅ **Secure IPC** - Controlled communication between frontend/backend
- ✅ **No Remote Code Execution** - All tools run locally

---

## � Troubleshooting

### **Application Won't Start?**

1. **Check Node.js**:
   ```bash
   node --version  # Should be 18+
   npm --version
   ```

2. **Check Rust**:
   ```bash
   cargo --version  # Should be 1.70+
   rustc --version
   ```

3. **Reinstall Dependencies**:
   ```bash
   npm install
   cd src-tauri
   cargo clean
   cargo build
   ```

### **Package Manager Not Detected?**

**Windows**:
- npm: Install Node.js from https://nodejs.org or via WinGet
- gem: Install Ruby from https://rubyinstaller.org or via WinGet
- WinGet: Install from Microsoft Store (App Installer)

**Linux**:
```bash
# npm
sudo apt install nodejs npm

# gem
sudo apt install ruby-full

# go
sudo apt install golang-go
```

**macOS**:
```bash
# Install Homebrew first
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Then install package managers
brew install node ruby go
```

### **Tool Installation Fails?**

1. **Check Console Output** - Look for error messages in the installation modal
2. **Verify Package Manager** - Ensure the required package manager is installed
3. **Check Internet Connection** - Tools are downloaded from the internet
4. **Manual Installation** - If auto-install fails, install manually and app will detect it

### **Build Errors?**

```bash
# Clean build
cargo clean
npm run tauri build

# Check for compilation errors
cd src-tauri
cargo check

# Update dependencies
cargo update
```

### **Common Issues**

| Issue | Solution |
|-------|----------|
| `npm.cmd not found` | Install Node.js or add to PATH |
| `gem.cmd not found` | Install Ruby or add to PATH |
| `cargo not found` | Install Rust toolchain |
| `go not found` | Install Go or add to PATH |
| Build takes forever | First build compiles Rust (~3-5 min), subsequent builds are faster |
| Port conflict | Frontend uses 1420, ensure it's available |

---

## � Building & Distribution

### **Development Build**

```bash
npm run tauri dev
```

### **Production Build**

```bash
npm run tauri build
```

**Output Locations**:

**Windows**:
- MSI Installer: `src-tauri/target/release/bundle/msi/AI Bug Bounty Scanner_2.0.0_x64_en-US.msi`
- Executable: `src-tauri/target/release/ai-bug-bounty-scanner.exe`

**Linux**:
- AppImage: `src-tauri/target/release/bundle/appimage/ai-bug-bounty-scanner_2.0.0_amd64.AppImage`
- DEB Package: `src-tauri/target/release/bundle/deb/ai-bug-bounty-scanner_2.0.0_amd64.deb`

**macOS**:
- DMG: `src-tauri/target/release/bundle/dmg/AI Bug Bounty Scanner_2.0.0_x64.dmg`
- App Bundle: `src-tauri/target/release/bundle/macos/AI Bug Bounty Scanner.app`

### **Installer Configuration**

Edit `src-tauri/tauri.conf.json`:

```json
{
  "package": {
    "productName": "AI Bug Bounty Scanner",
    "version": "2.0.0"
  },
  "tauri": {
    "bundle": {
      "identifier": "com.bugbounty.scanner",
      "icon": [
        "icons/32x32.png",
        "icons/128x128.png",
        "icons/icon.icns",
        "icons/icon.ico"
      ]
    }
  }
}
```

---

## 🎨 Customization

### **Changing the App Icon**

1. Create a 1024x1024 PNG icon
2. Place in `src-tauri/icons/`
3. Use Tauri CLI to generate all sizes:
   ```bash
   npm run tauri icon path/to/your-icon.png
   ```

### **Modifying Tool Catalog**

Edit `src-tauri/src/tools/catalog.rs` to add/modify tools:

```rust
ToolDefinition {
    name: "your-tool".to_string(),
    display_name: "Your Tool".to_string(),
    description: "Description of your tool".to_string(),
    category: ToolCategory::Reconnaissance,
    package_manager: Some(PackageManagerType::Go),
    go_package: Some("github.com/user/tool@latest".to_string()),
    // ... other fields
}
```

### **Adding New Package Managers**

1. Create new file in `src-tauri/src/tools/package_managers/`
2. Implement the manager trait
3. Add detection logic to `detection.rs`
4. Register in `mod.rs`

### **Creating Custom Adapters**

1. Create new file in `src-tauri/src/adapters/`
2. Implement the adapter interface
3. Add to adapter registry
4. Register in `registry.rs`

---

## 🤝 Contributing

Contributions are welcome! This is a professional security tool for the community.

### **How to Contribute**

1. **Fork the Repository**
2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make Your Changes**
   - Add new tools to the catalog
   - Implement new adapters
   - Add package manager support
   - Improve UI/UX
   - Fix bugs
4. **Test Thoroughly**
   ```bash
   npm run tauri dev
   cargo test
   ```
5. **Commit with Descriptive Messages**
   ```bash
   git commit -m "feat: Add support for new tool"
   ```
6. **Push and Create Pull Request**

### **Development Guidelines**

- **Rust Code**: Follow Rust style guidelines, use `cargo fmt`
- **TypeScript**: Use ESLint and Prettier
- **Commits**: Follow conventional commits (feat, fix, docs, etc.)
- **Testing**: Add tests for new features
- **Documentation**: Update relevant docs

### **Areas for Contribution**

- 🛠️ **New Tools**: Add more security tools to catalog
- 📦 **Package Managers**: Support for additional package managers
- 🎨 **UI/UX**: Improve interface and user experience
- 🔌 **Adapters**: Create adapters for more tools
- 🐛 **Bug Fixes**: Fix reported issues
- 📚 **Documentation**: Improve guides and docs
- 🧪 **Testing**: Add unit and integration tests

---

## 📚 Documentation

### **Available Documentation**

- **[NPM & Gem Detection Fix](./NPM_GEM_DETECTION_FIX_COMPLETE.md)** - How npm/gem detection works on Windows
- **[Package Manager Integration](./COMPLETE_PACKAGE_MANAGER_IMPLEMENTATION.md)** - Complete package manager system
- **[Adapter System](./ADAPTER_INTEGRATION_COMPLETE.md)** - Tool adapter architecture
- **[Frontend Guide](./FRONTEND_COMPLETE_COMPREHENSIVE.md)** - Frontend components and structure
- **[Next Steps](./NEXT_STEPS.md)** - Roadmap and future plans

### **API Documentation**

Tauri commands are documented in `src-tauri/src/commands/mod.rs`:
- `get_available_tools` - List all tools
- `install_tool` - Install a specific tool
- `detect_package_managers` - Check package manager status
- `get_tool_adapters` - List available adapters

---

## 🎯 Roadmap

### **Phase 1: Foundation** ✅ COMPLETE
- [x] Package manager detection and integration
- [x] Tool catalog system
- [x] Auto-installation for npm, gem, cargo, go, pipx
- [x] Basic UI for tool management
- [x] Tool-specific adapters (7 tools)

### **Phase 2: Scan Engine** 🚧 IN PROGRESS
- [ ] Workflow system for chaining tools
- [ ] Scan templates (subdomain enum, port scan, vuln scan)
- [ ] Real-time execution monitoring
- [ ] Output parsing and normalization
- [ ] Result aggregation

### **Phase 3: Reporting** 📋 PLANNED
- [ ] Report generation (PDF, HTML, JSON, CSV)
- [ ] Vulnerability database
- [ ] Finding deduplication
- [ ] Severity scoring
- [ ] Export/import functionality

### **Phase 4: Advanced Features** 🔮 FUTURE
- [ ] Plugin system for custom tools
- [ ] Cloud storage integration
- [ ] Team collaboration features
- [ ] CI/CD integration
- [ ] API for external integrations
- [ ] Dark/light theme
- [ ] Multi-language support

### **Phase 5: Platform Expansion** 🌐 FUTURE
- [ ] Linux package distribution (snap, flatpak)
- [ ] macOS Homebrew formula
- [ ] Docker container support
- [ ] Web-based version (optional)

---

## ⚖️ License

**MIT License** - See [LICENSE](./LICENSE) file for details

### **Ethical Use Policy**

This tool is designed for **authorized security testing only**. Users must:

- ✅ Obtain explicit permission before scanning any target
- ✅ Comply with local laws and regulations
- ✅ Use responsibly and ethically
- ✅ Respect rate limits and resource constraints
- ❌ Never use for unauthorized access or malicious purposes

**The developers are not responsible for misuse of this tool.**

---

## 📞 Support & Community

### **Getting Help**

1. **Documentation**: Check the docs/ folder
2. **Issues**: Open an issue on GitHub
3. **Discussions**: Join GitHub Discussions
4. **Console Logs**: Check application console for errors

### **Reporting Bugs**

Please include:
- Operating system and version
- Application version
- Steps to reproduce
- Error messages/screenshots
- Console output

### **Feature Requests**

Open an issue with:
- Clear description of the feature
- Use case and benefits
- Proposed implementation (optional)

---

## � Acknowledgments

### **Built With**
- **Tauri** - Desktop application framework
- **Rust** - Systems programming language
- **React** - UI framework
- **TypeScript** - Type-safe JavaScript

### **Security Tools**
Thanks to the amazing security community for creating tools like:
- ProjectDiscovery (subfinder, nuclei, naabu, httpx, etc.)
- OWASP (sqlmap, amass, etc.)
- And many more open-source contributors

### **Special Thanks**
- All contributors to this project
- The bug bounty community
- Open-source security tool developers

---

## 📈 Project Stats

- **Lines of Code**: 10,000+ (Rust + TypeScript)
- **Package Managers**: 7 integrated
- **Tools Supported**: 30+
- **Adapters**: 7 specialized
- **Platforms**: Windows, Linux, macOS
- **Build Time**: ~3-5 minutes (first time), ~10s (subsequent)
- **Bundle Size**: ~15-20 MB (platform-specific)

---

**Made with ❤️ for the security community**

**Version**: 2.0.0  
**Last Updated**: October 5, 2025  
**Status**: 🟢 Active Development

---

## 🚀 Quick Reference

```bash
# Install dependencies
npm install

# Run development mode
npm run tauri dev

# Build for production
npm run tauri build

# Run tests
cargo test

# Format code
cargo fmt
npm run format

# Check for errors
cargo check
npm run lint
```

**First time?** Just run `npm install && npm run tauri dev` 🎉

---

## 💡 Pro Tips

1. **First Build**: Takes 3-5 minutes (Rust compilation), be patient!
2. **Package Managers**: Let the app auto-install missing ones
3. **Tool Updates**: Check for updates regularly
4. **Error Messages**: Read them! They're designed to be helpful
5. **Console Output**: Watch the terminal for debugging info
6. **Cache**: Tool discovery is cached for faster startup

---

**Happy Bug Hunting! 🐛🔍**
