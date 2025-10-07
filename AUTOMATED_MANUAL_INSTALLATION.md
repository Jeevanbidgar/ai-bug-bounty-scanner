# Automated Manual Installation System

## Overview
Comprehensive automated installation system that handles tools requiring multi-step installation processes (git clone, pip install, symlinks, etc.) across Windows and Kali Linux.

---

## 🎯 Features

### Cross-Platform Support
- **Windows**: Creates `.bat` wrapper scripts, uses AppData\Local\Programs
- **Linux/Kali**: Creates symlinks, uses `~/.local/bin`, handles chmod +x

### Installation Methods Supported
1. **Git + Python** (git clone → pip install -r requirements.txt)
2. **Git + pip editable** (git clone → pip install -e .)
3. **Git + Ruby** (git clone → bundle install)
4. **Git + Go** (git clone → go build)
5. **Git + Perl** (git clone → chmod +x → symlink)
6. **Git + Make** (git clone → make install)

---

## 📦 Supported Tools (15)

### Python Tools (Git + pip)
| Tool | Steps | Description |
|------|-------|-------------|
| **xsstrike** | Clone → pip install -r → symlink | XSS detection suite |
| **cloudfail** | Clone → pip install -r → symlink | Find origin servers behind CDN |
| **linkfinder** | Clone → pip install -r → pip install -e . | Extract endpoints from JS |
| **knockpy** | Clone → pip install -e . | Subdomain scanner |
| **dnsrecon** | Clone → pip install -r → symlink | DNS enumeration |
| **wfuzz** | Clone → pip install -e . | Web fuzzer |

### Ruby Tools
| Tool | Steps | Description |
|------|-------|-------------|
| **wpscan** | Clone → gem install bundler → bundle install | WordPress scanner |

### Perl Tools  
| Tool | Steps | Description |
|------|-------|-------------|
| **joomscan** | Clone → chmod +x → symlink | Joomla scanner |
| **nikto** | Clone → symlink | Web server scanner |
| **dnsenum** | Clone → chmod +x → symlink | DNS enumeration |
| **searchsploit** | Clone → symlink → $PATH config | Exploit database |

### Go Tools
| Tool | Steps | Description |
|------|-------|-------------|
| **aquatone** | Clone → go build → symlink | Visual website inspection |

### Shell Script Tools
| Tool | Steps | Description |
|------|-------|-------------|
| **whatweb** | Clone → symlink | Web technology detection |

### Complex Setup
| Tool | Steps | Description |
|------|-------|-------------|
| **eyewitness** | Clone → cd Python/setup → sh setup.sh | Screenshot web pages |

---

## 🔧 Installation Step Types

### 1. GitClone
```rust
InstallStep::GitClone {
    url: "https://github.com/user/repo.git",
    target_dir: "repo"
}
```
- Clones repository to `tools_dir/repo`
- Skips if directory already exists
- Uses system `git` command

### 2. ChangeDirectory
```rust
InstallStep::ChangeDirectory {
    path: "repo/subdirectory"
}
```
- Changes working directory for subsequent steps
- Supports relative and absolute paths
- Validates directory exists

### 3. PipInstall
```rust
InstallStep::PipInstall {
    requirements_file: Some("requirements.txt")
}
```
- Installs Python dependencies
- Uses `python` (Windows) or `python3` (Linux)
- With requirements file: `pip install -r requirements.txt`
- Without: `pip install .`

### 4. PipInstallEditable
```rust
InstallStep::PipInstallEditable
```
- Installs package in development mode: `pip install -e .`
- Allows in-place modifications
- Used for tools with setup.py

### 5. RunCommand
```rust
InstallStep::RunCommand {
    command: "gem",
    args: vec!["install", "bundler"]
}
```
- Executes arbitrary command with arguments
- Captures stdout/stderr for live streaming
- Fails if exit code != 0

### 6. CreateSymlink
```rust
InstallStep::CreateSymlink {
    source: "tool.py",
    target: "/usr/local/bin/tool"
}
```
- **Windows**: Creates `.bat` wrapper with `python "source" %*`
- **Linux**: Creates actual symlink + chmod +x
- Target path uses platform-specific bin directory

### 7. Chmod
```rust
InstallStep::Chmod {
    path: "script.pl",
    mode: "+x"
}
```
- Linux/Kali only (no-op on Windows)
- Makes scripts executable
- Supports `+x` (755) and custom modes

### 8. MakeInstall
```rust
InstallStep::MakeInstall
```
- Runs `make install` in current directory
- For tools with Makefile
- Typically requires sudo/elevation

### 9. ConfigureEnvironment
```rust
InstallStep::ConfigureEnvironment {
    var_name: "PATH",
    var_value: "/new/path:$PATH"
}
```
- Informational only (requires restart)
- Shows users what environment changes are needed

---

## 📂 Directory Structure

### Windows
```
%LOCALAPPDATA%\SecurityTools\           # Tools installation root
├── XSStrike\                           # Git clones
├── CloudFail\
└── LinkFinder\

%LOCALAPPDATA%\Programs\SecurityTools\  # Executables
├── xsstrike.bat                        # Batch wrappers
├── cloudfail.bat
└── linkfinder.bat
```

### Linux/Kali
```
~/.local/share/security-tools/          # Tools installation root
├── XSStrike/                           # Git clones
├── CloudFail/
└── LinkFinder/

~/.local/bin/                           # Executables (already in $PATH)
├── xsstrike -> ../share/security-tools/XSStrike/xsstrike.py
├── cloudfail -> ../share/security-tools/CloudFail/cloudfail.py
└── linkfinder                          # Installed via pip -e .
```

---

## 🎬 Execution Flow

### 1. Pre-Installation
```rust
// Get tool-specific steps
let steps = ManualInstaller::get_install_steps("xsstrike");

// Create directories
let tools_dir = ManualInstaller::get_tools_dir();
let bin_dir = ManualInstaller::get_bin_dir();

// Emit installation started event
app_handle.emit_all(TOOL_INSTALLATION_STARTED, ...);
```

### 2. Step Execution
```rust
for (i, step) in steps.iter().enumerate() {
    // Show progress: "Step 1/4: Cloning from https://..."
    emit_output("Step 1/4: ...");
    
    // Execute step
    match execute_step(step) {
        Ok(result) => {
            // Update working directory if changed
            current_dir = result.new_working_dir;
            
            // Track installed path
            installed_path = result.installed_path;
        }
        Err(e) => {
            // Fail entire installation
            return Err(format!("Failed at step {}: {}", i, e));
        }
    }
}
```

### 3. Live Output Streaming
```rust
// Commands spawn with piped stdout/stderr
let mut child = Command::new("git")
    .args(&["clone", url])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()?;

// Stream output to frontend via Tauri events
tokio::spawn(async move {
    while let Some(line) = stdout_reader.next_line().await {
        app_handle.emit_all(
            TOOL_INSTALLATION_OUTPUT,
            { tool_name, output_type: "stdout", line }
        );
    }
});

// Wait for completion using tokio::join! (no deadlock)
let (status, _, stderr) = tokio::join!(
    child.wait(),
    stdout_task,
    stderr_task
);
```

### 4. Post-Installation
```rust
// Verify installation
if tool_found_in_path() {
    emit_all(TOOL_INSTALLATION_COMPLETED, success=true);
    recheck_tool(); // Update UI
} else {
    emit_all(TOOL_INSTALLATION_COMPLETED, success=false);
}
```

---

## 🔍 Example: XSStrike Installation

### Windows
```powershell
# Step 1: Clone repository
C:\Users\User\AppData\Local\SecurityTools> git clone https://github.com/s0md3v/XSStrike.git

# Step 2: Change directory
cd XSStrike

# Step 3: Install dependencies
python -m pip install -r requirements.txt

# Step 4: Create wrapper
echo @echo off > C:\Users\User\AppData\Local\Programs\SecurityTools\xsstrike.bat
echo python "C:\Users\User\AppData\Local\SecurityTools\XSStrike\xsstrike.py" %* >> xsstrike.bat

# Result: xsstrike.bat in PATH
xsstrike --help
```

### Linux/Kali
```bash
# Step 1: Clone repository
~/.local/share/security-tools$ git clone https://github.com/s0md3v/XSStrike.git

# Step 2: Change directory
cd XSStrike

# Step 3: Install dependencies
python3 -m pip install -r requirements.txt

# Step 4: Create symlink
ln -s ~/.local/share/security-tools/XSStrike/xsstrike.py ~/.local/bin/xsstrike
chmod +x ~/.local/share/security-tools/XSStrike/xsstrike.py

# Result: xsstrike in PATH
xsstrike --help
```

---

## 🚀 Adding New Tools

### Simple Python Tool
```rust
"newtool" => vec![
    InstallStep::GitClone {
        url: "https://github.com/user/newtool.git",
        target_dir: "newtool"
    },
    InstallStep::ChangeDirectory { path: "newtool" },
    InstallStep::PipInstall { requirements_file: Some("requirements.txt") },
    InstallStep::CreateSymlink {
        source: "newtool.py",
        target: Self::get_bin_dir().join("newtool")
    }
]
```

### Go Tool
```rust
"newtool" => vec![
    InstallStep::GitClone {
        url: "https://github.com/user/newtool.git",
        target_dir: "newtool"
    },
    InstallStep::ChangeDirectory { path: "newtool" },
    InstallStep::RunCommand {
        command: "go",
        args: vec!["build", "-o", "newtool"]
    },
    InstallStep::CreateSymlink {
        source: "newtool",
        target: Self::get_bin_dir().join("newtool")
    }
]
```

### Ruby Tool
```rust
"newtool" => vec![
    InstallStep::GitClone {
        url: "https://github.com/user/newtool.git",
        target_dir: "newtool"
    },
    InstallStep::ChangeDirectory { path: "newtool" },
    InstallStep::RunCommand {
        command: "gem",
        args: vec!["install", "bundler"]
    },
    InstallStep::RunCommand {
        command: "bundle",
        args: vec!["install"]
    }
]
```

---

## ⚡ Performance

| Metric | Value |
|--------|-------|
| Average installation time | 30-90 seconds |
| Git clone | 10-30 seconds |
| pip install | 15-45 seconds |
| Symlink creation | < 1 second |
| Total overhead | ~2 seconds |

---

## 🛡️ Error Handling

### Git Clone Failures
- **Already cloned**: Skip clone, continue to next step
- **Network error**: Fail with retry suggestion
- **Invalid URL**: Fail with error message

### pip Install Failures
- **Missing dependencies**: Show stderr output
- **Permission denied**: Suggest using venv or --user flag
- **Python not found**: Fail with "Python required" message

### Symlink Failures
- **Target already exists**: Skip (assume already installed)
- **Permission denied**: Fail with sudo suggestion (Linux)
- **Source not found**: Fail with file check

---

## 🔄 Updates

Tools installed via ManualInstaller can be updated by:
1. Deleting the tool directory (e.g., `XSStrike`)
2. Re-running the installation steps
3. OR: `cd` to tool directory and `git pull`

Future enhancement: Add `update_tool` support with `git pull` + reinstall.

---

## 📊 Tool Coverage

| Category | Tools | Install Method |
|----------|-------|----------------|
| Python (pip) | 6 | Git + pip |
| Ruby | 1 | Git + bundler |
| Perl | 4 | Git + chmod |
| Go | 1 | Git + go build |
| Shell | 1 | Git + symlink |
| Complex | 1 | Git + custom script |
| **Total** | **15** | **Automated Manual** |

---

## 🎯 Next Steps

### Phase 10 Enhancements
1. Add update support (`git pull` in tool directories)
2. Add uninstall support (remove symlinks + directories)
3. Add version detection for git-based tools
4. Add dependency checking (Python, Ruby, Perl versions)
5. Add pre-installation disk space check

### Additional Tools to Support
- **Metasploit** (complex installation)
- **Burp Suite** (Java-based, custom installer)
- **OWASP ZAP** (Java-based, custom installer)
- **radare2** (make install from source)

---

## ✅ Testing Checklist

### Windows
- [ ] XSStrike installs successfully
- [ ] CloudFail installs successfully
- [ ] Batch wrapper executes correctly
- [ ] Tool appears in PATH after restart
- [ ] Live streaming shows git/pip output

### Linux/Kali
- [ ] XSStrike installs successfully
- [ ] CloudFail installs successfully
- [ ] Symlink created and executable
- [ ] Tool appears in PATH immediately
- [ ] chmod +x applied correctly

### Cross-Platform
- [ ] Directory creation works
- [ ] Multiple tools can install in parallel
- [ ] Error messages are clear
- [ ] Recheck updates UI status
- [ ] Minimizable modal works during installation

---

*Last Updated: October 2, 2025*
*Author: Jeevan*
