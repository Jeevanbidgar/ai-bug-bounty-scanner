// Package manager detection
//
// Detects which package managers are available on the system

use super::PackageManagerType;
use crate::runtime::process::hidden_std_command;
use serde::{Deserialize, Serialize};
use tokio::time::{timeout, Duration};

/// Information about a detected package manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManagerInfo {
    /// Type of package manager
    pub manager_type: PackageManagerType,
    /// Whether the package manager is available
    pub available: bool,
    /// Version of the package manager (if detected)
    pub version: Option<String>,
    /// Path to the package manager executable (if found)
    pub path: Option<String>,
    /// Error message if detection failed
    pub error: Option<String>,
}

impl PackageManagerInfo {
    /// Create a new PackageManagerInfo for an unavailable manager
    pub fn unavailable(manager_type: PackageManagerType, error: String) -> Self {
        Self {
            manager_type,
            available: false,
            version: None,
            path: None,
            error: Some(error),
        }
    }

    /// Create a new PackageManagerInfo for an available manager
    pub fn available(
        manager_type: PackageManagerType,
        version: Option<String>,
        path: Option<String>,
    ) -> Self {
        Self {
            manager_type,
            available: true,
            version,
            path,
            error: None,
        }
    }
}

/// Detect all supported package managers
pub async fn detect_all_managers() -> Vec<PackageManagerInfo> {
    let managers = vec![
        PackageManagerType::Go,
        PackageManagerType::Pipx,
        PackageManagerType::Cargo,
        PackageManagerType::Npm,
        PackageManagerType::Gem,
        PackageManagerType::Apt,
        PackageManagerType::WinGet,
        PackageManagerType::Homebrew,
    ];

    let mut results = Vec::new();
    for manager in managers {
        results.push(detect_manager(manager).await);
    }
    results
}

/// Detect a specific package manager
pub async fn detect_manager(manager_type: PackageManagerType) -> PackageManagerInfo {
    match manager_type {
        PackageManagerType::Go => detect_go().await,
        PackageManagerType::Pipx => detect_pipx().await,
        PackageManagerType::Cargo => detect_cargo().await,
        PackageManagerType::Npm => detect_npm().await,
        PackageManagerType::Gem => detect_gem().await,
        PackageManagerType::Apt => detect_apt().await,
        PackageManagerType::WinGet => detect_winget().await,
        #[cfg(target_os = "macos")]
        PackageManagerType::Homebrew => detect_homebrew().await,
        #[cfg(not(target_os = "macos"))]
        PackageManagerType::Homebrew => PackageManagerInfo::unavailable(
            PackageManagerType::Homebrew,
            "Homebrew is only available on macOS".to_string(),
        ),
    }
}

/// Detect Go installation
async fn detect_go() -> PackageManagerInfo {
    // Try command first (if in PATH)
    match execute_detection_command("go", &["version"]).await {
        Ok((stdout, _stderr)) => {
            let version = parse_go_version(&stdout);
            return PackageManagerInfo::available(PackageManagerType::Go, version, None);
        }
        Err(_) => {
            // Try dynamic search
            if let Some(path) = find_executable_in_path("go").await {
                if let Ok((stdout, _stderr)) = execute_detection_command(&path, &["version"]).await
                {
                    let version = parse_go_version(&stdout);
                    eprintln!("✅ Found Go at: {}", path);
                    return PackageManagerInfo::available(
                        PackageManagerType::Go,
                        version,
                        Some(path),
                    );
                }
            }
        }
    }

    let error_msg = if cfg!(target_os = "windows") {
        "Go is not installed. Install from: https://go.dev/dl/ or run: winget install GoLang.Go"
            .to_string()
    } else {
        "Go is not installed. Run: sudo apt install golang-go (Debian/Ubuntu) or download from https://go.dev/dl/".to_string()
    };
    PackageManagerInfo::unavailable(PackageManagerType::Go, error_msg)
}

/// Detect pipx installation
async fn detect_pipx() -> PackageManagerInfo {
    // Try command first
    match execute_detection_command("pipx", &["--version"]).await {
        Ok((stdout, _stderr)) => {
            let version = parse_simple_version(&stdout);
            return PackageManagerInfo::available(PackageManagerType::Pipx, version, None);
        }
        Err(_) => {
            // Try dynamic search
            if let Some(path) = find_executable_in_path("pipx").await {
                if let Ok((stdout, _stderr)) =
                    execute_detection_command(&path, &["--version"]).await
                {
                    let version = parse_simple_version(&stdout);
                    eprintln!("✅ Found Pipx at: {}", path);
                    return PackageManagerInfo::available(
                        PackageManagerType::Pipx,
                        version,
                        Some(path),
                    );
                }
            }
        }
    }

    let error_msg = "pipx is not installed. Run: pip install --user pipx (then restart terminal) or python -m pip install --user pipx".to_string();
    PackageManagerInfo::unavailable(PackageManagerType::Pipx, error_msg)
}

/// Detect Cargo (Rust) installation
async fn detect_cargo() -> PackageManagerInfo {
    // Try command first
    match execute_detection_command("cargo", &["--version"]).await {
        Ok((stdout, _stderr)) => {
            let version = parse_simple_version(&stdout);
            return PackageManagerInfo::available(PackageManagerType::Cargo, version, None);
        }
        Err(_) => {
            // Try dynamic search
            if let Some(path) = find_executable_in_path("cargo").await {
                if let Ok((stdout, _stderr)) =
                    execute_detection_command(&path, &["--version"]).await
                {
                    let version = parse_simple_version(&stdout);
                    eprintln!("✅ Found Cargo at: {}", path);
                    return PackageManagerInfo::available(
                        PackageManagerType::Cargo,
                        version,
                        Some(path),
                    );
                }
            }
        }
    }

    let error_msg = if cfg!(target_os = "windows") {
        "Cargo is not installed. Install Rust from: https://rustup.rs/ or run: winget install Rustlang.Rustup".to_string()
    } else {
        "Cargo is not installed. Install Rust from: https://rustup.rs/ or run: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh".to_string()
    };
    PackageManagerInfo::unavailable(PackageManagerType::Cargo, error_msg)
}

/// Detect npm (Node.js) installation
async fn detect_npm() -> PackageManagerInfo {
    eprintln!("🔍 Detecting npm...");

    // On Windows, npm is npm.cmd (batch file), not npm.exe
    #[cfg(target_os = "windows")]
    let npm_cmd = "npm.cmd";

    #[cfg(not(target_os = "windows"))]
    let npm_cmd = "npm";

    // Try command first (with .cmd on Windows)
    match execute_detection_command(npm_cmd, &["--version"]).await {
        Ok((stdout, _stderr)) => {
            eprintln!("✅ npm command succeeded: {}", stdout.trim());
            let version = parse_simple_version(&stdout);
            return PackageManagerInfo::available(PackageManagerType::Npm, version, None);
        }
        Err(e) => {
            eprintln!("⚠️  {} command failed: {}", npm_cmd, e);

            // On Windows, also try without .cmd as fallback
            #[cfg(target_os = "windows")]
            {
                if let Ok((stdout, _stderr)) =
                    execute_detection_command("npm", &["--version"]).await
                {
                    eprintln!("✅ npm (without .cmd) succeeded: {}", stdout.trim());
                    let version = parse_simple_version(&stdout);
                    return PackageManagerInfo::available(PackageManagerType::Npm, version, None);
                }
            }

            // Try dynamic search
            if let Some(path) = find_executable_in_path("npm").await {
                eprintln!("🔍 Trying npm at: {}", path);
                if let Ok((stdout, _stderr)) =
                    execute_detection_command(&path, &["--version"]).await
                {
                    let version = parse_simple_version(&stdout);
                    eprintln!("✅ Found npm at: {}", path);
                    return PackageManagerInfo::available(
                        PackageManagerType::Npm,
                        version,
                        Some(path),
                    );
                }
            }
        }
    }

    eprintln!("❌ npm not detected");
    let error_msg = if cfg!(target_os = "windows") {
        "npm is not installed. Install Node.js from: https://nodejs.org/ or run: winget install OpenJS.NodeJS".to_string()
    } else {
        "npm is not installed. Install Node.js from: https://nodejs.org/ or run: sudo apt install nodejs npm (Debian/Ubuntu)".to_string()
    };
    PackageManagerInfo::unavailable(PackageManagerType::Npm, error_msg)
}

/// Detect gem (Ruby) installation
async fn detect_gem() -> PackageManagerInfo {
    eprintln!("🔍 Detecting gem...");

    // On Windows, gem is gem.cmd or gem.bat (batch file), not gem.exe
    #[cfg(target_os = "windows")]
    let gem_cmd = "gem.cmd";

    #[cfg(not(target_os = "windows"))]
    let gem_cmd = "gem";

    // Try command first (with .cmd on Windows)
    match execute_detection_command(gem_cmd, &["--version"]).await {
        Ok((stdout, _stderr)) => {
            eprintln!("✅ gem command succeeded: {}", stdout.trim());
            let version = parse_simple_version(&stdout);
            return PackageManagerInfo::available(PackageManagerType::Gem, version, None);
        }
        Err(e) => {
            eprintln!("⚠️  {} command failed: {}", gem_cmd, e);

            // On Windows, also try gem.bat and gem without extension as fallback
            #[cfg(target_os = "windows")]
            {
                if let Ok((stdout, _stderr)) =
                    execute_detection_command("gem.bat", &["--version"]).await
                {
                    eprintln!("✅ gem.bat succeeded: {}", stdout.trim());
                    let version = parse_simple_version(&stdout);
                    return PackageManagerInfo::available(PackageManagerType::Gem, version, None);
                }

                if let Ok((stdout, _stderr)) =
                    execute_detection_command("gem", &["--version"]).await
                {
                    eprintln!("✅ gem (without extension) succeeded: {}", stdout.trim());
                    let version = parse_simple_version(&stdout);
                    return PackageManagerInfo::available(PackageManagerType::Gem, version, None);
                }
            }

            // Try dynamic search
            if let Some(path) = find_executable_in_path("gem").await {
                eprintln!("🔍 Trying gem at: {}", path);
                if let Ok((stdout, _stderr)) =
                    execute_detection_command(&path, &["--version"]).await
                {
                    let version = parse_simple_version(&stdout);
                    eprintln!("✅ Found gem at: {}", path);
                    return PackageManagerInfo::available(
                        PackageManagerType::Gem,
                        version,
                        Some(path),
                    );
                }
            }
        }
    }

    eprintln!("❌ gem not detected");
    let error_msg = if cfg!(target_os = "windows") {
        "gem is not installed. Install Ruby from: https://rubyinstaller.org/ or run: winget install RubyInstallerTeam.Ruby".to_string()
    } else {
        "gem is not installed. Install Ruby from: https://www.ruby-lang.org/ or run: sudo apt install ruby-full (Debian/Ubuntu)".to_string()
    };
    PackageManagerInfo::unavailable(PackageManagerType::Gem, error_msg)
}

/// Detect APT installation (Debian/Ubuntu/Kali)
async fn detect_apt() -> PackageManagerInfo {
    // APT is Linux-only
    #[cfg(not(target_os = "linux"))]
    {
        PackageManagerInfo::unavailable(
            PackageManagerType::Apt,
            "APT is only available on Linux".to_string(),
        )
    }

    #[cfg(target_os = "linux")]
    {
        // Try command first
        match execute_detection_command("apt", &["--version"]).await {
            Ok((stdout, _stderr)) => {
                let version = parse_apt_version(&stdout);
                return PackageManagerInfo::available(PackageManagerType::Apt, version, None);
            }
            Err(_) => {
                // Try dynamic search
                if let Some(path) = find_executable_in_path("apt").await {
                    if let Ok((stdout, _stderr)) =
                        execute_detection_command(&path, &["--version"]).await
                    {
                        let version = parse_apt_version(&stdout);
                        eprintln!("✅ Found APT at: {}", path);
                        return PackageManagerInfo::available(
                            PackageManagerType::Apt,
                            version,
                            Some(path),
                        );
                    }
                }
            }
        }

        PackageManagerInfo::unavailable(
            PackageManagerType::Apt,
            "APT is not available on this system".to_string(),
        )
    }
}

/// Detect WinGet installation (Windows)
async fn detect_winget() -> PackageManagerInfo {
    // WinGet is Windows-only
    #[cfg(not(target_os = "windows"))]
    {
        PackageManagerInfo::unavailable(
            PackageManagerType::WinGet,
            "WinGet is only available on Windows".to_string(),
        )
    }

    #[cfg(target_os = "windows")]
    {
        // Strategy: Search dynamically across all common locations
        let search_locations = get_windows_executable_search_paths("winget.exe");

        // Try each location until we find a working winget
        for path in &search_locations {
            if let Ok((stdout, _stderr)) = execute_detection_command(path, &["--version"]).await {
                let version = parse_simple_version(&stdout);
                eprintln!("✅ Found WinGet at: {}", path);
                return PackageManagerInfo::available(
                    PackageManagerType::WinGet,
                    version,
                    Some(path.clone()),
                );
            }
        }

        // If direct paths didn't work, try using 'which' command (if available)
        if let Some(path) = find_executable_in_path("winget").await {
            if let Ok((stdout, _stderr)) = execute_detection_command(&path, &["--version"]).await {
                let version = parse_simple_version(&stdout);
                eprintln!("✅ Found WinGet in PATH: {}", path);
                return PackageManagerInfo::available(
                    PackageManagerType::WinGet,
                    version,
                    Some(path),
                );
            }
        }

        // Last resort: Check if App Installer package is installed
        let check_cmd = "powershell";
        let check_args = vec![
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-AppxPackage Microsoft.DesktopAppInstaller | Select-Object -ExpandProperty Version",
        ];

        if let Ok((stdout, _stderr)) = execute_detection_command(check_cmd, &check_args).await {
            if !stdout.trim().is_empty() {
                let version = parse_simple_version(&stdout);
                eprintln!(
                    "ℹ️  WinGet package detected but executable not found in common locations"
                );
                return PackageManagerInfo::available(
                    PackageManagerType::WinGet,
                    version,
                    Some("WinGet is installed but path not resolved. Try running from a regular terminal.".to_string())
                );
            }
        }

        // WinGet not found
        let error_msg = "WinGet is not installed. Install 'App Installer' from Microsoft Store or update Windows 10/11 to the latest version.".to_string();
        PackageManagerInfo::unavailable(PackageManagerType::WinGet, error_msg)
    }
}

/// Execute a command with timeout for detection
pub async fn execute_detection_command(
    command: &str,
    args: &[&str],
) -> Result<(String, String), String> {
    let timeout_duration = Duration::from_secs(5);

    // Spawn the command
    let output_future = tokio::task::spawn_blocking({
        let command = command.to_string();
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        move || {
            let mut cmd = hidden_std_command(&command);
            cmd.args(&args);
            cmd.output()
                .map_err(|e| format!("Failed to execute {}: {}", command, e))
        }
    });

    // Wait with timeout
    match timeout(timeout_duration, output_future).await {
        Ok(Ok(Ok(output))) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            if output.status.success() || !stdout.is_empty() || !stderr.is_empty() {
                Ok((stdout, stderr))
            } else {
                Err(format!("{} command failed", command))
            }
        }
        Ok(Ok(Err(e))) => Err(e),
        Ok(Err(_)) => Err(format!("{} detection task panicked", command)),
        Err(_) => Err(format!("{} detection timed out (5s)", command)),
    }
}

/// Parse Go version from output
fn parse_go_version(output: &str) -> Option<String> {
    // Example: "go version go1.21.0 windows/amd64"
    output
        .split_whitespace()
        .find(|s| s.starts_with("go1."))
        .map(|s| s.trim_start_matches("go").to_string())
}

/// Parse APT version from output
#[allow(dead_code)]
fn parse_apt_version(output: &str) -> Option<String> {
    // Example: "apt 2.4.8 (amd64)"
    output
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1).map(|v| v.to_string()))
}

/// Parse simple version from output (just get first numeric version)
fn parse_simple_version(output: &str) -> Option<String> {
    // Find first thing that looks like a version (e.g., "1.2.0", "v1.6.2721")
    let version_regex = regex::Regex::new(r"v?(\d+\.\d+(?:\.\d+)?)").ok()?;
    version_regex
        .captures(output)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

/// Get common search paths for Windows executables
/// Returns a list of potential paths where the executable might be located
#[allow(dead_code)]
fn get_windows_executable_search_paths(exe_name: &str) -> Vec<String> {
    let mut paths = Vec::new();

    // 1. Current directory
    paths.push(format!("./{}", exe_name));

    // 2. LOCALAPPDATA paths
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        // WindowsApps (where WinGet, modern apps are installed)
        paths.push(format!(
            r"{}\Microsoft\WindowsApps\{}",
            local_appdata, exe_name
        ));

        // Programs folder
        paths.push(format!(r"{}\Programs\{}", local_appdata, exe_name));
    }

    // 3. APPDATA paths
    if let Ok(appdata) = std::env::var("APPDATA") {
        paths.push(format!(r"{}\{}", appdata, exe_name));

        // npm global modules
        paths.push(format!(r"{}\npm\{}", appdata, exe_name));
    }

    // 4. ProgramFiles paths
    if let Ok(program_files) = std::env::var("PROGRAMFILES") {
        paths.push(format!(r"{}\{}", program_files, exe_name));

        // Git
        paths.push(format!(r"{}\Git\cmd\{}", program_files, exe_name));
        paths.push(format!(r"{}\Git\bin\{}", program_files, exe_name));
        paths.push(format!(r"{}\Git\usr\bin\{}", program_files, exe_name));

        // Go
        paths.push(format!(r"{}\Go\bin\{}", program_files, exe_name));

        // Node.js
        paths.push(format!(r"{}\nodejs\{}", program_files, exe_name));
    }

    // 5. ProgramFiles(x86) paths
    if let Ok(program_files_x86) = std::env::var("PROGRAMFILES(X86)") {
        paths.push(format!(r"{}\{}", program_files_x86, exe_name));
    }

    // 6. USERPROFILE paths
    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        // Scoop
        paths.push(format!(r"{}\scoop\shims\{}", user_profile, exe_name));
        paths.push(format!(
            r"{}\scoop\apps\{}\current\{}",
            user_profile,
            exe_name.trim_end_matches(".exe"),
            exe_name
        ));

        // Chocolatey
        paths.push(format!(r"{}\.chocolatey\bin\{}", user_profile, exe_name));

        // Local bin directories
        paths.push(format!(r"{}\.local\bin\{}", user_profile, exe_name));
        paths.push(format!(r"{}\bin\{}", user_profile, exe_name));

        // Go bin
        paths.push(format!(r"{}\go\bin\{}", user_profile, exe_name));

        // Cargo bin
        paths.push(format!(r"{}\.cargo\bin\{}", user_profile, exe_name));

        // Ruby bin
        paths.push(format!(r"{}\.gem\bin\{}", user_profile, exe_name));
    }

    // 7. System paths
    paths.push(format!(r"C:\Windows\System32\{}", exe_name));
    paths.push(format!(r"C:\Windows\{}", exe_name));

    // 8. Chocolatey
    paths.push(format!(r"C:\ProgramData\chocolatey\bin\{}", exe_name));

    paths
}

/// Get common search paths for Unix-like executables (Linux/macOS)
fn get_unix_executable_search_paths(exe_name: &str) -> Vec<String> {
    let mut paths = Vec::new();

    // 1. Standard system paths
    paths.push(format!("/usr/local/bin/{}", exe_name));
    paths.push(format!("/usr/bin/{}", exe_name));
    paths.push(format!("/bin/{}", exe_name));
    paths.push(format!("/usr/local/sbin/{}", exe_name));
    paths.push(format!("/usr/sbin/{}", exe_name));
    paths.push(format!("/sbin/{}", exe_name));

    // 2. Homebrew paths (macOS)
    #[cfg(target_os = "macos")]
    {
        // Apple Silicon (M1/M2)
        paths.push(format!("/opt/homebrew/bin/{}", exe_name));
        paths.push(format!("/opt/homebrew/sbin/{}", exe_name));

        // Intel Macs
        paths.push(format!("/usr/local/bin/{}", exe_name));
        paths.push(format!("/usr/local/sbin/{}", exe_name));

        // MacPorts
        paths.push(format!("/opt/local/bin/{}", exe_name));
        paths.push(format!("/opt/local/sbin/{}", exe_name));
    }

    // 3. Linuxbrew
    #[cfg(target_os = "linux")]
    {
        paths.push(format!("/home/linuxbrew/.linuxbrew/bin/{}", exe_name));

        // Snap
        paths.push(format!("/snap/bin/{}", exe_name));
    }

    // 4. User home directory paths
    if let Ok(home) = std::env::var("HOME") {
        paths.push(format!("{}/.local/bin/{}", home, exe_name));
        paths.push(format!("{}/bin/{}", home, exe_name));

        // Go
        paths.push(format!("{}/go/bin/{}", home, exe_name));

        // Cargo (Rust)
        paths.push(format!("{}/.cargo/bin/{}", home, exe_name));

        // Ruby gems
        paths.push(format!("{}/.gem/bin/{}", home, exe_name));

        // npm global
        paths.push(format!("{}/.npm-global/bin/{}", home, exe_name));

        // Homebrew on Linux
        #[cfg(target_os = "linux")]
        paths.push(format!("{}/.linuxbrew/bin/{}", home, exe_name));
    }

    paths
}

/// Dynamically find an executable by searching common locations
/// Returns the full path if found, None otherwise
pub async fn find_executable_in_path(exe_name: &str) -> Option<String> {
    // Try using 'which' command first (Unix-like systems)
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok((stdout, _)) = execute_detection_command("which", &[exe_name]).await {
            let path = stdout.trim();
            if !path.is_empty() && std::path::Path::new(path).exists() {
                return Some(path.to_string());
            }
        }
    }

    // Try using 'where' command on Windows
    #[cfg(target_os = "windows")]
    {
        if let Ok((stdout, _)) = execute_detection_command("where", &[exe_name]).await {
            // 'where' returns multiple lines if multiple instances found
            // We want the first one
            if let Some(first_line) = stdout.lines().next() {
                let path = first_line.trim();
                if !path.is_empty() && std::path::Path::new(path).exists() {
                    return Some(path.to_string());
                }
            }
        }
    }

    // Fallback: Search through PATH environment variable manually
    if let Ok(path_var) = std::env::var("PATH") {
        let separator = if cfg!(target_os = "windows") {
            ";"
        } else {
            ":"
        };

        for path_dir in path_var.split(separator) {
            let mut full_path = std::path::PathBuf::from(path_dir);
            full_path.push(exe_name);

            // On Windows, also try with .exe extension
            #[cfg(target_os = "windows")]
            {
                if !exe_name.to_lowercase().ends_with(".exe") {
                    let with_exe = format!("{}.exe", exe_name);
                    full_path.set_file_name(&with_exe);
                }
            }

            if full_path.exists() {
                if let Some(path_str) = full_path.to_str() {
                    return Some(path_str.to_string());
                }
            }
        }
    }

    // Final fallback: Check common installation locations
    #[cfg(target_os = "windows")]
    let search_paths = get_windows_executable_search_paths(exe_name);

    #[cfg(not(target_os = "windows"))]
    let search_paths = get_unix_executable_search_paths(exe_name);

    for path in search_paths {
        if std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }

    None
}

/// Get Homebrew prefix (authoritative source for installation location)
#[cfg(target_os = "macos")]
async fn get_homebrew_prefix() -> Result<String, String> {
    match execute_detection_command("brew", &["--prefix"]).await {
        Ok((stdout, _stderr)) => {
            let prefix = stdout.trim().to_string();
            if prefix.is_empty() {
                Err("brew --prefix returned empty result".to_string())
            } else {
                Ok(prefix)
            }
        }
        Err(e) => Err(format!("Failed to get Homebrew prefix: {}", e)),
    }
}

/// Detect macOS architecture for logging purposes only
#[cfg(target_os = "macos")]
async fn detect_macos_architecture() -> String {
    match execute_detection_command("uname", &["-m"]).await {
        Ok((stdout, _stderr)) => {
            let arch = stdout.trim().to_string();
            match arch.as_str() {
                "arm64" => "arm64".to_string(),
                "x86_64" => "x86_64".to_string(),
                _ => "unknown".to_string(),
            }
        }
        Err(_) => "unknown".to_string(),
    }
}

/// Detect Homebrew installation (macOS only)
#[cfg(target_os = "macos")]
async fn detect_homebrew() -> PackageManagerInfo {
    // Try command first
    match execute_detection_command("brew", &["--version"]).await {
        Ok((stdout, _stderr)) => {
            let version = parse_simple_version(&stdout);

            // Get Homebrew prefix (authoritative source)
            let prefix = get_homebrew_prefix()
                .await
                .unwrap_or_else(|_| "/opt/homebrew".to_string());

            // Architecture detection for logging only (don't block on mismatches)
            let arch = detect_macos_architecture().await;
            let expected_prefix = match arch.as_str() {
                "arm64" => "/opt/homebrew",
                "x86_64" => "/usr/local",
                _ => "/opt/homebrew",
            };

            // Warn if prefix doesn't match expectations, but don't block
            if prefix != expected_prefix {
                eprintln!(
                    "⚠️  Homebrew prefix {} doesn't match expected {} for {}. This is usually fine.",
                    prefix, expected_prefix, arch
                );
            }

            return PackageManagerInfo::available(
                PackageManagerType::Homebrew,
                version,
                None, // We don't need the path for detection, just availability
            );
        }
        Err(_) => {
            // Try dynamic search
            if let Some(path) = find_executable_in_path("brew").await {
                if let Ok((stdout, _stderr)) =
                    execute_detection_command(&path, &["--version"]).await
                {
                    let version = parse_simple_version(&stdout);
                    eprintln!("✅ Found Homebrew at: {}", path);
                    return PackageManagerInfo::available(
                        PackageManagerType::Homebrew,
                        version,
                        Some(path),
                    );
                }
            }
        }
    }

    PackageManagerInfo::unavailable(
        PackageManagerType::Homebrew,
        "Homebrew not found. Visit https://brew.sh for installation".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_go_version() {
        assert_eq!(
            parse_go_version("go version go1.21.0 windows/amd64"),
            Some("1.21.0".to_string())
        );
        assert_eq!(
            parse_go_version("go version go1.20.3 linux/amd64"),
            Some("1.20.3".to_string())
        );
    }

    #[test]
    fn test_parse_apt_version() {
        assert_eq!(
            parse_apt_version("apt 2.4.8 (amd64)"),
            Some("2.4.8".to_string())
        );
    }

    #[test]
    fn test_parse_simple_version() {
        assert_eq!(
            parse_simple_version("v1.6.2721"),
            Some("1.6.2721".to_string())
        );
        assert_eq!(parse_simple_version("1.2.0"), Some("1.2.0".to_string()));
        assert_eq!(
            parse_simple_version("pipx 1.4.3"),
            Some("1.4.3".to_string())
        );
    }

    #[tokio::test]
    async fn test_detect_all_managers() {
        let managers = detect_all_managers().await;
        assert_eq!(managers.len(), 8); // go, pipx, cargo, npm, gem, apt, winget, homebrew

        // At least one should be available (depending on platform)
        // On development machines, usually Go or Python/pipx is available
        eprintln!("Detected managers:");
        for manager in &managers {
            eprintln!(
                "  - {:?}: available={}, version={:?}",
                manager.manager_type, manager.available, manager.version
            );
        }
    }
}
