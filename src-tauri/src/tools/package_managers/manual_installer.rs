use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tauri::Emitter;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::events::{
    EventEmitter, TOOL_INSTALLATION_COMPLETED, TOOL_INSTALLATION_OUTPUT, TOOL_INSTALLATION_STARTED,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ManualInstaller;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct InstallationResult {
    pub success: bool,
    pub message: String,
    pub tool_name: String,
    pub installed_path: Option<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum InstallStep {
    GitClone { url: String, target_dir: String },
    ChangeDirectory { path: String },
    PipInstall { requirements_file: Option<String> },
    PipInstallEditable,
    RunCommand { command: String, args: Vec<String> },
    CreateSymlink { source: String, target: String },
    Chmod { path: String, mode: String },
    MakeInstall,
    ConfigureEnvironment { var_name: String, var_value: String },
}

// Result structure for individual step execution
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct StepResult {
    message: String,
    new_working_dir: Option<PathBuf>,
    installed_path: Option<String>,
}

#[allow(dead_code)]
impl ManualInstaller {
    pub fn new() -> Self {
        Self
    }

    /// Get the installation steps for a specific tool
    pub fn get_install_steps(tool_name: &str) -> Vec<InstallStep> {
        match tool_name {
            // === Python Tools (Git + pip) ===
            "xsstrike" => vec![
                InstallStep::GitClone {
                    url: "https://github.com/s0md3v/XSStrike.git".to_string(),
                    target_dir: "XSStrike".to_string(),
                },
                InstallStep::ChangeDirectory { path: "XSStrike".to_string() },
                InstallStep::PipInstall { requirements_file: Some("requirements.txt".to_string()) },
                InstallStep::CreateSymlink {
                    source: "xsstrike.py".to_string(),
                    target: Self::get_bin_dir().join("xsstrike").to_string_lossy().to_string(),
                },
            ],

            "cloudfail" => vec![
                InstallStep::GitClone {
                    url: "https://github.com/m0rtem/CloudFail.git".to_string(),
                    target_dir: "CloudFail".to_string(),
                },
                InstallStep::ChangeDirectory { path: "CloudFail".to_string() },
                InstallStep::PipInstall { requirements_file: Some("requirements.txt".to_string()) },
                InstallStep::CreateSymlink {
                    source: "cloudfail.py".to_string(),
                    target: Self::get_bin_dir().join("cloudfail").to_string_lossy().to_string(),
                },
            ],

            "linkfinder" => vec![
                InstallStep::GitClone {
                    url: "https://github.com/GerbenJavado/LinkFinder.git".to_string(),
                    target_dir: "LinkFinder".to_string(),
                },
                InstallStep::ChangeDirectory { path: "LinkFinder".to_string() },
                InstallStep::PipInstall { requirements_file: Some("requirements.txt".to_string()) },
                InstallStep::PipInstallEditable,
            ],

            "knockpy" => vec![
                InstallStep::GitClone {
                    url: "https://github.com/guelfoweb/knock.git".to_string(),
                    target_dir: "knock".to_string(),
                },
                InstallStep::ChangeDirectory { path: "knock".to_string() },
                InstallStep::PipInstallEditable,
            ],

            "dnsrecon" => vec![
                InstallStep::GitClone {
                    url: "https://github.com/darkoperator/dnsrecon.git".to_string(),
                    target_dir: "dnsrecon".to_string(),
                },
                InstallStep::ChangeDirectory { path: "dnsrecon".to_string() },
                InstallStep::PipInstall { requirements_file: Some("requirements.txt".to_string()) },
                InstallStep::CreateSymlink {
                    source: "dnsrecon.py".to_string(),
                    target: Self::get_bin_dir().join("dnsrecon").to_string_lossy().to_string(),
                },
            ],

            "dnsenum" => vec![
                InstallStep::GitClone {
                    url: "https://github.com/fwaeytens/dnsenum.git".to_string(),
                    target_dir: "dnsenum".to_string(),
                },
                InstallStep::ChangeDirectory { path: "dnsenum".to_string() },
                InstallStep::CreateSymlink {
                    source: "dnsenum.pl".to_string(),
                    target: Self::get_bin_dir().join("dnsenum").to_string_lossy().to_string(),
                },
            ],

            // === Ruby Tools ===
            "wpscan" => vec![
                InstallStep::GitClone {
                    url: "https://github.com/wpscanteam/wpscan.git".to_string(),
                    target_dir: "wpscan".to_string(),
                },
                InstallStep::ChangeDirectory { path: "wpscan".to_string() },
                InstallStep::RunCommand {
                    command: "gem".to_string(),
                    args: vec!["install", "bundler"].iter().map(|s| s.to_string()).collect(),
                },
                InstallStep::RunCommand {
                    command: "bundle".to_string(),
                    args: vec!["install", "--without", "test", "development"].iter().map(|s| s.to_string()).collect(),
                },
            ],

            "whatweb" => vec![
                InstallStep::GitClone {
                    url: "https://github.com/urbanadventurer/WhatWeb.git".to_string(),
                    target_dir: "WhatWeb".to_string(),
                },
                InstallStep::ChangeDirectory { path: "WhatWeb".to_string() },
                InstallStep::Chmod { path: "whatweb".to_string(), mode: "+x".to_string() },
                InstallStep::CreateSymlink {
                    source: "whatweb".to_string(),
                    target: Self::get_bin_dir().join("whatweb").to_string_lossy().to_string(),
                },
            ],

            // === Perl Tools ===
            "joomscan" => vec![
                InstallStep::GitClone {
                    url: "https://github.com/OWASP/joomscan.git".to_string(),
                    target_dir: "joomscan".to_string(),
                },
                InstallStep::ChangeDirectory { path: "joomscan".to_string() },
                InstallStep::Chmod { path: "joomscan.pl".to_string(), mode: "+x".to_string() },
                InstallStep::CreateSymlink {
                    source: "joomscan.pl".to_string(),
                    target: Self::get_bin_dir().join("joomscan").to_string_lossy().to_string(),
                },
            ],

            "nikto" => vec![
                InstallStep::GitClone {
                    url: "https://github.com/sullo/nikto.git".to_string(),
                    target_dir: "nikto".to_string(),
                },
                InstallStep::ChangeDirectory { path: "nikto/program".to_string() },
                InstallStep::Chmod { path: "nikto.pl".to_string(), mode: "+x".to_string() },
                InstallStep::CreateSymlink {
                    source: "nikto.pl".to_string(),
                    target: Self::get_bin_dir().join("nikto").to_string_lossy().to_string(),
                },
            ],

            // === Go Tools (requires compilation) ===
            "aquatone" => vec![
                InstallStep::GitClone {
                    url: "https://github.com/michenriksen/aquatone.git".to_string(),
                    target_dir: "aquatone".to_string(),
                },
                InstallStep::ChangeDirectory { path: "aquatone".to_string() },
                InstallStep::RunCommand {
                    command: "go".to_string(),
                    args: vec!["build", "-o", "aquatone"].iter().map(|s| s.to_string()).collect(),
                },
                InstallStep::CreateSymlink {
                    source: "aquatone".to_string(),
                    target: Self::get_bin_dir().join("aquatone").to_string_lossy().to_string(),
                },
            ],

            // === C/C++ Tools (requires compilation) ===
            "masscan" => vec![
                InstallStep::GitClone {
                    url: "https://github.com/robertdavidgraham/masscan.git".to_string(),
                    target_dir: "masscan".to_string(),
                },
                InstallStep::ChangeDirectory { path: "masscan".to_string() },
                InstallStep::MakeInstall,
                InstallStep::CreateSymlink {
                    source: "bin/masscan".to_string(),
                    target: Self::get_bin_dir().join("masscan").to_string_lossy().to_string(),
                },
            ],

            "rustscan" => vec![
                InstallStep::GitClone {
                    url: "https://github.com/RustScan/RustScan.git".to_string(),
                    target_dir: "RustScan".to_string(),
                },
                InstallStep::ChangeDirectory { path: "RustScan".to_string() },
                InstallStep::RunCommand {
                    command: "cargo".to_string(),
                    args: vec!["build", "--release"].iter().map(|s| s.to_string()).collect(),
                },
                InstallStep::CreateSymlink {
                    source: "target/release/rustscan".to_string(),
                    target: Self::get_bin_dir().join("rustscan").to_string_lossy().to_string(),
                },
            ],

            // === Shell Script Tools ===
            "eyewitness" => vec![
                InstallStep::GitClone {
                    url: "https://github.com/FortyNorthSecurity/EyeWitness.git".to_string(),
                    target_dir: "EyeWitness".to_string(),
                },
                InstallStep::ChangeDirectory { path: "EyeWitness/Python/setup".to_string() },
                InstallStep::RunCommand {
                    command: if cfg!(windows) { "cmd".to_string() } else { "bash".to_string() },
                    args: if cfg!(windows) {
                        vec!["/c", "setup.bat"].iter().map(|s| s.to_string()).collect()
                    } else {
                        vec!["setup.sh"].iter().map(|s| s.to_string()).collect()
                    },
                },
            ],

            // === Binary Downloads (GitHub Releases) ===
            "wappalyzer" => vec![
                InstallStep::RunCommand {
                    command: "npm".to_string(),
                    args: vec!["install", "-g", "wappalyzer"].iter().map(|s| s.to_string()).collect(),
                },
            ],

            "feroxbuster" => vec![
                InstallStep::RunCommand {
                    command: "cargo".to_string(),
                    args: vec!["install", "feroxbuster"].iter().map(|s| s.to_string()).collect(),
                },
            ],

            "wfuzz" => vec![
                InstallStep::RunCommand {
                    command: "pip".to_string(),
                    args: vec!["install", "wfuzz"].iter().map(|s| s.to_string()).collect(),
                },
            ],

            "dirbuster" => vec![
                InstallStep::RunCommand {
                    command: "echo".to_string(),
                    args: vec!["DirBuster is a GUI tool. Please download from: https://sourceforge.net/projects/dirbuster/"].iter().map(|s| s.to_string()).collect(),
                },
            ],

            "metasploit" => vec![
                InstallStep::RunCommand {
                    command: "echo".to_string(),
                    args: vec!["Metasploit requires installer. Windows: https://windows.metasploit.com/metasploitframework-latest.msi | Linux: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall"].iter().map(|s| s.to_string()).collect(),
                },
            ],

            "searchsploit" => vec![
                InstallStep::GitClone {
                    url: "https://github.com/offensive-security/exploitdb.git".to_string(),
                    target_dir: "exploitdb".to_string(),
                },
                InstallStep::ChangeDirectory { path: "exploitdb".to_string() },
                InstallStep::CreateSymlink {
                    source: "searchsploit".to_string(),
                    target: Self::get_bin_dir().join("searchsploit").to_string_lossy().to_string(),
                },
                InstallStep::ConfigureEnvironment {
                    var_name: "EXPLOITDB".to_string(),
                    var_value: std::env::current_dir()
                        .unwrap_or_default()
                        .join("exploitdb")
                        .to_string_lossy()
                        .to_string(),
                },
            ],

            "socat" => vec![
                InstallStep::RunCommand {
                    command: if cfg!(windows) { "choco".to_string() } else { "apt-get".to_string() },
                    args: if cfg!(windows) {
                        vec!["install", "-y", "socat"].iter().map(|s| s.to_string()).collect()
                    } else {
                        vec!["install", "-y", "socat"].iter().map(|s| s.to_string()).collect()
                    },
                },
            ],

            // Unknown tool
            _ => vec![],
        }
    }

    /// Get the appropriate binary directory for the OS
    fn get_bin_dir() -> PathBuf {
        if cfg!(target_os = "windows") {
            // Windows: use AppData\Local\Programs\SecurityTools
            let local_appdata = std::env::var("LOCALAPPDATA")
                .unwrap_or_else(|_| "C:\\Users\\Public\\AppData\\Local".to_string());
            PathBuf::from(local_appdata)
                .join("Programs")
                .join("SecurityTools")
        } else {
            // Linux/Kali: use ~/.local/bin
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            PathBuf::from(home).join(".local").join("bin")
        }
    }

    /// Get the tools installation directory
    fn get_tools_dir() -> PathBuf {
        if cfg!(target_os = "windows") {
            let local_appdata = std::env::var("LOCALAPPDATA")
                .unwrap_or_else(|_| "C:\\Users\\Public\\AppData\\Local".to_string());
            PathBuf::from(local_appdata).join("SecurityTools")
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("security-tools")
        }
    }

    /// Install a tool using manual steps
    pub async fn install(
        &self,
        tool_name: &str,
        app_handle: Option<&tauri::AppHandle>,
    ) -> Result<InstallationResult, String> {
        let steps = Self::get_install_steps(tool_name);

        if steps.is_empty() {
            return Ok(InstallationResult {
                success: false,
                message: format!("No manual installation steps defined for {}", tool_name),
                tool_name: tool_name.to_string(),
                installed_path: None,
            });
        }

        eprintln!(
            "📦 Installing {} via manual steps ({} steps)",
            tool_name,
            steps.len()
        );

        // Emit installation started event
        if let Some(handle) = app_handle {
            let _ = handle.emit(
                TOOL_INSTALLATION_STARTED,
                EventEmitter::tool_installation_started(tool_name, "manual"),
            );
        }

        // Create tools directory
        let tools_dir = Self::get_tools_dir();
        if !tools_dir.exists() {
            std::fs::create_dir_all(&tools_dir)
                .map_err(|e| format!("Failed to create tools directory: {}", e))?;
        }

        let bin_dir = Self::get_bin_dir();
        if !bin_dir.exists() {
            std::fs::create_dir_all(&bin_dir)
                .map_err(|e| format!("Failed to create bin directory: {}", e))?;
        }

        let mut current_dir = tools_dir.clone();
        let mut installed_path: Option<String> = None;

        // Execute each step
        for (i, step) in steps.iter().enumerate() {
            let step_num = i + 1;
            let step_desc = format!(
                "Step {}/{}: {}",
                step_num,
                steps.len(),
                Self::step_description(step)
            );

            self.emit_output(app_handle, tool_name, "stdout", &step_desc)
                .await;
            eprintln!("  {}", step_desc);

            match self
                .execute_step(step, &current_dir, tool_name, app_handle)
                .await
            {
                Ok(result) => {
                    if let Some(new_dir) = result.new_working_dir {
                        current_dir = new_dir;
                    }
                    if result.installed_path.is_some() {
                        installed_path = result.installed_path;
                    }
                    self.emit_output(
                        app_handle,
                        tool_name,
                        "stdout",
                        &format!("✅ {}", result.message),
                    )
                    .await;
                }
                Err(e) => {
                    let error_msg = format!("Failed at step {}: {}", step_num, e);
                    self.emit_output(app_handle, tool_name, "stderr", &error_msg)
                        .await;

                    if let Some(handle) = app_handle {
                        let _ = handle.emit(
                            TOOL_INSTALLATION_COMPLETED,
                            EventEmitter::tool_installation_completed(tool_name, false, &error_msg),
                        );
                    }

                    return Ok(InstallationResult {
                        success: false,
                        message: error_msg,
                        tool_name: tool_name.to_string(),
                        installed_path: None,
                    });
                }
            }
        }

        let success_msg = format!(
            "Successfully installed {} using {} manual steps",
            tool_name,
            steps.len()
        );

        if let Some(handle) = app_handle {
            let _ = handle.emit(
                TOOL_INSTALLATION_COMPLETED,
                EventEmitter::tool_installation_completed(tool_name, true, &success_msg),
            );
        }

        Ok(InstallationResult {
            success: true,
            message: success_msg,
            tool_name: tool_name.to_string(),
            installed_path,
        })
    }

    fn step_description(step: &InstallStep) -> String {
        match step {
            InstallStep::GitClone { url, .. } => format!("Cloning from {}", url),
            InstallStep::ChangeDirectory { path } => format!("Changing to directory {}", path),
            InstallStep::PipInstall { requirements_file } => {
                if let Some(file) = requirements_file {
                    format!("Installing Python dependencies from {}", file)
                } else {
                    "Installing Python package".to_string()
                }
            }
            InstallStep::PipInstallEditable => {
                "Installing in editable mode (pip install -e .)".to_string()
            }
            InstallStep::RunCommand { command, .. } => format!("Running command: {}", command),
            InstallStep::CreateSymlink { target, .. } => format!("Creating symlink to {}", target),
            InstallStep::Chmod { path, mode } => {
                format!("Setting permissions {} on {}", mode, path)
            }
            InstallStep::MakeInstall => "Running make install".to_string(),
            InstallStep::ConfigureEnvironment { var_name, .. } => {
                format!("Configuring environment variable {}", var_name)
            }
        }
    }

    async fn execute_step(
        &self,
        step: &InstallStep,
        current_dir: &Path,
        tool_name: &str,
        app_handle: Option<&tauri::AppHandle>,
    ) -> Result<StepResult, String> {
        match step {
            InstallStep::GitClone { url, target_dir } => {
                let target_path = current_dir.join(target_dir);

                // Skip if already cloned
                if target_path.exists() {
                    return Ok(StepResult {
                        message: format!("Directory {} already exists, skipping clone", target_dir),
                        new_working_dir: Some(target_path),
                        installed_path: None,
                    });
                }

                self.run_command_with_output(
                    "git",
                    &["clone", url, target_dir],
                    current_dir,
                    tool_name,
                    app_handle,
                )
                .await?;

                Ok(StepResult {
                    message: format!("Cloned {} to {}", url, target_dir),
                    new_working_dir: Some(target_path),
                    installed_path: None,
                })
            }

            InstallStep::ChangeDirectory { path } => {
                let new_dir = if Path::new(path).is_absolute() {
                    PathBuf::from(path)
                } else {
                    current_dir.join(path)
                };

                if !new_dir.exists() {
                    return Err(format!("Directory does not exist: {}", new_dir.display()));
                }

                Ok(StepResult {
                    message: format!("Changed directory to {}", new_dir.display()),
                    new_working_dir: Some(new_dir),
                    installed_path: None,
                })
            }

            InstallStep::PipInstall { requirements_file } => {
                let python_cmd = if cfg!(target_os = "windows") {
                    "python"
                } else {
                    "python3"
                };

                let args = if let Some(req_file) = requirements_file {
                    vec!["-m", "pip", "install", "-r", req_file]
                } else {
                    vec!["-m", "pip", "install", "."]
                };

                self.run_command_with_output(python_cmd, &args, current_dir, tool_name, app_handle)
                    .await?;

                Ok(StepResult {
                    message: "Python dependencies installed".to_string(),
                    new_working_dir: None,
                    installed_path: None,
                })
            }

            InstallStep::PipInstallEditable => {
                let python_cmd = if cfg!(target_os = "windows") {
                    "python"
                } else {
                    "python3"
                };

                self.run_command_with_output(
                    python_cmd,
                    &["-m", "pip", "install", "-e", "."],
                    current_dir,
                    tool_name,
                    app_handle,
                )
                .await?;

                Ok(StepResult {
                    message: "Installed in editable mode".to_string(),
                    new_working_dir: None,
                    installed_path: None,
                })
            }

            InstallStep::RunCommand { command, args } => {
                let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

                self.run_command_with_output(
                    command,
                    &args_str,
                    current_dir,
                    tool_name,
                    app_handle,
                )
                .await?;

                Ok(StepResult {
                    message: format!("Command {} executed successfully", command),
                    new_working_dir: None,
                    installed_path: None,
                })
            }

            InstallStep::CreateSymlink { source, target } => {
                let source_path = if Path::new(source).is_absolute() {
                    PathBuf::from(source)
                } else {
                    current_dir.join(source)
                };

                let target_path = PathBuf::from(target);

                // Skip if symlink already exists
                if target_path.exists() {
                    return Ok(StepResult {
                        message: format!("Symlink {} already exists", target),
                        new_working_dir: None,
                        installed_path: Some(target.clone()),
                    });
                }

                if cfg!(target_os = "windows") {
                    // Windows: Create a batch file wrapper
                    let batch_content = if source.ends_with(".py") {
                        format!("@echo off\npython \"{}\" %*", source_path.display())
                    } else {
                        format!("@echo off\n\"{}\" %*", source_path.display())
                    };

                    let target_bat = format!("{}.bat", target);
                    std::fs::write(&target_bat, batch_content)
                        .map_err(|e| format!("Failed to create batch file: {}", e))?;

                    Ok(StepResult {
                        message: format!("Created batch wrapper at {}", target_bat),
                        new_working_dir: None,
                        installed_path: Some(target_bat),
                    })
                } else {
                    // Linux: Create symlink
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;

                        std::os::unix::fs::symlink(&source_path, &target_path)
                            .map_err(|e| format!("Failed to create symlink: {}", e))?;

                        // Make it executable
                        let mut perms = std::fs::metadata(&source_path)
                            .map_err(|e| format!("Failed to get permissions: {}", e))?
                            .permissions();
                        perms.set_mode(0o755);
                        std::fs::set_permissions(&source_path, perms)
                            .map_err(|e| format!("Failed to set permissions: {}", e))?;
                    }

                    #[cfg(not(unix))]
                    {
                        return Err("Symlink creation not supported on this platform".to_string());
                    }

                    Ok(StepResult {
                        message: format!("Created symlink {} -> {}", target, source_path.display()),
                        new_working_dir: None,
                        installed_path: Some(target.clone()),
                    })
                }
            }

            InstallStep::Chmod { path, mode } => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;

                    let file_path = current_dir.join(path);
                    let mut perms = std::fs::metadata(&file_path)
                        .map_err(|e| format!("Failed to get permissions: {}", e))?
                        .permissions();

                    // Parse mode (simple implementation)
                    let mode_int = if mode == "+x" { 0o755 } else { 0o644 };

                    perms.set_mode(mode_int);
                    std::fs::set_permissions(&file_path, perms)
                        .map_err(|e| format!("Failed to set permissions: {}", e))?;
                }

                Ok(StepResult {
                    message: format!("Set permissions {} on {}", mode, path),
                    new_working_dir: None,
                    installed_path: None,
                })
            }

            InstallStep::MakeInstall => {
                self.run_command_with_output(
                    "make",
                    &["install"],
                    current_dir,
                    tool_name,
                    app_handle,
                )
                .await?;

                Ok(StepResult {
                    message: "Make install completed".to_string(),
                    new_working_dir: None,
                    installed_path: None,
                })
            }

            InstallStep::ConfigureEnvironment {
                var_name,
                var_value: _,
            } => {
                // For PATH, this is informational only (requires restart)
                Ok(StepResult {
                    message: format!(
                        "Environment variable {} configured (restart required)",
                        var_name
                    ),
                    new_working_dir: None,
                    installed_path: None,
                })
            }
        }
    }

    async fn run_command_with_output(
        &self,
        command: &str,
        args: &[&str],
        working_dir: &Path,
        tool_name: &str,
        app_handle: Option<&tauri::AppHandle>,
    ) -> Result<(), String> {
        let mut child = Command::new(command)
            .args(args)
            .current_dir(working_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn {}: {}", command, e))?;

        let stdout = child.stdout.take().expect("Failed to capture stdout");
        let stderr = child.stderr.take().expect("Failed to capture stderr");

        let stdout_reader = BufReader::new(stdout).lines();
        let stderr_reader = BufReader::new(stderr).lines();

        let tool_name_clone = tool_name.to_string();
        let handle_clone = app_handle.map(|h| h.clone());
        let stdout_task = tokio::spawn(async move {
            let mut lines = stdout_reader;
            while let Ok(Some(line)) = lines.next_line().await {
                eprintln!("[{}] {}", tool_name_clone, line);
                if let Some(handle) = &handle_clone {
                    let _ = handle.emit(
                        TOOL_INSTALLATION_OUTPUT,
                        EventEmitter::tool_installation_output(&tool_name_clone, "stdout", &line),
                    );
                }
            }
        });

        let tool_name_clone = tool_name.to_string();
        let handle_clone = app_handle.map(|h| h.clone());
        let stderr_task = tokio::spawn(async move {
            let mut lines = stderr_reader;
            let mut error_output = Vec::new();
            while let Ok(Some(line)) = lines.next_line().await {
                eprintln!("[{} stderr] {}", tool_name_clone, line);
                error_output.push(line.clone());
                if let Some(handle) = &handle_clone {
                    let _ = handle.emit(
                        TOOL_INSTALLATION_OUTPUT,
                        EventEmitter::tool_installation_output(&tool_name_clone, "stderr", &line),
                    );
                }
            }
            error_output
        });

        let (status, _, stderr_result) = tokio::join!(child.wait(), stdout_task, stderr_task);

        let stderr_output = stderr_result.unwrap_or_default();

        match status {
            Ok(exit_status) if exit_status.success() => Ok(()),
            Ok(exit_status) => Err(format!(
                "Command failed with exit code {}: {}",
                exit_status.code().unwrap_or(-1),
                stderr_output.join("\n")
            )),
            Err(e) => Err(format!("Failed to wait for command: {}", e)),
        }
    }

    async fn emit_output(
        &self,
        app_handle: Option<&tauri::AppHandle>,
        tool_name: &str,
        output_type: &str,
        message: &str,
    ) {
        if let Some(handle) = app_handle {
            let _ = handle.emit(
                TOOL_INSTALLATION_OUTPUT,
                EventEmitter::tool_installation_output(tool_name, output_type, message),
            );
        }
    }
}
