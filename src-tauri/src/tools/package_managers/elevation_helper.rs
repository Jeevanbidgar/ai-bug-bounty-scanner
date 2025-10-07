/// Helper for privilege elevation with GUI support on Linux
/// 
/// This module provides utilities for running commands with elevated privileges.
/// On Linux, it prefers pkexec (GUI password dialog) over sudo (terminal prompt).
/// 
/// Usage:
/// ```rust
/// use crate::tools::package_managers::elevation_helper::ElevationHelper;
/// 
/// let helper = ElevationHelper::new();
/// let (cmd, args) = helper.elevate_command(&["apt", "install", "-y", "package"]).await;
/// ```

use tokio::process::Command;

pub struct ElevationHelper;

impl ElevationHelper {
    pub fn new() -> Self {
        Self
    }

    /// Check if pkexec is available (for GUI password prompt)
    pub async fn is_pkexec_available(&self) -> bool {
        match Command::new("pkexec").arg("--version").output().await {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    /// Get the appropriate elevation command and arguments
    /// 
    /// Returns: (command, arguments)
    /// - On Linux with pkexec: ("pkexec", ["apt", "install", "package"])
    /// - On Linux without pkexec: ("sudo", ["apt", "install", "package"])
    /// - On other platforms: returns input as-is
    pub async fn elevate_command(&self, args: &[&str]) -> (String, Vec<String>) {
        #[cfg(target_os = "linux")]
        {
            if self.is_pkexec_available().await {
                (
                    "pkexec".to_string(),
                    args.iter().map(|s| s.to_string()).collect(),
                )
            } else {
                (
                    "sudo".to_string(),
                    args.iter().map(|s| s.to_string()).collect(),
                )
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            // On non-Linux, no elevation needed or use platform-specific method
            (
                args[0].to_string(),
                args[1..].iter().map(|s| s.to_string()).collect(),
            )
        }
    }

    /// Get a message describing which elevation method will be used
    pub async fn get_elevation_message(&self) -> &'static str {
        #[cfg(target_os = "linux")]
        {
            if self.is_pkexec_available().await {
                "🔐 Using pkexec (GUI password dialog will appear)...\n"
            } else {
                "⚠️  Using sudo (password prompt in terminal)...\n"
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            "Running command with appropriate privileges...\n"
        }
    }
}
