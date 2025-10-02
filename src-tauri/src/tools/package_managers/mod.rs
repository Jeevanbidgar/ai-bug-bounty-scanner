// Package manager module for tool installation
//
// This module provides detection and management of various package managers
// used to install security tools across different platforms.

pub mod detection;
pub mod version;
pub mod installation;
pub mod elevation;
pub mod go_install;
pub mod version_checker;
pub mod pipx_manager;
pub mod apt_manager;
pub mod winget_manager;

pub use detection::{PackageManagerInfo, detect_all_managers, detect_manager};
pub use installation::{InstallationResult, install_pipx, install_go_windows, install_winget_windows};
pub use elevation::{ElevationMethod, ElevationResult, execute_with_smart_elevation, execute_elevated, check_elevation_support};
pub use go_install::GoInstallManager;
pub use pipx_manager::PipxManager;
pub use apt_manager::AptManager;
pub use winget_manager::WingetManager;
pub use version_checker::{
    VersionCheckResult, 
    check_go_update, 
    check_apt_update, 
    check_winget_update, 
    check_pipx_update
};

#[cfg(target_os = "linux")]
pub use installation::install_apt_package;

use serde::{Deserialize, Serialize};

/// Supported package managers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageManagerType {
    /// Go install - works identically on Windows and Linux
    Go,
    /// pipx - Python CLI tool installer
    Pipx,
    /// APT - Debian/Ubuntu/Kali package manager
    Apt,
    /// WinGet - Windows package manager
    WinGet,
    /// Cargo - Rust package manager (future)
    Cargo,
    /// npm - Node.js package manager (future)
    Npm,
    /// Ruby gems (future)
    Gem,
}

impl PackageManagerType {
    /// Get the display name for the package manager
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Go => "go install",
            Self::Pipx => "pipx",
            Self::Apt => "APT",
            Self::WinGet => "WinGet",
            Self::Cargo => "cargo",
            Self::Npm => "npm",
            Self::Gem => "gem",
        }
    }

    /// Get the command name for the package manager
    pub fn command_name(&self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Pipx => "pipx",
            Self::Apt => "apt",
            Self::WinGet => "winget",
            Self::Cargo => "cargo",
            Self::Npm => "npm",
            Self::Gem => "gem",
        }
    }

    /// Get the color badge for UI display
    pub fn badge_color(&self) -> &'static str {
        match self {
            Self::Go => "green",       // 🟢 Primary method
            Self::Pipx => "yellow",    // 🟡 Python tools
            Self::Apt => "blue",       // 🔵 System packages
            Self::WinGet => "blue",    // 🔵 System packages
            Self::Cargo => "orange",   // 🟠 Rust tools
            Self::Npm => "red",        // 🔴 Node tools
            Self::Gem => "red",        // 🔴 Ruby tools
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_manager_display_names() {
        assert_eq!(PackageManagerType::Go.display_name(), "go install");
        assert_eq!(PackageManagerType::Pipx.display_name(), "pipx");
        assert_eq!(PackageManagerType::Apt.display_name(), "APT");
        assert_eq!(PackageManagerType::WinGet.display_name(), "WinGet");
    }

    #[test]
    fn test_package_manager_commands() {
        assert_eq!(PackageManagerType::Go.command_name(), "go");
        assert_eq!(PackageManagerType::Pipx.command_name(), "pipx");
    }

    #[test]
    fn test_badge_colors() {
        assert_eq!(PackageManagerType::Go.badge_color(), "green");
        assert_eq!(PackageManagerType::Pipx.badge_color(), "yellow");
        assert_eq!(PackageManagerType::Apt.badge_color(), "blue");
    }
}
