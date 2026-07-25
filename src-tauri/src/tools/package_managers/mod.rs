// Package manager module for tool installation
//
// This module provides detection and management of various package managers
// used to install security tools across different platforms.

pub mod apt_manager;
pub mod cargo_installer;
pub mod detection;
pub mod elevation;
pub mod elevation_helper;
pub mod gem_installer;
pub mod git_pip_installer;
pub mod go_install;
pub mod homebrew_manager;
pub mod homebrew_registry;
pub mod installation;
pub mod manual_installer;
pub mod npm_installer;
pub mod pipx_manager;
pub mod update_checker;
pub mod version;
pub mod version_checker;
pub mod winget_manager;

pub use apt_manager::AptManager;
pub use cargo_installer::CargoInstaller;
pub use detection::{detect_all_managers, detect_manager, PackageManagerInfo};
pub use elevation::{
    check_elevation_support, execute_elevated, execute_with_smart_elevation, ElevationMethod,
    ElevationResult,
};
pub use gem_installer::GemInstaller;
pub use git_pip_installer::GitPipInstaller;
pub use go_install::GoInstallManager;
pub use homebrew_manager::HomebrewManager;
pub use homebrew_registry::get_homebrew_mapping;
pub use installation::{install_pipx, InstallationResult};
pub use manual_installer::ManualInstaller;
pub use npm_installer::NpmInstaller;
pub use pipx_manager::PipxManager;
pub use update_checker::{UpdateCheckerConfig, UpdateCheckerCoordinator, UpdateCheckerFactory};
pub use version_checker::{
    check_apt_update, check_go_update, check_pipx_update, VersionCheckResult,
};
pub use winget_manager::WingetManager;

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
    /// Homebrew - macOS package manager
    Homebrew,
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
            Self::Homebrew => "Homebrew",
        }
    }

    /// Get the command name for the package manager
    #[allow(dead_code)]
    pub fn command_name(&self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Pipx => "pipx",
            Self::Apt => "apt",
            Self::WinGet => "winget",
            Self::Cargo => "cargo",
            Self::Npm => "npm",
            Self::Gem => "gem",
            Self::Homebrew => "brew",
        }
    }

    /// Get the color badge for UI display
    #[allow(dead_code)]
    pub fn badge_color(&self) -> &'static str {
        match self {
            Self::Go => "green",        // 🟢 Primary method
            Self::Pipx => "yellow",     // 🟡 Python tools
            Self::Apt => "blue",        // 🔵 System packages
            Self::WinGet => "blue",     // 🔵 System packages
            Self::Cargo => "orange",    // 🟠 Rust tools
            Self::Npm => "red",         // 🔴 Node tools
            Self::Gem => "red",         // 🔴 Ruby tools
            Self::Homebrew => "orange", // 🟠 macOS orange
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
        assert_eq!(PackageManagerType::Homebrew.display_name(), "Homebrew");
    }

    #[test]
    fn test_package_manager_commands() {
        assert_eq!(PackageManagerType::Go.command_name(), "go");
        assert_eq!(PackageManagerType::Pipx.command_name(), "pipx");
        assert_eq!(PackageManagerType::Homebrew.command_name(), "brew");
    }

    #[test]
    fn test_badge_colors() {
        assert_eq!(PackageManagerType::Go.badge_color(), "green");
        assert_eq!(PackageManagerType::Pipx.badge_color(), "yellow");
        assert_eq!(PackageManagerType::Apt.badge_color(), "blue");
        assert_eq!(PackageManagerType::Homebrew.badge_color(), "orange");
    }
}
