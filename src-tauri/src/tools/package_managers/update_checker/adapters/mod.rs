// Update Checker Adapters
//
// Package manager-specific implementations of the UpdateChecker trait

#[cfg(target_os = "linux")]
pub mod apt_adapter;
pub mod cargo_adapter;
pub mod gem_adapter;
pub mod go_adapter;
pub mod homebrew_adapter;
pub mod npm_adapter;
pub mod pipx_adapter;
#[cfg(target_os = "windows")]
pub mod winget_adapter;

#[cfg(target_os = "linux")]
pub use apt_adapter::AptUpdateChecker;
pub use cargo_adapter::CargoUpdateChecker;
pub use gem_adapter::GemUpdateChecker;
pub use go_adapter::GoUpdateChecker;
pub use homebrew_adapter::HomebrewUpdateChecker;
pub use npm_adapter::NpmUpdateChecker;
pub use pipx_adapter::PipxUpdateChecker;
#[cfg(target_os = "windows")]
pub use winget_adapter::WingetUpdateChecker;
