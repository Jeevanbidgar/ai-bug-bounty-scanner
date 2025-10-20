// Update Checker Adapters
//
// Package manager-specific implementations of the UpdateChecker trait

pub mod go_adapter;
pub mod npm_adapter;
pub mod pipx_adapter;
pub mod apt_adapter;
pub mod winget_adapter;
pub mod homebrew_adapter;
pub mod gem_adapter;
pub mod cargo_adapter;

pub use go_adapter::GoUpdateChecker;
pub use npm_adapter::NpmUpdateChecker;
pub use pipx_adapter::PipxUpdateChecker;
pub use apt_adapter::AptUpdateChecker;
pub use winget_adapter::WingetUpdateChecker;
pub use homebrew_adapter::HomebrewUpdateChecker;
pub use gem_adapter::GemUpdateChecker;
pub use cargo_adapter::CargoUpdateChecker;
