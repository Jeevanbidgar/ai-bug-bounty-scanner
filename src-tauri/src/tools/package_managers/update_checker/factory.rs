// Update Checker Factory
//
// Factory for creating and configuring update checkers for different package managers

#[cfg(target_os = "linux")]
use super::adapters::AptUpdateChecker;
#[cfg(target_os = "macos")]
use super::adapters::HomebrewUpdateChecker;
#[cfg(target_os = "windows")]
use super::adapters::WingetUpdateChecker;
use super::adapters::{
    CargoUpdateChecker, GemUpdateChecker, GoUpdateChecker, NpmUpdateChecker, PipxUpdateChecker,
};
use super::command_runner::CommandRunner;
use super::traits::{UpdateChecker, UpdateCheckerConfig};

/// Factory for creating update checkers
pub struct UpdateCheckerFactory;

impl UpdateCheckerFactory {
    /// Create all available update checkers
    pub async fn create_all_checkers(config: &UpdateCheckerConfig) -> Vec<Box<dyn UpdateChecker>> {
        let command_runner = CommandRunner::new(config.default_timeout, config.debug_logging);
        let mut checkers: Vec<Box<dyn UpdateChecker>> = Vec::new();

        // Create real package manager checkers
        // Note: These will only be added if the package manager is available on the system

        // Go checker (high priority for Go tools)
        let go_checker = GoUpdateChecker::new(command_runner.clone());
        if go_checker.is_available().await {
            checkers.push(Box::new(go_checker) as Box<dyn UpdateChecker>);
        }

        // Pipx checker (high priority for Python CLI tools)
        let pipx_checker = PipxUpdateChecker::new(command_runner.clone());
        if pipx_checker.is_available().await {
            checkers.push(Box::new(pipx_checker) as Box<dyn UpdateChecker>);
        }

        // Homebrew checker (macOS only)
        #[cfg(target_os = "macos")]
        {
            let homebrew_checker = HomebrewUpdateChecker::new(command_runner.clone());
            if homebrew_checker.is_available().await {
                checkers.push(Box::new(homebrew_checker) as Box<dyn UpdateChecker>);
            }
        }

        // APT checker (Linux only)
        #[cfg(target_os = "linux")]
        {
            let apt_checker = AptUpdateChecker::new(command_runner.clone());
            if apt_checker.is_available().await {
                checkers.push(Box::new(apt_checker) as Box<dyn UpdateChecker>);
            }
        }

        // WinGet checker (Windows only)
        #[cfg(target_os = "windows")]
        {
            let winget_checker = WingetUpdateChecker::new(command_runner.clone());
            if winget_checker.is_available().await {
                checkers.push(Box::new(winget_checker) as Box<dyn UpdateChecker>);
            }
        }

        // NPM checker (medium priority)
        let npm_checker = NpmUpdateChecker::new(command_runner.clone());
        if npm_checker.is_available().await {
            checkers.push(Box::new(npm_checker) as Box<dyn UpdateChecker>);
        }

        // Gem checker (lower priority)
        let gem_checker = GemUpdateChecker::new(command_runner.clone());
        if gem_checker.is_available().await {
            checkers.push(Box::new(gem_checker) as Box<dyn UpdateChecker>);
        }

        // Cargo checker (lower priority)
        let cargo_checker = CargoUpdateChecker::new(command_runner.clone());
        if cargo_checker.is_available().await {
            checkers.push(Box::new(cargo_checker) as Box<dyn UpdateChecker>);
        }

        // Sort by priority (lower priority number = higher priority)
        checkers.sort_by_key(|c| c.priority());

        eprintln!("✅ Loaded {} package manager checkers", checkers.len());
        for checker in &checkers {
            eprintln!("   - {}", checker.manager_name());
        }

        checkers
    }

    /// Create a specific checker by name
    pub async fn create_checker_by_name(
        manager_name: &str,
        config: &UpdateCheckerConfig,
    ) -> Option<Box<dyn UpdateChecker>> {
        let command_runner = CommandRunner::new(config.default_timeout, config.debug_logging);

        let checker: Option<Box<dyn UpdateChecker>> = match manager_name {
            "go" => {
                let checker = GoUpdateChecker::new(command_runner.clone());
                if checker.is_available().await {
                    Some(Box::new(checker))
                } else {
                    None
                }
            }
            "pipx" => {
                let checker = PipxUpdateChecker::new(command_runner.clone());
                if checker.is_available().await {
                    Some(Box::new(checker))
                } else {
                    None
                }
            }
            "homebrew" => {
                #[cfg(target_os = "macos")]
                {
                    let checker = HomebrewUpdateChecker::new(command_runner.clone());
                    if checker.is_available().await {
                        Some(Box::new(checker))
                    } else {
                        None
                    }
                }
                #[cfg(not(target_os = "macos"))]
                {
                    None
                }
            }
            "apt" => {
                #[cfg(target_os = "linux")]
                {
                    let checker = AptUpdateChecker::new(command_runner.clone());
                    if checker.is_available().await {
                        Some(Box::new(checker))
                    } else {
                        None
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    None
                }
            }
            "winget" => {
                #[cfg(target_os = "windows")]
                {
                    let checker = WingetUpdateChecker::new(command_runner.clone());
                    if checker.is_available().await {
                        Some(Box::new(checker))
                    } else {
                        None
                    }
                }
                #[cfg(not(target_os = "windows"))]
                {
                    None
                }
            }
            "npm" => {
                let checker = NpmUpdateChecker::new(command_runner.clone());
                if checker.is_available().await {
                    Some(Box::new(checker))
                } else {
                    None
                }
            }
            "gem" => {
                let checker = GemUpdateChecker::new(command_runner.clone());
                if checker.is_available().await {
                    Some(Box::new(checker))
                } else {
                    None
                }
            }
            "cargo" => {
                let checker = CargoUpdateChecker::new(command_runner.clone());
                if checker.is_available().await {
                    Some(Box::new(checker))
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(ref checker) = checker {
            eprintln!("✅ Loaded checker: {}", checker.manager_name());
        } else {
            eprintln!("⚠️  Checker '{}' not available", manager_name);
        }

        checker
    }

    /// Get list of supported package managers
    pub fn supported_managers() -> Vec<&'static str> {
        vec![
            "go", "pipx", "homebrew", "apt", "winget", "npm", "gem", "cargo",
        ]
    }

    /// Get platform-specific managers
    pub fn platform_managers() -> Vec<&'static str> {
        let mut managers = vec!["go", "pipx", "npm", "gem", "cargo"];

        #[cfg(target_os = "macos")]
        managers.push("homebrew");

        #[cfg(target_os = "linux")]
        managers.push("apt");

        #[cfg(target_os = "windows")]
        managers.push("winget");

        managers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_managers() {
        let managers = UpdateCheckerFactory::supported_managers();
        assert!(managers.contains(&"go"));
        assert!(managers.contains(&"pipx"));
        assert!(managers.contains(&"npm"));
    }

    #[test]
    fn test_platform_managers() {
        let managers = UpdateCheckerFactory::platform_managers();
        assert!(managers.contains(&"go"));
        assert!(managers.contains(&"pipx"));

        #[cfg(target_os = "macos")]
        assert!(managers.contains(&"homebrew"));

        #[cfg(target_os = "linux")]
        assert!(managers.contains(&"apt"));

        #[cfg(target_os = "windows")]
        assert!(managers.contains(&"winget"));
    }
}
