// Version probing and comparison
//
// Utilities for detecting tool versions and comparing them

use serde::{Deserialize, Serialize};
use crate::runtime::process::hidden_std_command;
use std::cmp::Ordering;
use tokio::time::{timeout, Duration};

/// Semantic version structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub pre_release: Option<String>,
}

impl Version {
    /// Parse a version string like "1.2.3" or "v2.0.1-beta"
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches('v');

        // Split by '-' to separate version from pre-release
        let parts: Vec<&str> = s.split('-').collect();
        let version_part = parts[0];
        let pre_release = if parts.len() > 1 {
            Some(parts[1..].join("-"))
        } else {
            None
        };

        // Parse version numbers
        let nums: Vec<&str> = version_part.split('.').collect();
        if nums.is_empty() {
            return None;
        }

        let major = nums[0].parse().ok()?;
        let minor = nums.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch = nums.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

        Some(Version {
            major,
            minor,
            patch,
            pre_release,
        })
    }

    /// Convert to string representation
    #[allow(dead_code)]
    pub fn to_string(&self) -> String {
        let base = format!("{}.{}.{}", self.major, self.minor, self.patch);
        if let Some(ref pre) = self.pre_release {
            format!("{}-{}", base, pre)
        } else {
            base
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare major, minor, patch
        match self.major.cmp(&other.major) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.minor.cmp(&other.minor) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.patch.cmp(&other.patch) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Pre-release versions are lower than release versions
        match (&self.pre_release, &other.pre_release) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater, // Release > Pre-release
            (Some(_), None) => Ordering::Less,    // Pre-release < Release
            (Some(a), Some(b)) => a.cmp(b),       // Compare pre-release strings
        }
    }
}

/// Probe the version of a tool by running it with version flags
#[allow(dead_code)]
pub async fn probe_version(tool_name: &str, version_args: &[String]) -> Option<String> {
    // Try each version arg until one works
    for arg in version_args {
        match execute_version_command(tool_name, arg).await {
            Ok(output) => {
                if let Some(version) = parse_version(&output) {
                    return Some(version);
                }
            }
            Err(_) => continue,
        }
    }
    None
}

/// Execute a command to get version with timeout
#[allow(dead_code)]
async fn execute_version_command(command: &str, arg: &str) -> Result<String, String> {
    let timeout_duration = Duration::from_secs(5);

    let output_future = tokio::task::spawn_blocking({
        let command = command.to_string();
        let arg = arg.to_string();
        move || {
            let mut cmd = hidden_std_command(&command);
            cmd.arg(&arg);
            cmd.output()
                .map_err(|e| format!("Failed to execute {}: {}", command, e))
        }
    });

    match timeout(timeout_duration, output_future).await {
        Ok(Ok(Ok(output))) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            // Some tools output version to stderr
            if !stdout.is_empty() {
                Ok(stdout)
            } else if !stderr.is_empty() {
                Ok(stderr)
            } else {
                Err(format!("{} returned no output", command))
            }
        }
        Ok(Ok(Err(e))) => Err(e),
        Ok(Err(_)) => Err(format!("{} version task panicked", command)),
        Err(_) => Err(format!("{} version check timed out (5s)", command)),
    }
}

/// Parse version string from command output
#[allow(dead_code)]
pub fn parse_version(output: &str) -> Option<String> {
    // Try multiple patterns
    let patterns = [
        // Standard version patterns
        r"v?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)",
        // Just major.minor
        r"v?(\d+\.\d+)",
        // Version preceded by "version"
        r"version\s+v?(\d+\.\d+(?:\.\d+)?)",
        // Version preceded by tool name
        r"[a-zA-Z0-9-]+\s+v?(\d+\.\d+(?:\.\d+)?)",
    ];

    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(caps) = re.captures(output) {
                if let Some(version_match) = caps.get(1) {
                    return Some(version_match.as_str().to_string());
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        assert_eq!(
            Version::parse("1.2.3"),
            Some(Version {
                major: 1,
                minor: 2,
                patch: 3,
                pre_release: None
            })
        );

        assert_eq!(
            Version::parse("v2.0.1"),
            Some(Version {
                major: 2,
                minor: 0,
                patch: 1,
                pre_release: None
            })
        );

        assert_eq!(
            Version::parse("3.1.0-beta"),
            Some(Version {
                major: 3,
                minor: 1,
                patch: 0,
                pre_release: Some("beta".to_string())
            })
        );
    }

    #[test]
    fn test_version_comparison() {
        let v1 = Version::parse("1.2.3").unwrap();
        let v2 = Version::parse("1.2.4").unwrap();
        let v3 = Version::parse("2.0.0").unwrap();

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);
    }

    #[test]
    fn test_version_prerelease() {
        let release = Version::parse("1.0.0").unwrap();
        let beta = Version::parse("1.0.0-beta").unwrap();

        assert!(beta < release);
    }

    #[test]
    fn test_parse_version_from_output() {
        assert_eq!(parse_version("subfinder v2.5.5"), Some("2.5.5".to_string()));

        assert_eq!(
            parse_version("nuclei version 3.0.4"),
            Some("3.0.4".to_string())
        );

        assert_eq!(parse_version("nmap version 7.94"), Some("7.94".to_string()));

        assert_eq!(parse_version("v1.2.3-beta"), Some("1.2.3-beta".to_string()));
    }

    #[test]
    fn test_version_to_string() {
        let v1 = Version {
            major: 1,
            minor: 2,
            patch: 3,
            pre_release: None,
        };
        assert_eq!(v1.to_string(), "1.2.3");

        let v2 = Version {
            major: 2,
            minor: 0,
            patch: 1,
            pre_release: Some("beta".to_string()),
        };
        assert_eq!(v2.to_string(), "2.0.1-beta");
    }

    #[tokio::test]
    async fn test_probe_version_go() {
        // Test with go (should be available on dev machines)
        let version = probe_version("go", &vec!["version".to_string()]).await;
        if version.is_some() {
            eprintln!("Detected go version: {:?}", version);
        }
    }
}
