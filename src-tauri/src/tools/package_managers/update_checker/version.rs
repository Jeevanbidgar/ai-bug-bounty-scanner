// Version comparison utilities
//
// Simple version comparison for update checking

use std::cmp::Ordering;

/// Simple version struct for comparison
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    parts: Vec<u64>,
    prerelease: Option<String>,
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl Version {
    /// Parse a version string
    pub fn parse(version_str: &str) -> Option<Self> {
        let version_str = version_str.trim().trim_start_matches('v');
        
        // Split on prerelease markers
        let (version_part, prerelease) = if let Some(idx) = version_str.find('-') {
            let (v, p) = version_str.split_at(idx);
            (v, Some(p[1..].to_string()))
        } else {
            (version_str, None)
        };
        
        // Parse numeric parts
        let parts: Vec<u64> = version_part
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect();
        
        if parts.is_empty() {
            return None;
        }
        
        let major = parts.get(0).copied().unwrap_or(0);
        let minor = parts.get(1).copied().unwrap_or(0);
        let patch = parts.get(2).copied().unwrap_or(0);
        
        Some(Version { parts, prerelease, major, minor, patch })
    }
    
    /// Compare two versions
    pub fn compare(&self, other: &Version) -> Ordering {
        // Compare numeric parts
        for i in 0..self.parts.len().max(other.parts.len()) {
            let a = self.parts.get(i).copied().unwrap_or(0);
            let b = other.parts.get(i).copied().unwrap_or(0);
            
            match a.cmp(&b) {
                Ordering::Equal => continue,
                other => return other,
            }
        }
        
        // If numeric parts are equal, compare prerelease
        match (&self.prerelease, &other.prerelease) {
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Less, // Prerelease < release
            (None, Some(_)) => Ordering::Greater, // Release > prerelease
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
    
    /// Check if this version is newer than another
    pub fn is_newer_than(&self, other: &Version) -> bool {
        self.compare(other) == Ordering::Greater
    }
    
    /// Check if this version is older than another
    pub fn is_older_than(&self, other: &Version) -> bool {
        self.compare(other) == Ordering::Less
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.compare(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compare(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        assert!(Version::parse("1.2.3").is_some());
        assert!(Version::parse("v1.2.3").is_some());
        assert!(Version::parse("1.2.3-alpha").is_some());
        assert!(Version::parse("invalid").is_none());
    }

    #[test]
    fn test_version_comparison() {
        let v1 = Version::parse("1.2.3").unwrap();
        let v2 = Version::parse("1.2.4").unwrap();
        let v3 = Version::parse("1.3.0").unwrap();
        
        assert!(v2.is_newer_than(&v1));
        assert!(v3.is_newer_than(&v2));
        assert!(v1.is_older_than(&v2));
    }

    #[test]
    fn test_prerelease_comparison() {
        let v1 = Version::parse("1.0.0-alpha").unwrap();
        let v2 = Version::parse("1.0.0").unwrap();
        
        assert!(v2.is_newer_than(&v1));
        assert!(v1.is_older_than(&v2));
    }
}

