// Tool adapters module - command builders for security tools

// Subdomain discovery
pub mod amass;
pub mod subfinder;

// Port scanning
pub mod naabu;
pub mod nmap;

// Vulnerability scanning
pub mod nuclei;

// URL discovery
pub mod gau;
pub mod waybackurls;

// Generic adapter (supports 30+ tools with common patterns)
pub mod generic;

// Central adapter registry
pub mod registry;

// Re-export commonly used types for convenience
pub use registry::{AdapterInfo, AdapterRegistry, AdapterType};
