// Tool adapters module - command builders for security tools

// Subdomain discovery
pub mod subfinder;
pub mod amass;

// Port scanning
pub mod naabu;
pub mod nmap;

// Vulnerability scanning
pub mod nuclei;

// URL discovery
pub mod gau;
pub mod waybackurls;

// Central adapter registry
pub mod registry;

// Re-export commonly used types for convenience
pub use registry::{AdapterRegistry, AdapterType, AdapterInfo};