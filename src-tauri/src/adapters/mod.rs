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

// Legacy generic preset experiment; retained for compatibility but not registered for execution
pub mod generic;

// Validated profiles for common command-line patterns
pub mod profile;

// Quarantined local CLI capability inference for newly installed catalog tools
pub mod auto;

// Central adapter registry
pub mod registry;

// Re-export commonly used types for convenience
pub use registry::{AdapterInfo, AdapterRegistry, AdapterType, CommandPreview};
