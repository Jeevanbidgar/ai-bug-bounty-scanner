// Error Types for Update Checker
//
// Defines comprehensive error handling for update checking operations

use serde::{Deserialize, Serialize};
use std::fmt;

/// Error codes for update checking operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateCheckErrorCode {
    /// Package manager not installed or not available
    ManagerNotAvailable,
    
    /// Package not found or not installed
    PackageNotFound,
    
    /// Network error during check
    NetworkError,
    
    /// Command execution failed
    CommandFailed,
    
    /// Command timed out
    Timeout,
    
    /// Invalid version format
    InvalidVersion,
    
    /// Permission denied
    PermissionDenied,
    
    /// Rate limited by remote service
    RateLimited,
    
    /// Invalid configuration
    InvalidConfig,
    
    /// Unknown error
    Unknown,
}

impl fmt::Display for UpdateCheckErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateCheckErrorCode::ManagerNotAvailable => write!(f, "ManagerNotAvailable"),
            UpdateCheckErrorCode::PackageNotFound => write!(f, "PackageNotFound"),
            UpdateCheckErrorCode::NetworkError => write!(f, "NetworkError"),
            UpdateCheckErrorCode::CommandFailed => write!(f, "CommandFailed"),
            UpdateCheckErrorCode::Timeout => write!(f, "Timeout"),
            UpdateCheckErrorCode::InvalidVersion => write!(f, "InvalidVersion"),
            UpdateCheckErrorCode::PermissionDenied => write!(f, "PermissionDenied"),
            UpdateCheckErrorCode::RateLimited => write!(f, "RateLimited"),
            UpdateCheckErrorCode::InvalidConfig => write!(f, "InvalidConfig"),
            UpdateCheckErrorCode::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Context information for errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckErrorContext {
    /// Package manager that failed
    pub manager: String,
    
    /// Package name being checked
    pub package: String,
    
    /// Command that was executed (if applicable)
    pub command: Option<String>,
    
    /// Exit code (if applicable)
    pub exit_code: Option<i32>,
    
    /// Standard error output
    pub stderr: Option<String>,
    
    /// Additional diagnostic information
    pub diagnostic: Option<String>,
}

impl UpdateCheckErrorContext {
    pub fn new(manager: String, package: String) -> Self {
        Self {
            manager,
            package,
            command: None,
            exit_code: None,
            stderr: None,
            diagnostic: None,
        }
    }

    pub fn with_command(mut self, command: String) -> Self {
        self.command = Some(command);
        self
    }

    pub fn with_exit_code(mut self, exit_code: i32) -> Self {
        self.exit_code = Some(exit_code);
        self
    }

    pub fn with_stderr(mut self, stderr: String) -> Self {
        self.stderr = Some(stderr);
        self
    }

    pub fn with_diagnostic(mut self, diagnostic: String) -> Self {
        self.diagnostic = Some(diagnostic);
        self
    }
}

/// Comprehensive error type for update checking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckError {
    /// Error code
    pub code: UpdateCheckErrorCode,
    
    /// Human-readable error message
    pub message: String,
    
    /// Context information
    pub context: UpdateCheckErrorContext,
    
    /// Whether this error is retryable
    pub retryable: bool,
}

impl UpdateCheckError {
    pub fn new(code: UpdateCheckErrorCode, message: String, context: UpdateCheckErrorContext) -> Self {
        let retryable = matches!(
            code,
            UpdateCheckErrorCode::NetworkError
                | UpdateCheckErrorCode::Timeout
                | UpdateCheckErrorCode::RateLimited
        );
        
        Self {
            code,
            message,
            context,
            retryable,
        }
    }

    pub fn manager_not_available(manager: String) -> Self {
        Self::new(
            UpdateCheckErrorCode::ManagerNotAvailable,
            format!("Package manager '{}' is not available", manager),
            UpdateCheckErrorContext::new(manager, "unknown".to_string()),
        )
    }

    pub fn package_not_found(manager: String, package: String) -> Self {
        Self::new(
            UpdateCheckErrorCode::PackageNotFound,
            format!("Package '{}' not found via {}", package, manager),
            UpdateCheckErrorContext::new(manager, package),
        )
    }

    pub fn command_failed(manager: String, package: String, command: String, exit_code: i32, stderr: String) -> Self {
        Self::new(
            UpdateCheckErrorCode::CommandFailed,
            format!("Command '{}' failed with exit code {}", command, exit_code),
            UpdateCheckErrorContext::new(manager, package)
                .with_command(command)
                .with_exit_code(exit_code)
                .with_stderr(stderr),
        )
    }

    pub fn timeout(manager: String, package: String, command: String) -> Self {
        Self::new(
            UpdateCheckErrorCode::Timeout,
            format!("Command '{}' timed out", command),
            UpdateCheckErrorContext::new(manager, package)
                .with_command(command)
                .with_diagnostic("Command execution exceeded timeout".to_string()),
        )
    }

    pub fn network_error(manager: String, package: String, error: String) -> Self {
        Self::new(
            UpdateCheckErrorCode::NetworkError,
            format!("Network error: {}", error),
            UpdateCheckErrorContext::new(manager, package)
                .with_diagnostic(error),
        )
    }

    pub fn invalid_version(manager: String, package: String, version: String) -> Self {
        Self::new(
            UpdateCheckErrorCode::InvalidVersion,
            format!("Invalid version format: {}", version),
            UpdateCheckErrorContext::new(manager, package)
                .with_diagnostic(format!("Failed to parse version '{}'", version)),
        )
    }

    pub fn permission_denied(manager: String, package: String, operation: String) -> Self {
        Self::new(
            UpdateCheckErrorCode::PermissionDenied,
            format!("Permission denied for operation: {}", operation),
            UpdateCheckErrorContext::new(manager, package)
                .with_diagnostic(format!("Insufficient permissions for: {}", operation)),
        )
    }

    pub fn rate_limited(manager: String, package: String, retry_after: Option<u64>) -> Self {
        let message = if let Some(seconds) = retry_after {
            format!("Rate limited, retry after {} seconds", seconds)
        } else {
            "Rate limited by remote service".to_string()
        };
        
        Self::new(
            UpdateCheckErrorCode::RateLimited,
            message,
            UpdateCheckErrorContext::new(manager, package)
                .with_diagnostic(format!("Rate limited, retry after {:?}", retry_after)),
        )
    }
}

impl fmt::Display for UpdateCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for UpdateCheckError {}

/// Result type for update checking operations
pub type UpdateCheckResult<T> = Result<T, UpdateCheckError>;
