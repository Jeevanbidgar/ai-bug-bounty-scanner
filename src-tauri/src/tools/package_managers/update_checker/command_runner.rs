// Command Runner for Update Checker
//
// Provides a unified interface for executing package manager commands
// with timeout, logging, and error handling

use super::error_types::{UpdateCheckError, UpdateCheckErrorCode};
use super::telemetry::TelemetryContext;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Result of command execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    /// Exit code
    pub exit_code: i32,

    /// Standard output
    pub stdout: String,

    /// Standard error
    pub stderr: String,

    /// Duration of execution
    pub duration: Duration,

    /// Whether the command succeeded
    pub success: bool,
}

impl CommandResult {
    pub fn new(exit_code: i32, stdout: String, stderr: String, duration: Duration) -> Self {
        Self {
            exit_code,
            stdout,
            stderr,
            duration,
            success: exit_code == 0,
        }
    }

    pub fn is_success(&self) -> bool {
        self.success
    }

    pub fn is_failure(&self) -> bool {
        !self.success
    }
}

/// Unified command runner with timeout and logging
#[derive(Clone)]
pub struct CommandRunner {
    /// Default timeout for commands
    default_timeout: Duration,

    /// Whether to enable debug logging
    debug_logging: bool,
}

impl CommandRunner {
    pub fn new(default_timeout: Duration, debug_logging: bool) -> Self {
        Self {
            default_timeout,
            debug_logging,
        }
    }

    /// Execute a command with the default timeout
    pub async fn execute(
        &self,
        command: &str,
        args: &[&str],
    ) -> Result<CommandResult, UpdateCheckError> {
        self.execute_with_timeout(command, args, self.default_timeout)
            .await
    }

    /// Execute a command with a custom timeout
    pub async fn execute_with_timeout(
        &self,
        command: &str,
        args: &[&str],
        timeout_duration: Duration,
    ) -> Result<CommandResult, UpdateCheckError> {
        self.execute_with_timeout_and_telemetry(command, args, timeout_duration, None)
            .await
    }

    /// Execute a command with telemetry context
    pub async fn execute_with_timeout_and_telemetry(
        &self,
        command: &str,
        args: &[&str],
        timeout_duration: Duration,
        telemetry_context: Option<&TelemetryContext>,
    ) -> Result<CommandResult, UpdateCheckError> {
        let start_time = std::time::Instant::now();

        if self.debug_logging {
            eprintln!("🔄 Executing: {} {}", command, args.join(" "));
        }

        let mut cmd = Command::new(command);
        cmd.args(args);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let output = timeout(timeout_duration, cmd.output())
            .await
            .map_err(|_| {
                UpdateCheckError::timeout(
                    "unknown".to_string(),
                    "unknown".to_string(),
                    format!("{} {}", command, args.join(" ")),
                )
            })?
            .map_err(|e| {
                UpdateCheckError::command_failed(
                    "unknown".to_string(),
                    "unknown".to_string(),
                    format!("{} {}", command, args.join(" ")),
                    -1,
                    e.to_string(),
                )
            })?;

        let duration = start_time.elapsed();

        let exit_code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        let result = CommandResult::new(exit_code, stdout, stderr, duration);

        // Record command execution in telemetry
        if let Some(telemetry_context) = telemetry_context {
            telemetry_context.record_command_executed(
                "unknown".to_string(), // Manager name would be passed separately
                format!("{} {}", command, args.join(" ")),
                result.success,
                Some(result.exit_code),
                result.stdout.len(),
                result.stderr.len(),
            );
        }

        if self.debug_logging {
            if result.success {
                eprintln!(
                    "✅ Command succeeded in {:?}: {}",
                    duration,
                    result.stdout.trim()
                );
            } else {
                eprintln!(
                    "❌ Command failed (exit code {}): {}",
                    exit_code,
                    result.stderr.trim()
                );
            }
        }

        Ok(result)
    }

    /// Execute a command with telemetry context
    pub async fn execute_with_telemetry(
        &self,
        command: &str,
        args: &[&str],
        telemetry_context: &TelemetryContext,
    ) -> Result<CommandResult, UpdateCheckError> {
        self.execute_with_timeout_and_telemetry(
            command,
            args,
            self.default_timeout,
            Some(telemetry_context),
        )
        .await
    }

    /// Execute a command and return only stdout if successful
    pub async fn execute_stdout(
        &self,
        command: &str,
        args: &[&str],
    ) -> Result<String, UpdateCheckError> {
        let result = self.execute(command, args).await?;

        if result.success {
            Ok(result.stdout)
        } else {
            Err(UpdateCheckError::command_failed(
                "unknown".to_string(),
                "unknown".to_string(),
                format!("{} {}", command, args.join(" ")),
                result.exit_code,
                result.stderr,
            ))
        }
    }

    /// Execute a command and return only stderr if failed
    pub async fn execute_stderr(
        &self,
        command: &str,
        args: &[&str],
    ) -> Result<String, UpdateCheckError> {
        let result = self.execute(command, args).await?;

        if result.success {
            Ok(result.stdout)
        } else {
            Ok(result.stderr)
        }
    }

    /// Check if a command is available
    pub async fn is_available(&self, command: &str) -> bool {
        let result = self.execute(command, &["--version"]).await;
        result.is_ok() && result.unwrap().success
    }

    /// Execute a command with JSON output parsing
    pub async fn execute_json<T>(&self, command: &str, args: &[&str]) -> Result<T, UpdateCheckError>
    where
        T: serde::de::DeserializeOwned,
    {
        let stdout = self.execute_stdout(command, args).await?;

        serde_json::from_str(&stdout).map_err(|e| {
            UpdateCheckError::new(
                UpdateCheckErrorCode::CommandFailed,
                format!("Failed to parse JSON output: {}", e),
                super::error_types::UpdateCheckErrorContext::new(
                    "unknown".to_string(),
                    "unknown".to_string(),
                )
                .with_diagnostic(stdout),
            )
        })
    }

    /// Execute a command with custom working directory
    pub async fn execute_in_dir(
        &self,
        command: &str,
        args: &[&str],
        working_dir: &std::path::Path,
    ) -> Result<CommandResult, UpdateCheckError> {
        let start_time = std::time::Instant::now();

        if self.debug_logging {
            eprintln!(
                "🔄 Executing in {:?}: {} {}",
                working_dir,
                command,
                args.join(" ")
            );
        }

        let mut cmd = Command::new(command);
        cmd.args(args);
        cmd.current_dir(working_dir);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let output = timeout(self.default_timeout, cmd.output())
            .await
            .map_err(|_| {
                UpdateCheckError::timeout(
                    "unknown".to_string(),
                    "unknown".to_string(),
                    format!("{} {}", command, args.join(" ")),
                )
            })?
            .map_err(|e| {
                UpdateCheckError::command_failed(
                    "unknown".to_string(),
                    "unknown".to_string(),
                    format!("{} {}", command, args.join(" ")),
                    -1,
                    e.to_string(),
                )
            })?;

        let duration = start_time.elapsed();

        let exit_code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        let result = CommandResult::new(exit_code, stdout, stderr, duration);

        if self.debug_logging {
            if result.success {
                eprintln!(
                    "✅ Command succeeded in {:?}: {}",
                    duration,
                    result.stdout.trim()
                );
            } else {
                eprintln!(
                    "❌ Command failed (exit code {}): {}",
                    exit_code,
                    result.stderr.trim()
                );
            }
        }

        Ok(result)
    }
}

impl Default for CommandRunner {
    fn default() -> Self {
        Self::new(Duration::from_secs(30), false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_command_runner_success() {
        let runner = CommandRunner::new(Duration::from_secs(5), false);

        // Test with a simple command that should succeed
        let result = runner.execute("echo", &["hello"]).await;
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.success);
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("hello"));
    }

    #[tokio::test]
    async fn test_command_runner_failure() {
        let runner = CommandRunner::new(Duration::from_secs(5), false);

        // Test with a command that should fail
        let result = runner.execute("false", &[]).await;
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(!result.success);
        assert_eq!(result.exit_code, 1);
    }

    #[tokio::test]
    async fn test_command_runner_timeout() {
        let runner = CommandRunner::new(Duration::from_millis(100), false);

        // Test with a command that should timeout
        let result = runner.execute("sleep", &["1"]).await;
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert_eq!(error.code, UpdateCheckErrorCode::Timeout);
    }

    #[tokio::test]
    async fn test_is_available() {
        let runner = CommandRunner::new(Duration::from_secs(5), false);

        // Test with a command that should be available
        assert!(runner.is_available("echo").await);

        // Test with a command that should not be available
        assert!(!runner.is_available("nonexistent_command_12345").await);
    }
}
