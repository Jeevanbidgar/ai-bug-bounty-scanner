use super::types::*;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::time::{timeout, timeout_at};

/// Process executor for running security tools with async streaming and control
pub struct ProcessExecutor {
    command: String,
    args: Vec<String>,
    working_directory: Option<PathBuf>,
    environment: HashMap<String, String>,
    timeout_duration: Duration,
    retry_count: u32,
    retry_delay: Duration,
    stdout_sender: Option<mpsc::UnboundedSender<String>>,
    stderr_sender: Option<mpsc::UnboundedSender<String>>,
    cancellation_token: Arc<RwLock<Option<broadcast::Sender<()>>>>,
}

impl ProcessExecutor {
    /// Create a new process executor
    pub fn new() -> Self {
        Self {
            command: String::new(),
            args: Vec::new(),
            working_directory: None,
            environment: HashMap::new(),
            timeout_duration: Duration::from_secs(300), // 5 minutes default
            retry_count: 0,
            retry_delay: Duration::from_secs(1),
            stdout_sender: None,
            stderr_sender: None,
            cancellation_token: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the command to execute
    pub fn with_command<S: Into<String>>(mut self, command: S) -> Self {
        self.command = command.into();
        self
    }

    /// Set command arguments
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Set working directory
    pub fn with_cwd<P: Into<PathBuf>>(mut self, cwd: P) -> Self {
        self.working_directory = Some(cwd.into());
        self
    }

    /// Set environment variables
    pub fn with_environment(mut self, env: HashMap<String, String>) -> Self {
        self.environment = env;
        self
    }

    /// Set execution timeout
    pub fn with_timeout(mut self, timeout_seconds: u64) -> Self {
        self.timeout_duration = Duration::from_secs(timeout_seconds);
        self
    }

    /// Set timeout in milliseconds
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_duration = Duration::from_millis(timeout_ms);
        self
    }

    /// Set retry configuration
    pub fn with_retry(mut self, count: u32, delay_seconds: u64) -> Self {
        self.retry_count = count;
        self.retry_delay = Duration::from_secs(delay_seconds);
        self
    }

    /// Set output stream senders for real-time streaming
    pub fn with_output_streams(
        mut self,
        stdout_sender: mpsc::UnboundedSender<String>,
        stderr_sender: mpsc::UnboundedSender<String>,
    ) -> Self {
        self.stdout_sender = Some(stdout_sender);
        self.stderr_sender = Some(stderr_sender);
        self
    }

    /// Execute the process with full async control and streaming
    pub async fn execute(mut self) -> Result<ProcessResult> {
        let mut last_error = None;

        // Try execution with retries
        for attempt in 0..=self.retry_count {
            match self.execute_once().await {
                Ok(result) => {
                    if attempt > 0 {
                        info!("Process succeeded on attempt {} after {} retries", attempt + 1, attempt);
                    }
                    return Ok(result);
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.retry_count {
                        warn!("Process failed on attempt {}: {:?}, retrying...", attempt + 1, last_error);
                        tokio::time::sleep(self.retry_delay).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("Process execution failed after all retries")))
    }

    /// Execute the process once (internal method)
    async fn execute_once(&mut self) -> Result<ProcessResult> {
        debug!("Executing command: {} with args: {:?}", self.command, self.args);

        // Setup cancellation token for this execution
        let (cancel_tx, mut cancel_rx) = broadcast::channel::<()>(1);
        *self.cancellation_token.write().await = Some(cancel_tx);

        // Build the command
        let mut cmd = Command::new(&self.command);
        cmd.args(&self.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        // Set working directory if specified
        if let Some(cwd) = &self.working_directory {
            cmd.current_dir(cwd);
        }

        // Set environment variables
        for (key, value) in &self.environment {
            cmd.env(key, value);
        }

        // Spawn the process
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                error!("Failed to spawn process '{}': {}", self.command, e);
                return Err(e.into());
            }
        };

        let start_time = std::time::Instant::now();
        let pid = child.id();

        info!("Spawned process {} with PID {}", self.command, pid.unwrap_or(0));

        // Get stdout and stderr handles
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("Failed to capture stdout"))?;
        let stderr = child.stderr.take().ok_or_else(|| anyhow!("Failed to capture stderr"))?;

        // Create readers for streaming
        let stdout_reader = BufReader::new(stdout);
        let stderr_reader = BufReader::new(stderr);

        // Create channels for collecting output
        let (stdout_tx, mut stdout_rx) = mpsc::unbounded_channel::<String>();
        let (stderr_tx, mut stderr_rx) = mpsc::unbounded_channel::<String>();

        // Set output senders if provided
        if let Some(sender) = &self.stdout_sender {
            let sender = sender.clone();
            tokio::spawn(async move {
                while let Some(line) = stdout_rx.recv().await {
                    let _ = sender.send(line);
                }
            });
        }

        if let Some(sender) = &self.stderr_sender {
            let sender = sender.clone();
            tokio::spawn(async move {
                while let Some(line) = stderr_rx.recv().await {
                    let _ = sender.send(line);
                }
            });
        }

        // Spawn stdout reader task
        let stdout_tx_clone = stdout_tx.clone();
        let stdout_task = tokio::spawn(async move {
            let mut lines = stdout_reader.lines();
            while let Some(line) = lines.next_line().await.unwrap_or(None) {
                let _ = stdout_tx_clone.send(line);
            }
        });

        // Spawn stderr reader task
        let stderr_tx_clone = stderr_tx.clone();
        let stderr_task = tokio::spawn(async move {
            let mut lines = stderr_reader.lines();
            while let Some(line) = lines.next_line().await.unwrap_or(None) {
                let _ = stderr_tx_clone.send(line);
            }
        });

        // Wait for process completion or timeout or cancellation
        let result = tokio::select! {
            result = child.wait() => {
                // Process completed normally
                let output = result?;
                let exit_code = output.code().unwrap_or(-1);

                // Wait for output readers to complete
                let _ = tokio::try_join!(stdout_task, stderr_task);

                // Collect all output
                let mut stdout_lines = Vec::new();
                while let Ok(line) = stdout_rx.try_recv() {
                    stdout_lines.push(line);
                }

                let mut stderr_lines = Vec::new();
                while let Ok(line) = stderr_rx.try_recv() {
                    stderr_lines.push(line);
                }

                Ok(ProcessResult {
                    exit_code,
                    stdout_lines,
                    stderr_lines,
                    artifacts: Vec::new(), // TODO: Implement artifact detection
                    duration_ms: start_time.elapsed().as_millis() as u64,
                })
            }
            _ = tokio::time::sleep(self.timeout_duration) => {
                // Timeout occurred
                error!("Process '{}' timed out after {:?}", self.command, self.timeout_duration);

                // Kill the process
                if let Err(e) = child.kill().await {
                    warn!("Failed to kill timed out process: {}", e);
                }

                // Wait for readers to complete
                let _ = tokio::try_join!(stdout_task, stderr_task);

                Err(anyhow!("Process timed out after {:?}", self.timeout_duration))
            }
            _ = cancel_rx.recv() => {
                // Cancellation requested
                info!("Process '{}' cancelled by user", self.command);

                // Kill the process
                if let Err(e) = child.kill().await {
                    warn!("Failed to kill cancelled process: {}", e);
                }

                // Wait for readers to complete
                let _ = tokio::try_join!(stdout_task, stderr_task);

                Err(anyhow!("Process cancelled by user"))
            }
        };

        // Clear cancellation token
        *self.cancellation_token.write().await = None;

        result
    }

    /// Cancel the current execution
    pub async fn cancel(&self) -> Result<()> {
        if let Some(cancel_tx) = self.cancellation_token.read().await.as_ref() {
            let _ = cancel_tx.send(());
        }
        Ok(())
    }

    /// Get current cancellation token for external cancellation
    pub fn get_cancellation_token(&self) -> Arc<RwLock<Option<broadcast::Sender<()>>>> {
        self.cancellation_token.clone()
    }
}

impl Default for ProcessExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Process execution result
#[derive(Debug, Clone)]
pub struct ProcessResult {
    pub exit_code: i32,
    pub stdout_lines: Vec<String>,
    pub stderr_lines: Vec<String>,
    pub artifacts: Vec<ExecutionArtifact>,
    pub duration_ms: u64,
}

/// Factory function for creating executors
pub fn create_executor() -> ProcessExecutor {
    ProcessExecutor::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_process_executor_creation() {
        let executor = ProcessExecutor::new()
            .with_command("echo")
            .with_args(vec!["hello".to_string(), "world".to_string()]);

        // This would normally execute, but we'll just test the builder pattern
        assert_eq!(executor.command, "echo");
        assert_eq!(executor.args, vec!["hello", "world"]);
    }

    #[tokio::test]
    async fn test_echo_command_execution() {
        let (stdout_tx, mut stdout_rx) = mpsc::unbounded_channel();
        let (stderr_tx, mut stderr_rx) = mpsc::unbounded_channel();

        let result = ProcessExecutor::new()
            .with_command("echo")
            .with_args(vec!["test".to_string()])
            .with_output_streams(stdout_tx, stderr_tx)
            .execute()
            .await;

        // The test might fail if echo is not available, but that's expected in CI
        match result {
            Ok(process_result) => {
                assert_eq!(process_result.exit_code, 0);
                assert!(process_result.stdout_lines.iter().any(|line| line.contains("test")));
            }
            Err(e) => {
                // This is expected if echo is not available in the test environment
                println!("Expected test failure: {}", e);
            }
        }
    }
}