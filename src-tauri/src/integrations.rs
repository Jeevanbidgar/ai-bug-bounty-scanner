//! Desktop-owned setup helpers for local MCP hosts.
//!
//! These commands only create client configuration that launches the local
//! `unihack-mcp` STDIO process. They never request or store a model-provider
//! API key.

use crate::daemon::{DaemonClient, DESKTOP_CREDENTIAL_ID};
use crate::governance::{EngagementScope, McpAuditEvent};
use crate::runtime::process::configure_tokio_command;
use crate::service::{CreateEngagementRequest, ServicePaths};
use serde::Serialize;
use std::path::{Path, PathBuf};
use tokio::process::Command;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpHostStatus {
    pub installed: bool,
    pub executable_path: Option<String>,
    pub configured: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpIntegrationInfo {
    pub transport: String,
    pub server_name: String,
    pub binary_path: String,
    pub binary_available: bool,
    pub provider_api_key_required: bool,
    pub codex: McpHostStatus,
    pub claude_code: McpHostStatus,
    pub codex_add_command: String,
    pub claude_add_command: String,
    pub codex_toml: String,
    pub claude_json: String,
    pub restart_note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpConfigurationResult {
    pub client: String,
    pub configured: bool,
    pub already_configured: bool,
    pub message: String,
}

#[tauri::command]
pub async fn get_mcp_integration_info() -> Result<McpIntegrationInfo, String> {
    let binary = resolve_mcp_binary();
    build_integration_info(binary).await
}

#[tauri::command]
pub async fn configure_mcp_client(client: String) -> Result<McpConfigurationResult, String> {
    let binary = resolve_mcp_binary();
    if !binary.is_file() {
        return Err(format!(
            "The UniHack MCP binary is not available at {}. Build or reinstall UniHack first.",
            binary.display()
        ));
    }

    match client.as_str() {
        "codex" => configure_codex(&binary).await,
        "claude_code" => configure_claude(&binary).await,
        _ => Err("Unsupported MCP client. Use 'codex' or 'claude_code'.".to_string()),
    }
}

#[tauri::command]
pub async fn list_engagement_scopes() -> Result<Vec<EngagementScope>, String> {
    desktop_daemon()
        .await?
        .list_engagements()
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn create_engagement_scope(
    request: CreateEngagementRequest,
) -> Result<EngagementScope, String> {
    desktop_daemon()
        .await?
        .create_engagement(request)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn revoke_engagement_scope(scope_id: String) -> Result<EngagementScope, String> {
    desktop_daemon()
        .await?
        .revoke_engagement(&scope_id)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn list_mcp_audit_activity(limit: Option<u32>) -> Result<Vec<McpAuditEvent>, String> {
    desktop_daemon()
        .await?
        .list_audit_activity(limit.unwrap_or(50).clamp(1, 200))
        .await
        .map_err(|error| error.to_string())
}

pub async fn desktop_daemon() -> Result<DaemonClient, String> {
    let paths = ServicePaths::discover().map_err(|error| error.to_string())?;
    DaemonClient::connect_or_start_as(&paths, DESKTOP_CREDENTIAL_ID)
        .await
        .map_err(|error| error.to_string())
}

async fn build_integration_info(binary: PathBuf) -> Result<McpIntegrationInfo, String> {
    let binary_path = binary.to_string_lossy().to_string();
    let codex_path = which::which("codex").ok();
    let claude_path = which::which("claude").ok();
    let codex_configured = match codex_path.as_deref() {
        Some(path) => client_has_matching_config(path, &binary).await,
        None => false,
    };
    let claude_configured = match claude_path.as_deref() {
        Some(path) => client_has_matching_config(path, &binary).await,
        None => false,
    };

    let claude_json = serde_json::to_string_pretty(&serde_json::json!({
        "mcpServers": {
            "unihack": {
                "type": "stdio",
                "command": binary_path,
                "args": [],
                "env": {}
            }
        }
    }))
    .map_err(|error| error.to_string())?;
    let toml_path = toml_string(&binary_path);

    Ok(McpIntegrationInfo {
        transport: "stdio".to_string(),
        server_name: "unihack".to_string(),
        binary_available: binary.is_file(),
        provider_api_key_required: false,
        codex: McpHostStatus {
            installed: codex_path.is_some(),
            executable_path: codex_path.map(|path| path.to_string_lossy().to_string()),
            configured: codex_configured,
        },
        claude_code: McpHostStatus {
            installed: claude_path.is_some(),
            executable_path: claude_path.map(|path| path.to_string_lossy().to_string()),
            configured: claude_configured,
        },
        codex_add_command: format!("codex mcp add unihack -- {}", shell_display(&binary)),
        claude_add_command: format!(
            "claude mcp add --transport stdio --scope user unihack -- {}",
            shell_display(&binary)
        ),
        codex_toml: format!(
            "[mcp_servers.unihack]\ncommand = {toml_path}\nargs = []"
        ),
        claude_json,
        binary_path,
        restart_note: "Start a fresh Codex task or Claude Code session after changing MCP configuration so the host can discover the UniHack tools.".to_string(),
    })
}

async fn configure_codex(binary: &Path) -> Result<McpConfigurationResult, String> {
    let codex = which::which("codex")
        .map_err(|_| "Codex CLI was not found on this system PATH.".to_string())?;
    if client_has_matching_config(&codex, binary).await {
        return Ok(McpConfigurationResult {
            client: "codex".to_string(),
            configured: true,
            already_configured: true,
            message: "Codex already points to this UniHack MCP binary.".to_string(),
        });
    }

    let existing = run_client(&codex, &["mcp", "get", "unihack"]).await?;
    if existing.status.success() {
        return Err(
            "Codex already has an MCP server named 'unihack' with a different command. Remove or rename that entry before continuing."
                .to_string(),
        );
    }

    let binary_path = binary.to_string_lossy().to_string();
    let output = run_client(
        &codex,
        &["mcp", "add", "unihack", "--", binary_path.as_str()],
    )
    .await?;
    command_result("codex", output)
}

async fn configure_claude(binary: &Path) -> Result<McpConfigurationResult, String> {
    let claude = which::which("claude")
        .map_err(|_| "Claude Code CLI was not found on this system PATH.".to_string())?;
    if client_has_matching_config(&claude, binary).await {
        return Ok(McpConfigurationResult {
            client: "claude_code".to_string(),
            configured: true,
            already_configured: true,
            message: "Claude Code already points to this UniHack MCP binary.".to_string(),
        });
    }

    let existing = run_client(&claude, &["mcp", "get", "unihack"]).await?;
    if existing.status.success() {
        return Err(
            "Claude Code already has an MCP server named 'unihack' with a different command. Remove or rename that entry before continuing."
                .to_string(),
        );
    }

    let binary_path = binary.to_string_lossy().to_string();
    let output = run_client(
        &claude,
        &[
            "mcp",
            "add",
            "--transport",
            "stdio",
            "--scope",
            "user",
            "unihack",
            "--",
            binary_path.as_str(),
        ],
    )
    .await?;
    command_result("claude_code", output)
}

async fn client_has_matching_config(client: &Path, binary: &Path) -> bool {
    run_client(client, &["mcp", "get", "unihack"])
        .await
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| {
            let expected = binary.to_string_lossy();
            String::from_utf8_lossy(&output.stdout).contains(expected.as_ref())
        })
}

async fn run_client(client: &Path, arguments: &[&str]) -> Result<std::process::Output, String> {
    let mut command = Command::new(client);
    command.args(arguments);
    configure_tokio_command(&mut command);
    command
        .output()
        .await
        .map_err(|error| format!("Failed to run {}: {error}", client.display()))
}

fn command_result(
    client: &str,
    output: std::process::Output,
) -> Result<McpConfigurationResult, String> {
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if error.is_empty() {
            format!("{client} rejected the MCP configuration update")
        } else {
            error
        });
    }
    Ok(McpConfigurationResult {
        client: client.to_string(),
        configured: true,
        already_configured: false,
        message: "UniHack MCP configuration was added. Start a fresh client session to load it."
            .to_string(),
    })
}

fn resolve_mcp_binary() -> PathBuf {
    if let Some(configured) = std::env::var_os("UNIHACK_MCP_BINARY") {
        return PathBuf::from(configured);
    }

    let executable_name = if cfg!(windows) {
        "unihack-mcp.exe"
    } else {
        "unihack-mcp"
    };
    let mut candidates = Vec::new();
    if let Ok(current) = std::env::current_exe() {
        if let Some(parent) = current.parent() {
            candidates.push(parent.join(executable_name));
            candidates.push(parent.join("../Resources").join(executable_name));
            candidates.push(parent.join("../Resources/binaries").join(executable_name));
        }
    }
    candidates.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/debug")
            .join(executable_name),
    );
    candidates
        .iter()
        .find(|path| path.is_file())
        .cloned()
        .unwrap_or_else(|| candidates.remove(0))
}

fn toml_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn shell_display(path: &Path) -> String {
    let value = path.to_string_lossy();
    if value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '/' | '\\' | '_' | '-' | '.')
    }) {
        value.to_string()
    } else {
        format!("\"{}\"", value.replace('"', "\\\""))
    }
}

#[cfg(test)]
mod tests {
    use super::{shell_display, toml_string};
    use std::path::Path;

    #[test]
    fn config_rendering_quotes_paths_with_spaces() {
        assert_eq!(
            shell_display(Path::new("/Applications/UniHack Tools/unihack-mcp")),
            "\"/Applications/UniHack Tools/unihack-mcp\""
        );
        assert_eq!(
            toml_string("C:\\UniHack\\mcp.exe"),
            "\"C:\\\\UniHack\\\\mcp.exe\""
        );
    }
}
