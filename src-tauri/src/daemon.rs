//! Versioned local daemon protocol and client.
//!
//! The daemon is launched on demand and communicates only over a Unix-domain
//! socket (macOS/Linux) or a local named pipe (Windows). Frames are
//! length-prefixed JSON and every connection completes an HMAC challenge using
//! a pairing secret stored in the operating-system credential store.

use crate::database::{Report, Scan};
use crate::events::DomainEvent;
use crate::governance::{Capability, EngagementScope};
use crate::runtime::process::configure_tokio_command;
use crate::service::{
    CreateEngagementRequest, MissionValidation, RunAccepted, RunStatus, ScanEvidence, ServicePaths,
    ServiceStatus, StartWorkflowRequest, UniHackService, WorkflowCatalogEntry,
    LOCAL_OWNER_PROFILE_ID,
};
use crate::settings::AppSettings;
use crate::tools::discovery::ToolRecord;
use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

#[cfg(windows)]
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

type HmacSha256 = Hmac<Sha256>;

pub const DAEMON_PROTOCOL_VERSION: u32 = 2;
#[cfg(debug_assertions)]
pub const MCP_CREDENTIAL_ID: &str = "mcp-development-v1";
#[cfg(not(debug_assertions))]
pub const MCP_CREDENTIAL_ID: &str = "mcp-production-v1";
#[cfg(debug_assertions)]
pub const DESKTOP_CREDENTIAL_ID: &str = "desktop-development-v1";
#[cfg(not(debug_assertions))]
pub const DESKTOP_CREDENTIAL_ID: &str = "desktop-production-v1";
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const PAIRING_SERVICE: &str = "com.aibugbountyscanner.app";

#[derive(Debug, Clone)]
pub struct DaemonEndpoint {
    #[cfg(unix)]
    pub socket_path: PathBuf,
    #[cfg(windows)]
    pub pipe_name: String,
}

impl DaemonEndpoint {
    pub fn from_paths(paths: &ServicePaths) -> Self {
        #[cfg(unix)]
        {
            Self {
                socket_path: paths.app_data_dir.join("unihackd-v2.sock"),
            }
        }
        #[cfg(windows)]
        {
            use sha2::Digest;
            let hash = hex::encode(Sha256::digest(
                paths.app_data_dir.to_string_lossy().as_bytes(),
            ));
            Self {
                pipe_name: format!(r"\\.\pipe\unihackd-v2-{}", &hash[..16]),
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerHandshake {
    Challenge {
        protocol_version: u32,
        nonce: String,
    },
    Authenticated {
        protocol_version: u32,
    },
    Enrollment {
        protocol_version: u32,
        secret: String,
    },
    Rejected {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientHandshake {
    Enroll {
        protocol_version: u32,
        profile_id: String,
        credential_id: String,
    },
    Authenticate {
        protocol_version: u32,
        profile_id: String,
        credential_id: String,
        response: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DaemonRequestEnvelope {
    request_id: String,
    operation: DaemonOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", content = "input", rename_all = "snake_case")]
enum DaemonOperation {
    Ping,
    GetStatus,
    ListTools {
        force_refresh: bool,
    },
    GetTool {
        name: String,
        force_refresh: bool,
    },
    ListWorkflows,
    GetWorkflow {
        workflow_id: String,
    },
    ListEngagements,
    CreateEngagement {
        request: CreateEngagementRequest,
    },
    RevokeEngagement {
        scope_id: String,
    },
    ListAuditActivity {
        limit: u32,
    },
    ValidateMission {
        scope_id: String,
        workflow_id: String,
        target: String,
    },
    StartWorkflow {
        request: StartWorkflowRequest,
    },
    GetRunStatus {
        run_id: String,
    },
    CancelRun {
        run_id: String,
    },
    SubscribeEvents,
    ListScans,
    GetScanEvidence {
        scan_id: String,
    },
    ListReports,
    GetReport {
        report_id: String,
    },
    RefreshAutoAdapters,
    RuntimeSettings,
    Audit {
        capability: Capability,
        request_id: String,
        scope_id: Option<String>,
        arguments: Value,
        outcome: String,
        correlation_id: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DaemonResponseEnvelope {
    request_id: String,
    status: String,
    data: Option<Value>,
    error_code: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Clone)]
struct AuthenticatedClient {
    profile_id: String,
    credential_id: String,
}

#[cfg(unix)]
type PlatformClient = UnixStream;
#[cfg(windows)]
type PlatformClient = NamedPipeClient;

#[derive(Clone)]
pub struct DaemonClient {
    transport: Arc<Mutex<PlatformClient>>,
    endpoint: DaemonEndpoint,
    credential_id: String,
}

impl DaemonClient {
    pub async fn connect_or_start(paths: &ServicePaths) -> Result<Self> {
        Self::connect_or_start_as(paths, MCP_CREDENTIAL_ID).await
    }

    pub async fn connect_or_start_as(paths: &ServicePaths, credential_id: &str) -> Result<Self> {
        validate_credential_id(credential_id)?;
        let endpoint = DaemonEndpoint::from_paths(paths);
        if let Ok(client) = Self::connect(&endpoint, credential_id).await {
            return Ok(client);
        }

        let binary = resolve_daemon_binary()?;
        let mut command = tokio::process::Command::new(&binary);
        command
            .env("UNIHACK_APP_DATA_DIR", &paths.app_data_dir)
            .env("UNIHACK_WORKFLOWS_DIR", &paths.workflows_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null());
        configure_tokio_command(&mut command);
        command
            .spawn()
            .with_context(|| format!("daemon_unavailable: failed to start {}", binary.display()))?;

        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            match Self::connect(&endpoint, credential_id).await {
                Ok(client) => return Ok(client),
                Err(error) if Instant::now() < deadline => {
                    let _ = error;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => {
                    return Err(anyhow!(
                        "daemon_unavailable: UniHack daemon did not become ready: {error}"
                    ))
                }
            }
        }
    }

    async fn connect(endpoint: &DaemonEndpoint, credential_id: &str) -> Result<Self> {
        let mut stream = connect_platform(endpoint).await?;
        authenticate_client(&mut stream, credential_id).await?;
        Ok(Self {
            transport: Arc::new(Mutex::new(stream)),
            endpoint: endpoint.clone(),
            credential_id: credential_id.to_string(),
        })
    }

    async fn request<T: DeserializeOwned>(&self, operation: DaemonOperation) -> Result<T> {
        let request_id = Uuid::new_v4().to_string();
        let request = DaemonRequestEnvelope {
            request_id: request_id.clone(),
            operation,
        };
        let mut transport = self.transport.lock().await;
        write_frame(&mut *transport, &request).await?;
        let response = read_frame::<_, DaemonResponseEnvelope>(&mut *transport).await?;
        if response.request_id != request_id {
            return Err(anyhow!("daemon_protocol_error: response ID mismatch"));
        }
        if response.status != "ok" {
            return Err(anyhow!(
                "{}",
                response
                    .error_code
                    .or(response.message)
                    .unwrap_or_else(|| "daemon_error".to_string())
            ));
        }
        serde_json::from_value(response.data.unwrap_or(Value::Null))
            .context("daemon_protocol_error: invalid response payload")
    }

    pub async fn ping(&self) -> Result<String> {
        self.request(DaemonOperation::Ping).await
    }

    pub async fn status(&self) -> Result<ServiceStatus> {
        self.request(DaemonOperation::GetStatus).await
    }

    pub async fn list_tools(&self, force_refresh: bool) -> Result<Vec<ToolRecord>> {
        self.request(DaemonOperation::ListTools { force_refresh })
            .await
    }

    pub async fn get_tool(&self, name: &str, force_refresh: bool) -> Result<Option<ToolRecord>> {
        self.request(DaemonOperation::GetTool {
            name: name.to_string(),
            force_refresh,
        })
        .await
    }

    pub async fn list_workflows(&self) -> Result<Vec<WorkflowCatalogEntry>> {
        self.request(DaemonOperation::ListWorkflows).await
    }

    pub async fn get_workflow(&self, workflow_id: &str) -> Result<WorkflowCatalogEntry> {
        self.request(DaemonOperation::GetWorkflow {
            workflow_id: workflow_id.to_string(),
        })
        .await
    }

    pub async fn list_engagements(&self) -> Result<Vec<EngagementScope>> {
        self.request(DaemonOperation::ListEngagements).await
    }

    pub async fn create_engagement(
        &self,
        request: CreateEngagementRequest,
    ) -> Result<EngagementScope> {
        self.request(DaemonOperation::CreateEngagement { request })
            .await
    }

    pub async fn revoke_engagement(&self, scope_id: &str) -> Result<EngagementScope> {
        self.request(DaemonOperation::RevokeEngagement {
            scope_id: scope_id.to_string(),
        })
        .await
    }

    pub async fn list_audit_activity(
        &self,
        limit: u32,
    ) -> Result<Vec<crate::governance::McpAuditEvent>> {
        self.request(DaemonOperation::ListAuditActivity { limit })
            .await
    }

    pub async fn validate_mission(
        &self,
        scope_id: &str,
        workflow_id: &str,
        target: &str,
    ) -> Result<MissionValidation> {
        self.request(DaemonOperation::ValidateMission {
            scope_id: scope_id.to_string(),
            workflow_id: workflow_id.to_string(),
            target: target.to_string(),
        })
        .await
    }

    pub async fn start_workflow(&self, request: StartWorkflowRequest) -> Result<RunAccepted> {
        self.request(DaemonOperation::StartWorkflow { request })
            .await
    }

    pub async fn get_run_status(&self, run_id: &str) -> Result<RunStatus> {
        self.request(DaemonOperation::GetRunStatus {
            run_id: run_id.to_string(),
        })
        .await
    }

    pub async fn cancel_run(&self, run_id: &str) -> Result<RunStatus> {
        self.request(DaemonOperation::CancelRun {
            run_id: run_id.to_string(),
        })
        .await
    }

    /// Open a dedicated authenticated event stream. Request/response traffic
    /// continues on the primary connection so long-running UI subscriptions
    /// cannot block desktop or MCP commands.
    pub async fn subscribe_events(&self) -> Result<mpsc::Receiver<DomainEvent>> {
        let mut stream = connect_platform(&self.endpoint).await?;
        authenticate_client(&mut stream, &self.credential_id).await?;
        let request_id = Uuid::new_v4().to_string();
        write_frame(
            &mut stream,
            &DaemonRequestEnvelope {
                request_id: request_id.clone(),
                operation: DaemonOperation::SubscribeEvents,
            },
        )
        .await?;
        let response = read_frame::<_, DaemonResponseEnvelope>(&mut stream).await?;
        if response.request_id != request_id || response.status != "ok" {
            return Err(anyhow!(
                "{}",
                response
                    .error_code
                    .or(response.message)
                    .unwrap_or_else(|| "daemon_protocol_error".to_string())
            ));
        }

        let (sender, receiver) = mpsc::channel(256);
        tokio::spawn(async move {
            while let Ok(event) = read_frame::<_, DomainEvent>(&mut stream).await {
                if sender.send(event).await.is_err() {
                    break;
                }
            }
        });
        Ok(receiver)
    }

    pub async fn list_scans(&self) -> Result<Vec<Scan>> {
        self.request(DaemonOperation::ListScans).await
    }

    pub async fn get_scan_evidence(&self, scan_id: &str) -> Result<ScanEvidence> {
        self.request(DaemonOperation::GetScanEvidence {
            scan_id: scan_id.to_string(),
        })
        .await
    }

    pub async fn list_reports(&self) -> Result<Vec<Report>> {
        self.request(DaemonOperation::ListReports).await
    }

    pub async fn get_report(&self, report_id: &str) -> Result<Option<Report>> {
        self.request(DaemonOperation::GetReport {
            report_id: report_id.to_string(),
        })
        .await
    }

    pub async fn refresh_auto_adapters(&self) -> Result<Value> {
        self.request(DaemonOperation::RefreshAutoAdapters).await
    }

    pub async fn runtime_settings(&self) -> Result<AppSettings> {
        self.request(DaemonOperation::RuntimeSettings).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn audit(
        &self,
        capability: Capability,
        request_id: String,
        scope_id: Option<String>,
        arguments: Value,
        outcome: String,
        correlation_id: Option<String>,
    ) -> Result<()> {
        self.request(DaemonOperation::Audit {
            capability,
            request_id,
            scope_id,
            arguments,
            outcome,
            correlation_id,
        })
        .await
    }
}

struct DaemonRuntimeState {
    service: Arc<UniHackService>,
    active_connections: AtomicUsize,
    last_activity: Mutex<Instant>,
}

impl DaemonRuntimeState {
    async fn touch(&self) {
        *self.last_activity.lock().await = Instant::now();
    }
}

pub async fn run_daemon(paths: ServicePaths) -> Result<()> {
    paths.ensure_directories().await?;
    let service = Arc::new(UniHackService::initialize_owner(paths.clone()).await?);
    let endpoint = DaemonEndpoint::from_paths(&paths);
    let state = Arc::new(DaemonRuntimeState {
        service,
        active_connections: AtomicUsize::new(0),
        last_activity: Mutex::new(Instant::now()),
    });
    run_platform_server(endpoint, state).await
}

async fn handle_connection<S>(mut stream: S, state: Arc<DaemonRuntimeState>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    state.active_connections.fetch_add(1, Ordering::SeqCst);
    state.touch().await;
    let result = async {
        let authenticated_client = authenticate_server(&mut stream, &state.service).await?;
        loop {
            let request = match read_frame::<_, DaemonRequestEnvelope>(&mut stream).await {
                Ok(request) => request,
                Err(error) if is_disconnect(&error) => break,
                Err(error) => return Err(error),
            };
            state.touch().await;
            let request_id = request.request_id.clone();
            if matches!(&request.operation, DaemonOperation::SubscribeEvents) {
                let subscription = require_desktop_client(&authenticated_client)
                    .and_then(|_| state.service.subscribe_events());
                match subscription {
                    Ok(mut receiver) => {
                        write_frame(
                            &mut stream,
                            &DaemonResponseEnvelope {
                                request_id,
                                status: "ok".to_string(),
                                data: Some(Value::Null),
                                error_code: None,
                                message: None,
                            },
                        )
                        .await?;
                        loop {
                            match receiver.recv().await {
                                Ok(event) => {
                                    state.touch().await;
                                    write_frame(&mut stream, &event).await?;
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                    write_frame(
                                        &mut stream,
                                        &DomainEvent {
                                            name: crate::events::SYSTEM_NOTIFICATION.to_string(),
                                            payload: serde_json::json!({
                                                "notification_type": "warning",
                                                "title": "Live updates resumed",
                                                "message": format!("{skipped} high-frequency updates were skipped; persisted run status remains authoritative."),
                                                "timestamp": chrono::Utc::now().to_rfc3339(),
                                            }),
                                        },
                                    )
                                    .await?;
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                            }
                        }
                        break;
                    }
                    Err(error) => {
                        write_frame(
                            &mut stream,
                            &DaemonResponseEnvelope {
                                request_id,
                                status: "error".to_string(),
                                data: None,
                                error_code: Some(stable_error(&error)),
                                message: Some(error.to_string()),
                            },
                        )
                        .await?;
                        continue;
                    }
                }
            }
            let response =
                match execute_operation(&state.service, &authenticated_client, request.operation)
                    .await
                {
                    Ok(data) => DaemonResponseEnvelope {
                        request_id,
                        status: "ok".to_string(),
                        data: Some(data),
                        error_code: None,
                        message: None,
                    },
                    Err(error) => DaemonResponseEnvelope {
                        request_id,
                        status: "error".to_string(),
                        data: None,
                        error_code: Some(stable_error(&error)),
                        message: Some(error.to_string()),
                    },
                };
            write_frame(&mut stream, &response).await?;
        }
        Ok(())
    }
    .await;
    state.active_connections.fetch_sub(1, Ordering::SeqCst);
    state.touch().await;
    result
}

async fn execute_operation(
    service: &UniHackService,
    client: &AuthenticatedClient,
    operation: DaemonOperation,
) -> Result<Value> {
    match operation {
        DaemonOperation::Ping => Ok(Value::String("pong".to_string())),
        DaemonOperation::GetStatus => {
            serde_json::to_value(service.status().await?).map_err(Into::into)
        }
        DaemonOperation::ListTools { force_refresh } => {
            serde_json::to_value(service.list_tools(force_refresh).await?).map_err(Into::into)
        }
        DaemonOperation::GetTool {
            name,
            force_refresh,
        } => {
            serde_json::to_value(service.get_tool(&name, force_refresh).await?).map_err(Into::into)
        }
        DaemonOperation::ListWorkflows => {
            serde_json::to_value(service.list_workflows().await?).map_err(Into::into)
        }
        DaemonOperation::GetWorkflow { workflow_id } => {
            serde_json::to_value(service.get_workflow(&workflow_id).await?).map_err(Into::into)
        }
        DaemonOperation::ListEngagements => {
            serde_json::to_value(service.list_engagements().await?).map_err(Into::into)
        }
        DaemonOperation::CreateEngagement { request } => {
            require_desktop_client(client)?;
            serde_json::to_value(service.create_engagement(request).await?).map_err(Into::into)
        }
        DaemonOperation::RevokeEngagement { scope_id } => {
            require_desktop_client(client)?;
            serde_json::to_value(service.revoke_engagement(&scope_id).await?).map_err(Into::into)
        }
        DaemonOperation::ListAuditActivity { limit } => {
            require_desktop_client(client)?;
            serde_json::to_value(service.list_audit_activity(limit).await?).map_err(Into::into)
        }
        DaemonOperation::ValidateMission {
            scope_id,
            workflow_id,
            target,
        } => serde_json::to_value(
            service
                .validate_mission(&scope_id, &workflow_id, &target)
                .await?,
        )
        .map_err(Into::into),
        DaemonOperation::StartWorkflow { request } => {
            if request.revoke_scope_on_completion {
                require_desktop_client(client)?;
            }
            serde_json::to_value(service.start_workflow(request).await?).map_err(Into::into)
        }
        DaemonOperation::GetRunStatus { run_id } => {
            serde_json::to_value(service.get_run_status(&run_id).await?).map_err(Into::into)
        }
        DaemonOperation::CancelRun { run_id } => {
            serde_json::to_value(service.cancel_run(&run_id).await?).map_err(Into::into)
        }
        DaemonOperation::SubscribeEvents => Err(anyhow!("daemon_protocol_error")),
        DaemonOperation::ListScans => {
            serde_json::to_value(service.list_scans().await?).map_err(Into::into)
        }
        DaemonOperation::GetScanEvidence { scan_id } => {
            serde_json::to_value(service.get_scan_evidence(&scan_id).await?).map_err(Into::into)
        }
        DaemonOperation::ListReports => {
            serde_json::to_value(service.list_reports().await?).map_err(Into::into)
        }
        DaemonOperation::GetReport { report_id } => {
            serde_json::to_value(service.get_report(&report_id).await?).map_err(Into::into)
        }
        DaemonOperation::RefreshAutoAdapters => service.refresh_auto_adapters().await,
        DaemonOperation::RuntimeSettings => {
            serde_json::to_value(service.runtime_settings().await?).map_err(Into::into)
        }
        DaemonOperation::Audit {
            capability,
            request_id,
            scope_id,
            arguments,
            outcome,
            correlation_id,
        } => {
            service
                .audit(
                    capability,
                    request_id,
                    scope_id,
                    arguments,
                    outcome,
                    correlation_id,
                )
                .await?;
            Ok(Value::Null)
        }
    }
}

fn require_desktop_client(client: &AuthenticatedClient) -> Result<()> {
    if client.profile_id == LOCAL_OWNER_PROFILE_ID && client.credential_id == DESKTOP_CREDENTIAL_ID
    {
        Ok(())
    } else {
        Err(anyhow!("capability_denied"))
    }
}

async fn authenticate_server<S>(
    stream: &mut S,
    service: &UniHackService,
) -> Result<AuthenticatedClient>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let nonce = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    write_frame(
        stream,
        &ServerHandshake::Challenge {
            protocol_version: DAEMON_PROTOCOL_VERSION,
            nonce: nonce.clone(),
        },
    )
    .await?;
    let mut request = read_frame::<_, ClientHandshake>(stream).await?;
    if let ClientHandshake::Enroll {
        protocol_version,
        profile_id,
        credential_id,
    } = &request
    {
        let profile_is_active = *protocol_version == DAEMON_PROTOCOL_VERSION
            && validate_credential_id(credential_id).is_ok()
            && service
                .database()
                .get_mcp_client_profile(profile_id)
                .await?
                .is_some_and(|profile| profile.revoked_at.is_none());
        if !profile_is_active {
            write_frame(
                stream,
                &ServerHandshake::Rejected {
                    code: "capability_denied".to_string(),
                    message: "The local MCP profile cannot be enrolled".to_string(),
                },
            )
            .await?;
            return Err(anyhow!("capability_denied"));
        }

        let secret = load_or_create_pairing_secret(profile_id, credential_id)?;
        write_frame(
            stream,
            &ServerHandshake::Enrollment {
                protocol_version: DAEMON_PROTOCOL_VERSION,
                secret: hex::encode(secret),
            },
        )
        .await?;
        request = read_frame::<_, ClientHandshake>(stream).await?;
    }

    let ClientHandshake::Authenticate {
        protocol_version,
        profile_id,
        credential_id,
        response,
    } = request
    else {
        return Err(anyhow!("daemon_protocol_error: authentication expected"));
    };

    let authenticated = if protocol_version == DAEMON_PROTOCOL_VERSION
        && validate_credential_id(&credential_id).is_ok()
    {
        service
            .database()
            .get_mcp_client_profile(&profile_id)
            .await?
            .filter(|profile| profile.revoked_at.is_none())
            .is_some()
            && load_pairing_secret(&profile_id, &credential_id)
                .ok()
                .and_then(|secret| challenge_response(&secret, nonce.as_bytes()).ok())
                .is_some_and(|expected| constant_time_hex_eq(&expected, &response))
    } else {
        false
    };

    if !authenticated {
        write_frame(
            stream,
            &ServerHandshake::Rejected {
                code: "capability_denied".to_string(),
                message: "Local daemon authentication failed".to_string(),
            },
        )
        .await?;
        return Err(anyhow!("capability_denied"));
    }

    write_frame(
        stream,
        &ServerHandshake::Authenticated {
            protocol_version: DAEMON_PROTOCOL_VERSION,
        },
    )
    .await?;
    Ok(AuthenticatedClient {
        profile_id,
        credential_id,
    })
}

async fn authenticate_client<S>(stream: &mut S, credential_id: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let handshake = read_frame::<_, ServerHandshake>(stream).await?;
    let ServerHandshake::Challenge {
        protocol_version,
        nonce,
    } = handshake
    else {
        return Err(anyhow!("daemon_protocol_error: challenge expected"));
    };
    if protocol_version != DAEMON_PROTOCOL_VERSION {
        return Err(anyhow!("daemon_protocol_error: unsupported daemon version"));
    }
    validate_credential_id(credential_id)?;
    let secret = match load_client_pairing_secret(LOCAL_OWNER_PROFILE_ID, credential_id) {
        Ok(secret) => secret,
        Err(error) if is_missing_keyring_entry(&error) => {
            write_frame(
                stream,
                &ClientHandshake::Enroll {
                    protocol_version: DAEMON_PROTOCOL_VERSION,
                    profile_id: LOCAL_OWNER_PROFILE_ID.to_string(),
                    credential_id: credential_id.to_string(),
                },
            )
            .await?;
            let ServerHandshake::Enrollment {
                protocol_version,
                secret,
            } = read_frame::<_, ServerHandshake>(stream).await?
            else {
                return Err(anyhow!("daemon_protocol_error: enrollment expected"));
            };
            if protocol_version != DAEMON_PROTOCOL_VERSION {
                return Err(anyhow!(
                    "daemon_protocol_error: unsupported enrollment version"
                ));
            }
            let decoded = hex::decode(&secret)
                .context("daemon_protocol_error: enrollment secret is invalid")?;
            store_client_pairing_secret(LOCAL_OWNER_PROFILE_ID, credential_id, &secret)?;
            decoded
        }
        Err(error) => return Err(error),
    };
    let response = challenge_response(&secret, nonce.as_bytes())?;
    write_frame(
        stream,
        &ClientHandshake::Authenticate {
            protocol_version: DAEMON_PROTOCOL_VERSION,
            profile_id: LOCAL_OWNER_PROFILE_ID.to_string(),
            credential_id: credential_id.to_string(),
            response,
        },
    )
    .await?;
    match read_frame::<_, ServerHandshake>(stream).await? {
        ServerHandshake::Authenticated { protocol_version }
            if protocol_version == DAEMON_PROTOCOL_VERSION =>
        {
            Ok(())
        }
        ServerHandshake::Rejected { code, .. } => Err(anyhow!(code)),
        _ => Err(anyhow!(
            "daemon_protocol_error: authentication acknowledgement expected"
        )),
    }
}

async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(value)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(anyhow!("daemon_protocol_error: frame too large"));
    }
    writer.write_u32(payload.len() as u32).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let length = reader.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(anyhow!("daemon_protocol_error: invalid frame length"));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload).context("daemon_protocol_error: invalid JSON frame")
}

fn load_pairing_secret(profile_id: &str, credential_id: &str) -> Result<Vec<u8>> {
    let entry = keyring::Entry::new(
        PAIRING_SERVICE,
        &pairing_account(profile_id, credential_id)?,
    )?;
    let encoded = entry
        .get_password()
        .context("daemon_unavailable: local pairing secret is unavailable")?;
    hex::decode(encoded).context("daemon_unavailable: local pairing secret is invalid")
}

fn load_client_pairing_secret(profile_id: &str, credential_id: &str) -> Result<Vec<u8>> {
    let entry = keyring::Entry::new(
        PAIRING_SERVICE,
        &client_pairing_account(profile_id, credential_id)?,
    )?;
    let encoded = entry
        .get_password()
        .context("client_pairing_secret_missing")?;
    hex::decode(encoded).context("daemon_unavailable: local client pairing secret is invalid")
}

fn store_client_pairing_secret(profile_id: &str, credential_id: &str, encoded: &str) -> Result<()> {
    let entry = keyring::Entry::new(
        PAIRING_SERVICE,
        &client_pairing_account(profile_id, credential_id)?,
    )?;
    entry
        .set_password(encoded)
        .context("The OS credential store rejected the local MCP client pairing secret")
}

fn is_missing_keyring_entry(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<keyring::Error>()
            .is_some_and(|error| matches!(error, keyring::Error::NoEntry))
    })
}

fn load_or_create_pairing_secret(profile_id: &str, credential_id: &str) -> Result<Vec<u8>> {
    let entry = keyring::Entry::new(
        PAIRING_SERVICE,
        &pairing_account(profile_id, credential_id)?,
    )?;
    match entry.get_password() {
        Ok(encoded) => hex::decode(encoded).context("Stored MCP pairing secret is invalid"),
        Err(keyring::Error::NoEntry) => {
            let encoded = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
            entry
                .set_password(&encoded)
                .context("The OS credential store rejected the MCP pairing secret")?;
            hex::decode(encoded).context("Generated MCP pairing secret is invalid")
        }
        Err(error) => Err(error).context("MCP pairing secret is unavailable"),
    }
}

fn pairing_account(profile_id: &str, credential_id: &str) -> Result<String> {
    // The daemon and MCP proxy use separate credential entries so each signed
    // sidecar owns the item it reads. Sharing one macOS Keychain item across
    // binaries causes an authorization prompt on every unsigned development
    // build and is not a reliable production pairing model.
    Ok(format!(
        "mcp-daemon-profile:{profile_id}:{credential_id}{}",
        credential_namespace_suffix()?
    ))
}

fn client_pairing_account(profile_id: &str, credential_id: &str) -> Result<String> {
    Ok(format!(
        "mcp-client-profile:{profile_id}:{credential_id}{}",
        credential_namespace_suffix()?
    ))
}

fn credential_namespace_suffix() -> Result<String> {
    let Some(namespace) = std::env::var_os("UNIHACK_CREDENTIAL_NAMESPACE") else {
        return Ok(String::new());
    };
    let namespace = namespace
        .into_string()
        .map_err(|_| anyhow!("capability_denied: invalid credential namespace"))?;
    validate_credential_id(&namespace)?;
    Ok(format!(":{namespace}"))
}

fn validate_credential_id(credential_id: &str) -> Result<()> {
    if credential_id.is_empty()
        || credential_id.len() > 64
        || !credential_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(anyhow!(
            "capability_denied: invalid client credential identifier"
        ));
    }
    Ok(())
}

fn challenge_response(secret: &[u8], nonce: &[u8]) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|error| anyhow!(error.to_string()))?;
    mac.update(nonce);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn constant_time_hex_eq(expected: &str, actual: &str) -> bool {
    let (Ok(expected), Ok(actual)) = (hex::decode(expected), hex::decode(actual)) else {
        return false;
    };
    if expected.len() != actual.len() {
        return false;
    }
    expected
        .iter()
        .zip(actual)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn stable_error(error: &anyhow::Error) -> String {
    let message = error.to_string();
    [
        "scope_required",
        "scope_mismatch",
        "scope_signature_invalid",
        "grant_expired",
        "grant_revoked",
        "capability_denied",
        "workflow_quarantined",
        "workflow_revision_mismatch",
        "verification_failed",
        "tool_unavailable",
        "scope_budget_exceeded",
        "idempotency_in_progress",
        "idempotency_conflict",
        "run_not_found",
        "scan_not_found",
        "scan_already_running",
        "elevation_required",
        "daemon_unavailable",
    ]
    .into_iter()
    .find(|code| message.contains(code))
    .unwrap_or("daemon_error")
    .to_string()
}

fn is_disconnect(error: &anyhow::Error) -> bool {
    error.downcast_ref::<std::io::Error>().is_some_and(|error| {
        matches!(
            error.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
        )
    })
}

fn resolve_daemon_binary() -> Result<PathBuf> {
    if let Some(configured) = std::env::var_os("UNIHACK_DAEMON_BINARY") {
        let path = PathBuf::from(configured);
        if path.is_file() {
            return Ok(path);
        }
    }
    let name = if cfg!(windows) {
        "unihackd.exe"
    } else {
        "unihackd"
    };
    let mut candidates = Vec::new();
    if let Ok(current) = std::env::current_exe() {
        if let Some(parent) = current.parent() {
            candidates.push(parent.join(name));
            candidates.push(parent.join("../Resources").join(name));
            candidates.push(parent.join("../Resources/binaries").join(name));
        }
    }
    candidates.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/debug")
            .join(name),
    );
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| anyhow!("daemon_unavailable: unihackd binary was not found"))
}

#[cfg(unix)]
async fn connect_platform(endpoint: &DaemonEndpoint) -> Result<PlatformClient> {
    UnixStream::connect(&endpoint.socket_path)
        .await
        .with_context(|| format!("daemon_unavailable: {}", endpoint.socket_path.display()))
}

#[cfg(windows)]
async fn connect_platform(endpoint: &DaemonEndpoint) -> Result<PlatformClient> {
    ClientOptions::new()
        .open(&endpoint.pipe_name)
        .with_context(|| format!("daemon_unavailable: {}", endpoint.pipe_name))
}

#[cfg(unix)]
async fn run_platform_server(
    endpoint: DaemonEndpoint,
    state: Arc<DaemonRuntimeState>,
) -> Result<()> {
    if endpoint.socket_path.exists() {
        if UnixStream::connect(&endpoint.socket_path).await.is_ok() {
            return Err(anyhow!(
                "daemon_unavailable: another daemon is already running"
            ));
        }
        std::fs::remove_file(&endpoint.socket_path).with_context(|| {
            format!(
                "Failed to remove stale daemon socket {}",
                endpoint.socket_path.display()
            )
        })?;
    }
    let listener = UnixListener::bind(&endpoint.socket_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &endpoint.socket_path,
            std::fs::Permissions::from_mode(0o600),
        )?;
    }
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let connection_state = state.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(stream, connection_state).await {
                        eprintln!("UniHack daemon client disconnected: {error}");
                    }
                });
            }
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                let idle = state.last_activity.lock().await.elapsed();
                let active_runs = state
                    .service
                    .database()
                    .count_active_workflow_executions()
                    .await
                    .unwrap_or(1);
                if state.active_connections.load(Ordering::SeqCst) == 0
                    && active_runs == 0
                    && idle >= IDLE_TIMEOUT
                {
                    break;
                }
            }
        }
    }
    let _ = std::fs::remove_file(&endpoint.socket_path);
    Ok(())
}

#[cfg(windows)]
async fn run_platform_server(
    endpoint: DaemonEndpoint,
    state: Arc<DaemonRuntimeState>,
) -> Result<()> {
    let mut first = true;
    loop {
        let mut options = ServerOptions::new();
        options.reject_remote_clients(true);
        if first {
            options.first_pipe_instance(true);
            first = false;
        }
        let server: NamedPipeServer = options.create(&endpoint.pipe_name)?;
        tokio::select! {
            result = server.connect() => {
                result?;
                let connection_state = state.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(server, connection_state).await {
                        eprintln!("UniHack daemon client disconnected: {error}");
                    }
                });
            }
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                let idle = state.last_activity.lock().await.elapsed();
                let active_runs = state
                    .service
                    .database()
                    .count_active_workflow_executions()
                    .await
                    .unwrap_or(1);
                if state.active_connections.load(Ordering::SeqCst) == 0
                    && active_runs == 0
                    && idle >= IDLE_TIMEOUT
                {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        challenge_response, constant_time_hex_eq, require_desktop_client, validate_credential_id,
        AuthenticatedClient,
    };
    use crate::service::LOCAL_OWNER_PROFILE_ID;

    #[test]
    fn hmac_challenge_rejects_modified_responses() {
        let expected = challenge_response(b"secret", b"nonce").unwrap();
        assert!(constant_time_hex_eq(&expected, &expected));
        let mut modified = expected.clone();
        modified.replace_range(0..2, "ff");
        assert!(!constant_time_hex_eq(&expected, &modified));
    }

    #[test]
    fn credential_ids_are_bounded_before_keyring_lookup() {
        assert!(validate_credential_id("mcp").is_ok());
        assert!(validate_credential_id("desktop_client-2").is_ok());
        assert!(validate_credential_id("").is_err());
        assert!(validate_credential_id("../../other-account").is_err());
        assert!(validate_credential_id("Desktop").is_err());
    }

    #[test]
    fn engagement_mutations_require_the_desktop_credential() {
        let desktop = AuthenticatedClient {
            profile_id: LOCAL_OWNER_PROFILE_ID.to_string(),
            credential_id: super::DESKTOP_CREDENTIAL_ID.to_string(),
        };
        let mcp = AuthenticatedClient {
            profile_id: LOCAL_OWNER_PROFILE_ID.to_string(),
            credential_id: "mcp".to_string(),
        };
        assert!(require_desktop_client(&desktop).is_ok());
        assert!(require_desktop_client(&mcp).is_err());
    }
}
