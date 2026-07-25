//! Transport-neutral UniHack application service.
//!
//! Tauri commands, the local daemon, and MCP tools must call this layer rather
//! than duplicating validation or process-launch behavior.

use crate::adapters::auto::AutoAdapterService;
use crate::database::{
    Database, IdempotencyReservation, Report, Scan, WorkflowArtifact, WorkflowExecutionGovernance,
    WorkflowFinding,
};
use crate::events::{DomainEvent, SharedEventSink};
use crate::governance::{
    AuthorizedTarget, Capability, EngagementScope, McpAuditEvent, McpClientProfile, RiskTier,
    ScopeBudget, WorkflowRevisionRecord, WorkflowTrustRecord, WorkflowTrustSource,
};
use crate::settings::AppSettings;
use crate::tools::discovery::{ToolDiscoveryService, ToolRecord};
use crate::workflow::loader::WorkflowLoader;
use crate::workflow::{
    engine::{ExecutionGuard, WorkflowEngine},
    types::{ExecutionStatus, WorkflowCompatibility, WorkflowTemplate},
};
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, RwLock};
use uuid::Uuid;

pub const LOCAL_OWNER_PROFILE_ID: &str = "local-owner-automation";
const KEYRING_SERVICE: &str = "com.aibugbountyscanner.app";
const SCOPE_SIGNING_ACCOUNT: &str = "daemon-scope-signing-key-v1";
const AUDIT_SIGNING_ACCOUNT: &str = "daemon-audit-signing-key-v1";

#[derive(Debug, Clone)]
pub struct ServicePaths {
    pub app_data_dir: PathBuf,
    pub workflows_dir: PathBuf,
    pub results_dir: PathBuf,
    pub reports_dir: PathBuf,
    pub artifacts_dir: PathBuf,
}

impl ServicePaths {
    pub fn discover() -> Result<Self> {
        let app_data_dir = std::env::var_os("UNIHACK_APP_DATA_DIR")
            .map(PathBuf::from)
            .or_else(|| dirs::data_dir().map(|base| base.join("com.aibugbountyscanner.app")))
            .ok_or_else(|| anyhow!("Unable to determine the UniHack application-data directory"))?;

        let workflows_dir = if let Some(configured) = std::env::var_os("UNIHACK_WORKFLOWS_DIR") {
            PathBuf::from(configured)
        } else {
            discover_workflows_dir()?
        };

        if !workflows_dir.exists() {
            return Err(anyhow!(
                "Workflow resources were not found at {}",
                workflows_dir.display()
            ));
        }

        Ok(Self {
            results_dir: app_data_dir.join("results"),
            reports_dir: app_data_dir.join("reports"),
            artifacts_dir: app_data_dir.join("artifacts"),
            app_data_dir,
            workflows_dir,
        })
    }

    pub async fn ensure_directories(&self) -> Result<()> {
        for directory in [
            &self.app_data_dir,
            &self.results_dir,
            &self.reports_dir,
            &self.artifacts_dir,
        ] {
            tokio::fs::create_dir_all(directory)
                .await
                .with_context(|| format!("Failed to create {}", directory.display()))?;
        }
        Ok(())
    }
}

fn discover_workflows_dir() -> Result<PathBuf> {
    let development = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow!("Tauri crate must have a project parent directory"))?
        .join("app/workflows");
    if development.exists() {
        return Ok(development);
    }

    let executable = std::env::current_exe()?;
    let executable_dir = executable
        .parent()
        .ok_or_else(|| anyhow!("UniHack executable has no parent directory"))?;
    let candidates = [
        executable_dir.join("workflows"),
        executable_dir.join("../Resources/workflows"),
        executable_dir.join("../share/unihack/workflows"),
    ];
    candidates
        .into_iter()
        .find(|candidate| candidate.exists())
        .ok_or_else(|| anyhow!("Bundled workflow resources could not be located"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatus {
    pub product: String,
    pub version: String,
    pub api_version: String,
    pub platform: String,
    pub architecture: String,
    pub profile_id: String,
    pub profile_revoked: bool,
    pub workflows_available: usize,
    pub tools_available: usize,
    pub tools_known: usize,
    pub execution_owner: String,
    pub native_execution_enabled: bool,
    pub remote_transport_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowCatalogEntry {
    pub workflow: WorkflowTemplate,
    pub compatibility: WorkflowCompatibility,
    pub revision_hash: String,
    pub trust_source: WorkflowTrustSource,
    pub risk_tier: RiskTier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionValidation {
    pub valid: bool,
    pub scope_id: String,
    pub workflow_id: String,
    pub target: String,
    pub revision_hash: String,
    pub risk_tier: RiskTier,
    pub missing_tools: Vec<String>,
    pub warnings: Vec<String>,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateEngagementRequest {
    pub name: String,
    pub targets: Vec<String>,
    #[serde(default)]
    pub workflow_ids: Vec<String>,
    pub allowed_risk_tier: RiskTier,
    pub duration_minutes: u32,
    #[serde(default)]
    pub authorization_confirmed: bool,
    #[serde(default)]
    pub budget: ScopeBudget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanEvidence {
    pub scan: Scan,
    pub execution_id: Option<String>,
    pub artifacts: Vec<WorkflowArtifact>,
    pub findings: Vec<WorkflowFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartWorkflowRequest {
    pub scope_id: String,
    pub workflow_id: String,
    pub revision_hash: String,
    pub target: String,
    pub idempotency_key: String,
    pub scan_id: Option<String>,
    pub scan_name: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub revoke_scope_on_completion: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunAccepted {
    pub run_id: String,
    pub scan_id: String,
    pub scope_id: String,
    pub workflow_id: String,
    pub revision_hash: String,
    pub status: String,
    pub replayed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunStatus {
    pub run_id: String,
    pub scan_id: Option<String>,
    pub scope_id: String,
    pub workflow_id: String,
    pub revision_hash: String,
    pub status: String,
    pub terminal: bool,
    pub progress: u32,
    pub current_step: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub logs: Vec<String>,
    pub logs_truncated: bool,
}

#[derive(Clone)]
pub struct UniHackService {
    paths: ServicePaths,
    db: Arc<Database>,
    owns_execution_state: bool,
    tool_discovery: Arc<RwLock<ToolDiscoveryService>>,
    auto_adapters: Arc<AutoAdapterService>,
    profile: Arc<RwLock<McpClientProfile>>,
    settings: Arc<RwLock<AppSettings>>,
    workflow_engine: Option<Arc<WorkflowEngine>>,
    event_sender: Option<broadcast::Sender<DomainEvent>>,
    audit_signing_key: Option<Arc<Vec<u8>>>,
    audit_lock: Arc<Mutex<()>>,
}

impl UniHackService {
    /// Initialize an auxiliary service client. It applies idempotent schema
    /// migrations but does not mark running Tauri-owned executions interrupted.
    pub async fn initialize_client(paths: ServicePaths) -> Result<Self> {
        Self::initialize(paths, false).await
    }

    /// Initialize the single execution owner. The daemon is the only process
    /// allowed to recover interrupted runs or own child-process lifecycle.
    pub async fn initialize_owner(paths: ServicePaths) -> Result<Self> {
        Self::initialize(paths, true).await
    }

    async fn initialize(paths: ServicePaths, owns_execution_state: bool) -> Result<Self> {
        paths.ensure_directories().await?;
        let db = Arc::new(if owns_execution_state {
            Database::new(paths.app_data_dir.clone()).await?
        } else {
            Database::open_client(paths.app_data_dir.clone()).await?
        });
        let loaded_settings = db
            .get_setting("runtime")
            .await?
            .and_then(|value| serde_json::from_str::<AppSettings>(&value).ok())
            .filter(|settings| settings.validate().is_ok())
            .unwrap_or_default();

        let mut discovery =
            ToolDiscoveryService::new(paths.app_data_dir.join("tool_discovery_cache.json"));
        if let Err(error) = discovery.load_cache().await {
            eprintln!("UniHack MCP could not load the tool cache: {error}");
        }

        let profile = match db.get_mcp_client_profile(LOCAL_OWNER_PROFILE_ID).await? {
            Some(mut existing) => {
                if existing.revoked_at.is_none() {
                    let expected = McpClientProfile::owner_automation();
                    let mut changed = false;
                    for capability in expected.capabilities {
                        if !existing.capabilities.contains(&capability) {
                            existing.capabilities.push(capability);
                            changed = true;
                        }
                    }
                    if changed {
                        db.upsert_mcp_client_profile(&existing).await?;
                    }
                }
                existing
            }
            None => {
                let created = McpClientProfile::owner_automation();
                db.upsert_mcp_client_profile(&created).await?;
                created
            }
        };
        if profile.revoked_at.is_none() {
            db.touch_mcp_client_profile(&profile.id).await?;
        }

        let auto_adapters =
            Arc::new(AutoAdapterService::load(paths.app_data_dir.join("auto_adapters.json")).await);
        let tool_discovery = Arc::new(RwLock::new(discovery));
        let settings = Arc::new(RwLock::new(loaded_settings));
        let (event_sink, event_sender) = if owns_execution_state {
            let (sink, sender) = SharedEventSink::broadcast(512);
            (sink, Some(sender))
        } else {
            (SharedEventSink::noop(), None)
        };
        let workflow_engine = owns_execution_state.then(|| {
            Arc::new(WorkflowEngine::new(
                event_sink,
                tool_discovery.clone(),
                paths.artifacts_dir.clone(),
                paths.workflows_dir.clone(),
                db.clone(),
                settings.clone(),
            ))
        });
        let audit_signing_key = owns_execution_state
            .then(load_or_create_audit_signing_key)
            .transpose()?
            .map(Arc::new);

        Ok(Self {
            paths,
            db,
            owns_execution_state,
            tool_discovery,
            auto_adapters,
            profile: Arc::new(RwLock::new(profile)),
            settings,
            workflow_engine,
            event_sender,
            audit_signing_key,
            audit_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn paths(&self) -> &ServicePaths {
        &self.paths
    }

    pub fn database(&self) -> Arc<Database> {
        self.db.clone()
    }

    pub fn subscribe_events(&self) -> Result<broadcast::Receiver<DomainEvent>> {
        self.event_sender
            .as_ref()
            .map(broadcast::Sender::subscribe)
            .ok_or_else(|| anyhow!("daemon_unavailable"))
    }

    pub async fn profile(&self) -> McpClientProfile {
        self.profile.read().await.clone()
    }

    pub async fn require_capability(&self, capability: Capability) -> Result<()> {
        let profile = self.profile.read().await;
        if profile.allows(&capability) {
            Ok(())
        } else {
            Err(anyhow!("capability_denied"))
        }
    }

    pub async fn status(&self) -> Result<ServiceStatus> {
        self.require_capability(Capability::ReadStatus).await?;
        let workflows = WorkflowLoader::new(&self.paths.workflows_dir)
            .load_all_workflows()
            .await?;
        let tools = self
            .tool_discovery
            .read()
            .await
            .get_all_tool_records(false)
            .await;
        let profile = self.profile.read().await;
        Ok(ServiceStatus {
            product: "UniHack".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            api_version: crate::governance::GOVERNANCE_API_VERSION.to_string(),
            platform: std::env::consts::OS.to_string(),
            architecture: std::env::consts::ARCH.to_string(),
            profile_id: profile.id.clone(),
            profile_revoked: profile.revoked_at.is_some(),
            workflows_available: workflows.len(),
            tools_available: tools.iter().filter(|tool| tool.installed).count(),
            tools_known: tools.len(),
            execution_owner: if self.owns_execution_state {
                "unihackd".to_string()
            } else {
                "tauri_compatibility_mode".to_string()
            },
            native_execution_enabled: self.workflow_engine.is_some(),
            remote_transport_enabled: false,
        })
    }

    pub async fn list_tools(&self, force_refresh: bool) -> Result<Vec<ToolRecord>> {
        self.require_capability(Capability::ReadTools).await?;
        Ok(self
            .tool_discovery
            .read()
            .await
            .get_all_tool_records(force_refresh)
            .await)
    }

    pub async fn get_tool(&self, name: &str, force_refresh: bool) -> Result<Option<ToolRecord>> {
        self.require_capability(Capability::ReadTools).await?;
        Ok(self
            .tool_discovery
            .read()
            .await
            .get_tool_record(name, force_refresh)
            .await)
    }

    pub async fn list_workflows(&self) -> Result<Vec<WorkflowCatalogEntry>> {
        self.require_capability(Capability::ReadWorkflows).await?;
        let loader = WorkflowLoader::new(&self.paths.workflows_dir);
        let mut entries = Vec::new();
        for workflow in loader.load_all_workflows().await?.into_values() {
            entries.push(self.register_packaged_workflow(workflow).await?);
        }
        entries.sort_by(|left, right| left.workflow.name.cmp(&right.workflow.name));
        Ok(entries)
    }

    pub async fn get_workflow(&self, workflow_id: &str) -> Result<WorkflowCatalogEntry> {
        self.require_capability(Capability::ReadWorkflows).await?;
        let workflow = WorkflowLoader::new(&self.paths.workflows_dir)
            .load_workflow(workflow_id)
            .await?;
        self.register_packaged_workflow(workflow).await
    }

    async fn register_packaged_workflow(
        &self,
        workflow: WorkflowTemplate,
    ) -> Result<WorkflowCatalogEntry> {
        let compatibility = self
            .tool_discovery
            .read()
            .await
            .get_tool_compatibility(&workflow)
            .await?;
        let document = serde_json::to_value(&workflow)?;
        let revision = WorkflowRevisionRecord::from_document(&workflow.id, document)
            .map_err(|error| anyhow!(error))?;
        self.db.upsert_workflow_revision(&revision).await?;
        self.db
            .upsert_workflow_trust(&WorkflowTrustRecord {
                revision_hash: revision.revision_hash.clone(),
                source: WorkflowTrustSource::Packaged,
                verifier_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                evidence_hash: None,
                trusted_at: Utc::now(),
                revoked_at: None,
            })
            .await?;
        Ok(WorkflowCatalogEntry {
            risk_tier: workflow_risk(&workflow),
            workflow,
            compatibility,
            revision_hash: revision.revision_hash,
            trust_source: WorkflowTrustSource::Packaged,
        })
    }

    pub async fn list_engagements(&self) -> Result<Vec<EngagementScope>> {
        self.require_capability(Capability::ValidateMission).await?;
        let profile = self.profile.read().await;
        self.db.list_engagement_scopes(&profile.id).await
    }

    /// Desktop-only creation path. This is intentionally not exported as an MCP
    /// tool; an agent cannot mint its own authorization.
    pub async fn create_engagement(
        &self,
        request: CreateEngagementRequest,
    ) -> Result<EngagementScope> {
        self.require_capability(Capability::ManageEngagements)
            .await?;
        if !request.authorization_confirmed {
            return Err(anyhow!(
                "Explicit authorization confirmation is required to create an engagement"
            ));
        }
        let name = request.name.trim();
        if name.is_empty() || name.chars().count() > 120 {
            return Err(anyhow!(
                "Engagement name must contain between 1 and 120 characters"
            ));
        }
        if request.targets.is_empty() || request.targets.len() > 128 {
            return Err(anyhow!(
                "An engagement must contain between 1 and 128 target boundaries"
            ));
        }
        if !(5..=43_200).contains(&request.duration_minutes) {
            return Err(anyhow!(
                "Engagement duration must be between 5 minutes and 30 days"
            ));
        }
        validate_scope_budget(&request.budget)?;

        let mut unique_workflows = HashSet::new();
        for workflow_id in &request.workflow_ids {
            if !unique_workflows.insert(workflow_id.clone()) {
                return Err(anyhow!("Workflow IDs in an engagement must be unique"));
            }
            self.get_workflow(workflow_id).await?;
        }

        let profile = self.profile.read().await;
        let targets = request
            .targets
            .iter()
            .map(|target| AuthorizedTarget::parse(target).map_err(|error| anyhow!(error)))
            .collect::<Result<Vec<_>>>()?;
        let starts_at = Utc::now();
        let expires_at = starts_at + chrono::Duration::minutes(request.duration_minutes as i64);
        let mut scope = EngagementScope::new(
            name.to_string(),
            profile.id.clone(),
            targets,
            request.workflow_ids,
            request.allowed_risk_tier,
            starts_at,
            expires_at,
            request.budget,
        )
        .map_err(|error| anyhow!(error))?;
        let signing_key = load_or_create_scope_signing_key()?;
        scope.sign(&signing_key).map_err(|error| anyhow!(error))?;
        self.db.upsert_engagement_scope(&scope).await?;
        drop(profile);
        self.audit(
            Capability::ManageEngagements,
            Uuid::new_v4().to_string(),
            Some(scope.id.clone()),
            json!({
                "action": "create",
                "targetCount": scope.targets.len(),
                "workflowCount": scope.workflow_ids.len(),
                "expiresAt": scope.expires_at,
            }),
            "success".to_string(),
            None,
        )
        .await?;
        Ok(scope)
    }

    pub async fn revoke_engagement(&self, scope_id: &str) -> Result<EngagementScope> {
        self.require_capability(Capability::ManageEngagements)
            .await?;
        let profile = self.profile.read().await;
        let mut scope = self
            .db
            .get_engagement_scope(scope_id)
            .await?
            .ok_or_else(|| anyhow!("scope_required"))?;
        if scope.principal_id != profile.id {
            return Err(anyhow!("capability_denied"));
        }
        if scope.revoked_at.is_none() {
            scope.revoked_at = Some(Utc::now());
            scope.revision = scope.revision.saturating_add(1);
            let signing_key = load_or_create_scope_signing_key()?;
            scope.sign(&signing_key).map_err(|error| anyhow!(error))?;
            self.db.upsert_engagement_scope(&scope).await?;
        }
        drop(profile);
        if let Some(engine) = &self.workflow_engine {
            for execution_id in self.db.list_scope_active_execution_ids(&scope.id).await? {
                if let Err(error) = engine.stop_execution(&execution_id).await {
                    eprintln!(
                        "UniHack could not immediately cancel revoked execution {execution_id}: {error}"
                    );
                }
            }
        }
        self.audit(
            Capability::ManageEngagements,
            Uuid::new_v4().to_string(),
            Some(scope.id.clone()),
            json!({ "action": "revoke", "revision": scope.revision }),
            "success".to_string(),
            None,
        )
        .await?;
        Ok(scope)
    }

    pub async fn validate_mission(
        &self,
        scope_id: &str,
        workflow_id: &str,
        target: &str,
    ) -> Result<MissionValidation> {
        self.require_capability(Capability::ValidateMission).await?;
        let workflow = self.get_workflow(workflow_id).await?;
        let profile = self.profile.read().await;
        let scope = self
            .db
            .get_engagement_scope(scope_id)
            .await?
            .ok_or_else(|| anyhow!("scope_required"))?;
        let signing_key = load_scope_signing_key()?;
        if !scope
            .verify_signature(&signing_key)
            .map_err(|error| anyhow!(error))?
        {
            return Err(anyhow!("scope_signature_invalid"));
        }

        let validation = scope.validate_use(
            &profile.id,
            workflow_id,
            target,
            workflow.risk_tier,
            Utc::now(),
        );
        let error_code = validation.err();
        Ok(MissionValidation {
            valid: error_code.is_none() && workflow.compatibility.compatible,
            scope_id: scope.id,
            workflow_id: workflow_id.to_string(),
            target: target.to_string(),
            revision_hash: workflow.revision_hash,
            risk_tier: workflow.risk_tier,
            missing_tools: workflow.compatibility.missing_tools,
            warnings: workflow.compatibility.warnings,
            error_code,
        })
    }

    pub async fn start_workflow(&self, request: StartWorkflowRequest) -> Result<RunAccepted> {
        self.require_capability(Capability::ExecuteWorkflow).await?;
        validate_idempotency_key(&request.idempotency_key)?;
        let request_hash = hex::encode(Sha256::digest(serde_json::to_vec(&request)?));
        let profile = self.profile.read().await.clone();
        let scope = self
            .db
            .get_engagement_scope(&request.scope_id)
            .await?
            .ok_or_else(|| anyhow!("scope_required"))?;
        let expires_at = scope.expires_at.min(Utc::now() + ChronoDuration::hours(24));
        match self
            .db
            .reserve_idempotency_key(
                &profile.id,
                &request.idempotency_key,
                &Capability::ExecuteWorkflow,
                &request_hash,
                expires_at,
            )
            .await?
        {
            IdempotencyReservation::Replayed(response) => {
                let mut accepted: RunAccepted = serde_json::from_str(&response)
                    .context("Stored idempotent response is invalid")?;
                accepted.replayed = true;
                return Ok(accepted);
            }
            IdempotencyReservation::InProgress => {
                return Err(anyhow!("idempotency_in_progress"));
            }
            IdempotencyReservation::Conflict => {
                return Err(anyhow!("idempotency_conflict"));
            }
            IdempotencyReservation::Acquired => {}
        }

        let result = self
            .start_workflow_once(request.clone(), profile.clone())
            .await;
        match result {
            Ok(accepted) => {
                let encoded = serde_json::to_string(&accepted)?;
                if let Err(error) = self
                    .db
                    .complete_idempotency_key(
                        &profile.id,
                        &request.idempotency_key,
                        &request_hash,
                        &encoded,
                    )
                    .await
                {
                    // The execution is already bound and running. Preserve the
                    // pending reservation rather than allowing a duplicate run.
                    eprintln!(
                        "UniHack could not finalize idempotency key {}: {error}",
                        request.idempotency_key
                    );
                }
                if request.revoke_scope_on_completion {
                    self.schedule_scope_revocation(
                        accepted.run_id.clone(),
                        accepted.scope_id.clone(),
                    );
                }
                Ok(accepted)
            }
            Err(error) => {
                self.db
                    .release_idempotency_key(&profile.id, &request.idempotency_key, &request_hash)
                    .await?;
                Err(error)
            }
        }
    }

    async fn start_workflow_once(
        &self,
        request: StartWorkflowRequest,
        profile: McpClientProfile,
    ) -> Result<RunAccepted> {
        let engine = self
            .workflow_engine
            .clone()
            .ok_or_else(|| anyhow!("daemon_unavailable"))?;
        if request.revision_hash.len() != 64
            || !request
                .revision_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(anyhow!("workflow_quarantined"));
        }
        let catalog_entry = self.get_workflow(&request.workflow_id).await?;
        if catalog_entry.revision_hash != request.revision_hash {
            return Err(anyhow!("workflow_revision_mismatch"));
        }
        if !catalog_entry.compatibility.compatible {
            return Err(anyhow!("tool_unavailable"));
        }
        let revision = self
            .db
            .get_workflow_revision(&request.revision_hash)
            .await?
            .ok_or_else(|| anyhow!("workflow_quarantined"))?;
        if !revision.immutable || revision.workflow_id != request.workflow_id {
            return Err(anyhow!("workflow_quarantined"));
        }
        let recalculated =
            WorkflowRevisionRecord::from_document(&revision.workflow_id, revision.document.clone())
                .map_err(|error| anyhow!(error))?;
        if recalculated.revision_hash != request.revision_hash {
            return Err(anyhow!("workflow_revision_mismatch"));
        }
        let trust = self
            .db
            .get_workflow_trust(&request.revision_hash)
            .await?
            .ok_or_else(|| anyhow!("workflow_quarantined"))?;
        if trust.revoked_at.is_some() {
            return Err(anyhow!("workflow_quarantined"));
        }
        let workflow: WorkflowTemplate = serde_json::from_value(revision.document.clone())
            .context("Stored workflow revision is invalid")?;
        if workflow.id != request.workflow_id {
            return Err(anyhow!("workflow_revision_mismatch"));
        }

        let scope = self
            .db
            .get_engagement_scope(&request.scope_id)
            .await?
            .ok_or_else(|| anyhow!("scope_required"))?;
        let signing_key = load_scope_signing_key()?;
        if !scope
            .verify_signature(&signing_key)
            .map_err(|error| anyhow!(error))?
        {
            return Err(anyhow!("scope_signature_invalid"));
        }
        scope
            .validate_use(
                &profile.id,
                &request.workflow_id,
                &request.target,
                catalog_entry.risk_tier,
                Utc::now(),
            )
            .map_err(|error| anyhow!(error))?;

        let executions_used = self.db.count_scope_executions(&scope.id).await?;
        if executions_used >= scope.budget.max_executions {
            return Err(anyhow!("scope_budget_exceeded"));
        }
        let configured_parallelism = self.settings.read().await.max_parallel_steps;
        let run_parallelism = configured_parallelism
            .min(scope.budget.max_concurrent_processes as usize)
            .max(1);
        let active_runs = self.db.count_scope_active_executions(&scope.id).await? as usize;
        if (active_runs + 1).saturating_mul(run_parallelism)
            > scope.budget.max_concurrent_processes as usize
        {
            return Err(anyhow!("scope_budget_exceeded"));
        }
        if scope_output_bytes(&self.db, &self.paths.results_dir, &scope.id).await?
            >= scope.budget.max_output_bytes
        {
            return Err(anyhow!("scope_budget_exceeded"));
        }

        let scan_name = request
            .scan_name
            .as_deref()
            .unwrap_or(&workflow.name)
            .trim();
        if scan_name.is_empty() || scan_name.chars().count() > 120 {
            return Err(anyhow!(
                "Scan name must contain between 1 and 120 characters"
            ));
        }
        if request
            .description
            .as_ref()
            .is_some_and(|description| description.chars().count() > 4_000)
        {
            return Err(anyhow!("Scan description cannot exceed 4000 characters"));
        }
        let target = crate::security::validate_scan_target(&request.target)
            .map_err(|error| anyhow!(error))?;
        let execution_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let (scan, scan_was_created) = if let Some(scan_id) = &request.scan_id {
            let mut scan = self
                .db
                .get_scan(scan_id)
                .await?
                .ok_or_else(|| anyhow!("scan_not_found"))?;
            if scan.status.eq_ignore_ascii_case("running") {
                return Err(anyhow!("scan_already_running"));
            }
            if scan.workflow_id.as_deref() != Some(workflow.id.as_str())
                || crate::security::validate_scan_target(&scan.target)
                    .map_err(|error| anyhow!(error))?
                    != target
            {
                return Err(anyhow!("workflow_revision_mismatch"));
            }
            scan.name = scan_name.to_string();
            scan.status = "pending".to_string();
            scan.started = now;
            scan.completed = None;
            scan.progress = 0;
            scan.current_test = None;
            scan.current_step = None;
            scan.total_steps = Some(workflow.steps.len() as i32);
            scan.working_directory =
                Some(managed_scan_directory(&self.paths.results_dir, scan_id).await?);
            scan.target_validated = true;
            scan.updated_at = now;
            self.db.update_scan(&scan).await?;
            (scan, false)
        } else {
            let scan_id = Uuid::new_v4().to_string();
            let working_directory =
                managed_scan_directory(&self.paths.results_dir, &scan_id).await?;
            let scan = Scan {
                id: scan_id,
                name: scan_name.to_string(),
                target: target.clone(),
                status: "pending".to_string(),
                scan_type: workflow.category.clone(),
                workflow_id: Some(workflow.id.clone()),
                started: now,
                completed: None,
                progress: 0,
                current_test: None,
                current_step: None,
                total_steps: Some(workflow.steps.len() as i32),
                duration: None,
                estimated_time: None,
                description: request.description.clone(),
                tags: None,
                working_directory: Some(working_directory),
                agents: Some("automation".to_string()),
                command_log: None,
                target_validated: true,
                vulnerabilities: Some(0),
                critical: Some(0),
                high: Some(0),
                medium: Some(0),
                low: Some(0),
                created_at: now,
                updated_at: now,
            };
            self.db.create_scan(&scan).await?;
            (scan, true)
        };
        let scan_id = scan.id.clone();
        let working_directory = scan
            .working_directory
            .clone()
            .ok_or_else(|| anyhow!("Managed scan directory is unavailable"))?;

        let request_id = Uuid::new_v4().to_string();
        let governance = WorkflowExecutionGovernance {
            execution_id: execution_id.clone(),
            revision_hash: request.revision_hash.clone(),
            scope_id: scope.id.clone(),
            principal_id: profile.id.clone(),
            request_id,
            created_at: now,
        };
        let guard = Arc::new(ScopeExecutionGuard {
            db: self.db.clone(),
            results_dir: self.paths.results_dir.clone(),
            signing_key,
            execution_id: execution_id.clone(),
            scope_id: scope.id.clone(),
            principal_id: profile.id,
            workflow_id: workflow.id.clone(),
            revision_hash: request.revision_hash.clone(),
            target,
            risk_tier: catalog_entry.risk_tier,
            started_at: now,
            max_runtime_seconds: scope.budget.max_runtime_seconds,
            max_output_bytes: scope.budget.max_output_bytes,
        });
        let inputs = crate::security::workflow_target_inputs(&request.target)
            .map_err(|error| anyhow!(error))?;
        if let Err(error) = engine
            .execute_workflow_revision(
                execution_id.clone(),
                workflow,
                inputs,
                working_directory,
                Some(scan_id.clone()),
                governance,
                run_parallelism,
                guard,
            )
            .await
        {
            let mut failed_scan = scan;
            failed_scan.status = "failed".to_string();
            failed_scan.completed = Some(Utc::now());
            failed_scan.updated_at = Utc::now();
            let _ = self.db.update_scan(&failed_scan).await;
            if scan_was_created {
                eprintln!(
                    "A failed start left scan {} as an auditable record",
                    failed_scan.id
                );
            }
            return Err(error);
        }

        Ok(RunAccepted {
            run_id: execution_id,
            scan_id,
            scope_id: scope.id,
            workflow_id: request.workflow_id,
            revision_hash: request.revision_hash,
            status: "pending".to_string(),
            replayed: false,
        })
    }

    pub async fn get_run_status(&self, run_id: &str) -> Result<RunStatus> {
        self.require_capability(Capability::ReadScans).await?;
        let engine = self
            .workflow_engine
            .clone()
            .ok_or_else(|| anyhow!("daemon_unavailable"))?;
        let governance = self.authorized_run_governance(run_id).await?;
        let execution = engine
            .get_execution_status(run_id)
            .await?
            .ok_or_else(|| anyhow!("run_not_found"))?;
        Ok(run_status(execution, governance))
    }

    pub async fn cancel_run(&self, run_id: &str) -> Result<RunStatus> {
        self.require_capability(Capability::CancelExecution).await?;
        let engine = self
            .workflow_engine
            .clone()
            .ok_or_else(|| anyhow!("daemon_unavailable"))?;
        let governance = self.authorized_run_governance(run_id).await?;
        let execution = engine
            .get_execution_status(run_id)
            .await?
            .ok_or_else(|| anyhow!("run_not_found"))?;
        if !is_terminal_status(&execution.status) {
            engine.stop_execution(run_id).await?;
        }
        let execution = engine
            .get_execution_status(run_id)
            .await?
            .ok_or_else(|| anyhow!("run_not_found"))?;
        Ok(run_status(execution, governance))
    }

    async fn authorized_run_governance(&self, run_id: &str) -> Result<WorkflowExecutionGovernance> {
        let governance = self
            .db
            .get_workflow_execution_governance(run_id)
            .await?
            .ok_or_else(|| anyhow!("run_not_found"))?;
        let profile = self.profile.read().await;
        if governance.principal_id != profile.id {
            return Err(anyhow!("capability_denied"));
        }
        Ok(governance)
    }

    fn schedule_scope_revocation(&self, run_id: String, scope_id: String) {
        let service = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let Some(engine) = &service.workflow_engine else {
                    return;
                };
                match engine.get_execution_status(&run_id).await {
                    Ok(Some(execution)) if is_terminal_status(&execution.status) => {
                        if let Err(error) = service.revoke_engagement(&scope_id).await {
                            eprintln!(
                                "UniHack could not retire one-shot scope {scope_id}: {error}"
                            );
                        }
                        return;
                    }
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => return,
                }
            }
        });
    }

    pub async fn list_scans(&self) -> Result<Vec<Scan>> {
        self.require_capability(Capability::ReadScans).await?;
        self.db.list_scans().await
    }

    pub async fn get_scan_evidence(&self, scan_id: &str) -> Result<ScanEvidence> {
        self.require_capability(Capability::ReadEvidence).await?;
        let scan = self
            .db
            .get_scan(scan_id)
            .await?
            .ok_or_else(|| anyhow!("Scan '{scan_id}' not found"))?;
        let execution = self
            .db
            .get_latest_workflow_execution_for_scan(scan_id)
            .await?;
        let (execution_id, artifacts, findings) = if let Some(execution) = execution {
            let artifacts = self.db.get_workflow_artifacts(&execution.id).await?;
            let findings = self.db.get_workflow_findings(&execution.id).await?;
            (Some(execution.id), artifacts, findings)
        } else {
            (None, Vec::new(), Vec::new())
        };
        Ok(ScanEvidence {
            scan,
            execution_id,
            artifacts,
            findings,
        })
    }

    pub async fn list_reports(&self) -> Result<Vec<Report>> {
        self.require_capability(Capability::ReadReports).await?;
        self.db.list_reports().await
    }

    pub async fn get_report(&self, report_id: &str) -> Result<Option<Report>> {
        self.require_capability(Capability::ReadReports).await?;
        self.db.get_report(report_id).await
    }

    pub async fn refresh_auto_adapters(&self) -> Result<Value> {
        self.require_capability(Capability::MaintainAdapters)
            .await?;
        let tools = self.list_tools(true).await?;
        let failures = self.auto_adapters.sync_installed_tools(tools.clone()).await;
        let profiles = self.auto_adapters.list_profiles().await;
        Ok(json!({
            "toolsChecked": tools.len(),
            "installedTools": tools.iter().filter(|tool| tool.installed).count(),
            "profilesAvailable": profiles.len(),
            "readyProfiles": profiles
                .iter()
                .filter(|profile| profile.status == crate::adapters::auto::AutoAdapterStatus::Ready)
                .count(),
            "failures": failures,
        }))
    }

    pub async fn runtime_settings(&self) -> Result<AppSettings> {
        self.require_capability(Capability::ReadStatus).await?;
        Ok(self.settings.read().await.clone())
    }

    pub async fn list_audit_activity(&self, limit: u32) -> Result<Vec<McpAuditEvent>> {
        self.require_capability(Capability::ManageEngagements)
            .await?;
        let profile = self.profile.read().await;
        self.db
            .list_mcp_audit_events(&profile.id, limit.clamp(1, 200))
            .await
    }

    pub async fn audit(
        &self,
        capability: Capability,
        request_id: String,
        scope_id: Option<String>,
        arguments: Value,
        outcome: String,
        correlation_id: Option<String>,
    ) -> Result<()> {
        let _audit_guard = self.audit_lock.lock().await;
        let signing_key = self
            .audit_signing_key
            .as_ref()
            .ok_or_else(|| anyhow!("daemon_unavailable"))?;
        let profile = self.profile.read().await;
        let event = McpAuditEvent::new(
            profile.id.clone(),
            capability,
            request_id,
            scope_id,
            sanitize_json(arguments),
            outcome,
            correlation_id,
            self.db.latest_audit_hash().await?,
            signing_key,
        )
        .map_err(|error| anyhow!(error))?;
        self.db.append_mcp_audit_event(&event).await
    }
}

struct ScopeExecutionGuard {
    db: Arc<Database>,
    results_dir: PathBuf,
    signing_key: Vec<u8>,
    execution_id: String,
    scope_id: String,
    principal_id: String,
    workflow_id: String,
    revision_hash: String,
    target: String,
    risk_tier: RiskTier,
    started_at: DateTime<Utc>,
    max_runtime_seconds: u64,
    max_output_bytes: u64,
}

impl ScopeExecutionGuard {
    async fn validate_now(&self) -> Result<()> {
        let scope = self
            .db
            .get_engagement_scope(&self.scope_id)
            .await?
            .ok_or_else(|| anyhow!("scope_required"))?;
        if !scope
            .verify_signature(&self.signing_key)
            .map_err(|error| anyhow!(error))?
        {
            return Err(anyhow!("scope_signature_invalid"));
        }
        scope
            .validate_use(
                &self.principal_id,
                &self.workflow_id,
                &self.target,
                self.risk_tier,
                Utc::now(),
            )
            .map_err(|error| anyhow!(error))?;
        let governance = self
            .db
            .get_workflow_execution_governance(&self.execution_id)
            .await?
            .ok_or_else(|| anyhow!("workflow_quarantined"))?;
        if governance.scope_id != self.scope_id
            || governance.principal_id != self.principal_id
            || governance.revision_hash != self.revision_hash
        {
            return Err(anyhow!("workflow_quarantined"));
        }
        let revision = self
            .db
            .get_workflow_revision(&self.revision_hash)
            .await?
            .ok_or_else(|| anyhow!("workflow_quarantined"))?;
        let trust = self
            .db
            .get_workflow_trust(&self.revision_hash)
            .await?
            .ok_or_else(|| anyhow!("workflow_quarantined"))?;
        if !revision.immutable
            || revision.workflow_id != self.workflow_id
            || trust.revoked_at.is_some()
        {
            return Err(anyhow!("workflow_quarantined"));
        }
        let elapsed = Utc::now().signed_duration_since(self.started_at);
        if elapsed > ChronoDuration::seconds(self.max_runtime_seconds as i64) {
            return Err(anyhow!("scope_budget_exceeded"));
        }
        if scope_output_bytes(&self.db, &self.results_dir, &self.scope_id).await?
            > self.max_output_bytes
        {
            return Err(anyhow!("scope_budget_exceeded"));
        }
        Ok(())
    }
}

impl ExecutionGuard for ScopeExecutionGuard {
    fn validate(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(self.validate_now())
    }
}

async fn managed_scan_directory(results_dir: &Path, scan_id: &str) -> Result<String> {
    tokio::fs::create_dir_all(results_dir).await?;
    let canonical_root = tokio::fs::canonicalize(results_dir).await?;
    let directory = canonical_root.join(scan_id);
    tokio::fs::create_dir_all(&directory).await?;
    let canonical_directory = tokio::fs::canonicalize(&directory).await?;
    if !path_is_within(&canonical_root, &canonical_directory) {
        return Err(anyhow!("Managed scan directory escaped the results root"));
    }
    Ok(canonical_directory.to_string_lossy().to_string())
}

async fn scope_output_bytes(db: &Database, results_dir: &Path, scope_id: &str) -> Result<u64> {
    tokio::fs::create_dir_all(results_dir).await?;
    let canonical_root = tokio::fs::canonicalize(results_dir).await?;
    let mut total = 0_u64;
    for directory in db.list_scope_working_directories(scope_id).await? {
        let path = PathBuf::from(directory);
        let canonical = match tokio::fs::canonicalize(&path).await {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !path_is_within(&canonical_root, &canonical) {
            return Err(anyhow!("Managed execution output escaped the results root"));
        }
        total = total.saturating_add(directory_size_without_symlinks(&canonical).await?);
    }
    Ok(total)
}

async fn directory_size_without_symlinks(root: &Path) -> Result<u64> {
    let mut total = 0_u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = tokio::fs::symlink_metadata(&path).await?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_file() {
            total = total.saturating_add(metadata.len());
            continue;
        }
        if metadata.is_dir() {
            let mut entries = tokio::fs::read_dir(&path).await?;
            while let Some(entry) = entries.next_entry().await? {
                pending.push(entry.path());
            }
        }
    }
    Ok(total)
}

fn validate_idempotency_key(key: &str) -> Result<()> {
    if !(8..=128).contains(&key.len())
        || !key.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(anyhow!(
            "Idempotency keys must contain 8-128 safe ASCII characters"
        ));
    }
    Ok(())
}

fn is_terminal_status(status: &ExecutionStatus) -> bool {
    matches!(
        status,
        ExecutionStatus::Completed
            | ExecutionStatus::Failed
            | ExecutionStatus::Cancelled
            | ExecutionStatus::Interrupted
    )
}

fn run_status(
    execution: crate::workflow::types::WorkflowExecution,
    governance: WorkflowExecutionGovernance,
) -> RunStatus {
    const MAX_LOGS: usize = 200;
    const MAX_LOG_BYTES: usize = 64 * 1024;
    let logs_truncated = execution.logs.len() > MAX_LOGS
        || execution
            .logs
            .iter()
            .map(|entry| entry.message.len())
            .sum::<usize>()
            > MAX_LOG_BYTES;
    let mut bytes = 0_usize;
    let mut logs = execution
        .logs
        .iter()
        .rev()
        .take(MAX_LOGS)
        .take_while(|entry| {
            bytes = bytes.saturating_add(entry.message.len());
            bytes <= MAX_LOG_BYTES
        })
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>();
    logs.reverse();
    let status = match &execution.status {
        ExecutionStatus::Pending => "pending",
        ExecutionStatus::Running => "running",
        ExecutionStatus::Completed => "completed",
        ExecutionStatus::Failed => "failed",
        ExecutionStatus::Cancelled => "cancelled",
        ExecutionStatus::Interrupted => "interrupted",
    }
    .to_string();
    RunStatus {
        run_id: execution.id,
        scan_id: execution.scan_id,
        scope_id: governance.scope_id,
        workflow_id: execution.workflow_id,
        revision_hash: governance.revision_hash,
        terminal: is_terminal_status(&execution.status),
        status,
        progress: execution.progress,
        current_step: execution.current_step,
        started_at: execution.started,
        completed_at: execution.completed,
        logs,
        logs_truncated,
    }
}

fn workflow_risk(workflow: &WorkflowTemplate) -> RiskTier {
    let id = workflow.id.to_ascii_lowercase();
    let category = workflow.category.to_ascii_lowercase();
    if id.contains("passive") || id.contains("discovery-only") || category.contains("passive") {
        RiskTier::Passive
    } else {
        RiskTier::Active
    }
}

fn validate_scope_budget(budget: &ScopeBudget) -> Result<()> {
    if !(1..=10_000).contains(&budget.max_executions) {
        return Err(anyhow!("Scope max executions must be between 1 and 10000"));
    }
    if !(1..=32).contains(&budget.max_concurrent_processes) {
        return Err(anyhow!(
            "Scope concurrent process limit must be between 1 and 32"
        ));
    }
    if !(30..=86_400).contains(&budget.max_runtime_seconds) {
        return Err(anyhow!(
            "Scope runtime limit must be between 30 seconds and 24 hours"
        ));
    }
    if !(1_024..=5_000_000_000).contains(&budget.max_output_bytes) {
        return Err(anyhow!("Scope output limit must be between 1 KiB and 5 GB"));
    }
    Ok(())
}

fn load_scope_signing_key() -> Result<Vec<u8>> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, &secure_account(SCOPE_SIGNING_ACCOUNT)?)?;
    let encoded = entry
        .get_password()
        .context("Secure scope-signing key is unavailable")?;
    hex::decode(encoded).context("Stored scope-signing key is invalid")
}

fn load_or_create_scope_signing_key() -> Result<Vec<u8>> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, &secure_account(SCOPE_SIGNING_ACCOUNT)?)?;
    match entry.get_password() {
        Ok(encoded) => hex::decode(encoded).context("Stored scope-signing key is invalid"),
        Err(keyring::Error::NoEntry) => {
            let secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
            entry
                .set_password(&secret)
                .context("The OS credential store rejected the scope-signing key")?;
            hex::decode(secret).context("Generated scope-signing key was invalid")
        }
        Err(error) => Err(error).context("Secure scope-signing key is unavailable"),
    }
}

fn load_or_create_audit_signing_key() -> Result<Vec<u8>> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, &secure_account(AUDIT_SIGNING_ACCOUNT)?)?;
    match entry.get_password() {
        Ok(encoded) => hex::decode(encoded).context("Stored audit-signing key is invalid"),
        Err(keyring::Error::NoEntry) => {
            let secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
            entry
                .set_password(&secret)
                .context("The OS credential store rejected the audit-signing key")?;
            hex::decode(secret).context("Generated audit-signing key was invalid")
        }
        Err(error) => Err(error).context("Secure audit-signing key is unavailable"),
    }
}

fn secure_account(base: &str) -> Result<String> {
    let Some(namespace) = std::env::var_os("UNIHACK_CREDENTIAL_NAMESPACE") else {
        return Ok(base.to_string());
    };
    let namespace = namespace
        .into_string()
        .map_err(|_| anyhow!("capability_denied: invalid credential namespace"))?;
    if namespace.is_empty()
        || namespace.len() > 64
        || !namespace.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(anyhow!("capability_denied: invalid credential namespace"));
    }
    Ok(format!("{base}:{namespace}"))
}

pub fn sanitize_json(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    let lowercase = key.to_ascii_lowercase();
                    let sensitive = [
                        "key",
                        "token",
                        "secret",
                        "password",
                        "authorization",
                        "cookie",
                        "credential",
                    ]
                    .iter()
                    .any(|needle| lowercase.contains(needle));
                    (
                        key,
                        if sensitive {
                            json!("[REDACTED]")
                        } else {
                            sanitize_json(value)
                        },
                    )
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(sanitize_json).collect()),
        other => other,
    }
}

pub fn path_is_within(parent: &Path, child: &Path) -> bool {
    child.starts_with(parent)
}

#[cfg(test)]
mod tests {
    use super::sanitize_json;
    use serde_json::json;

    #[test]
    fn audit_sanitization_redacts_nested_credentials() {
        let sanitized = sanitize_json(json!({
            "target": "example.com",
            "nested": { "apiToken": "secret", "safe": "value" }
        }));
        assert_eq!(sanitized["nested"]["apiToken"], "[REDACTED]");
        assert_eq!(sanitized["nested"]["safe"], "value");
    }
}
