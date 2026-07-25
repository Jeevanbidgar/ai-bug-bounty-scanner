//! Authorization, capability, revision-trust, and audit contracts shared by
//! Tauri, the local daemon, and MCP clients.
//!
//! These types deliberately contain no model-provider concepts. An MCP host is
//! an authenticated local client of UniHack; it does not need an OpenAI or
//! Anthropic API key.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use url::Url;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

pub const GOVERNANCE_API_VERSION: &str = "1.0";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    ReadOnly,
    Passive,
    Active,
    Maintenance,
    Privileged,
    Destructive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ReadStatus,
    ReadTools,
    ReadWorkflows,
    ReadScans,
    ReadEvidence,
    ReadReports,
    ValidateMission,
    ExecuteWorkflow,
    ExecuteToolAction,
    CancelExecution,
    GenerateReport,
    MaintainTools,
    MaintainAdapters,
    ManageEngagements,
    ManageWorkflowDrafts,
    UpdateRuntimeSettings,
    DeleteScanRecord,
    DeleteReport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizedTargetKind {
    Hostname,
    Ip,
    Cidr,
    Url,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedTarget {
    pub original: String,
    pub canonical: String,
    pub kind: AuthorizedTargetKind,
}

impl AuthorizedTarget {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let validated = crate::security::validate_scan_target(raw)?;
        let target = validated.trim();

        if target.contains("://") {
            let url = Url::parse(target).map_err(|error| format!("Invalid target URL: {error}"))?;
            let host = url
                .host_str()
                .ok_or_else(|| "Target URL must contain a host".to_string())?
                .to_ascii_lowercase();
            let mut canonical = format!("{}://{}", url.scheme().to_ascii_lowercase(), host);
            if let Some(port) = url.port() {
                canonical.push_str(&format!(":{port}"));
            }
            let path = if url.path().is_empty() {
                "/"
            } else {
                url.path()
            };
            canonical.push_str(path);
            return Ok(Self {
                original: target.to_string(),
                canonical,
                kind: AuthorizedTargetKind::Url,
            });
        }

        if target.contains('/') {
            let network = target
                .parse::<IpNet>()
                .map_err(|error| format!("Invalid CIDR target: {error}"))?;
            return Ok(Self {
                original: target.to_string(),
                canonical: network.to_string(),
                kind: AuthorizedTargetKind::Cidr,
            });
        }

        if let Ok(address) = target.parse::<IpAddr>() {
            return Ok(Self {
                original: target.to_string(),
                canonical: address.to_string(),
                kind: AuthorizedTargetKind::Ip,
            });
        }

        Ok(Self {
            original: target.to_string(),
            canonical: target.trim_end_matches('.').to_ascii_lowercase(),
            kind: AuthorizedTargetKind::Hostname,
        })
    }

    pub fn contains(&self, requested: &AuthorizedTarget) -> bool {
        match self.kind {
            AuthorizedTargetKind::Hostname => requested_host(requested)
                .is_some_and(|host| host.eq_ignore_ascii_case(&self.canonical)),
            AuthorizedTargetKind::Ip => {
                requested_ip(requested).is_some_and(|address| address.to_string() == self.canonical)
            }
            AuthorizedTargetKind::Cidr => {
                let Ok(scope) = self.canonical.parse::<IpNet>() else {
                    return false;
                };
                match requested.kind {
                    AuthorizedTargetKind::Cidr => requested
                        .canonical
                        .parse::<IpNet>()
                        .is_ok_and(|candidate| network_contains_network(scope, candidate)),
                    _ => requested_ip(requested).is_some_and(|address| scope.contains(&address)),
                }
            }
            AuthorizedTargetKind::Url => url_contains(&self.canonical, &requested.canonical),
        }
    }
}

fn requested_host(target: &AuthorizedTarget) -> Option<String> {
    match target.kind {
        AuthorizedTargetKind::Hostname => Some(target.canonical.clone()),
        AuthorizedTargetKind::Url => Url::parse(&target.canonical)
            .ok()?
            .host_str()
            .map(|host| host.to_ascii_lowercase()),
        _ => None,
    }
}

fn requested_ip(target: &AuthorizedTarget) -> Option<IpAddr> {
    match target.kind {
        AuthorizedTargetKind::Ip => target.canonical.parse().ok(),
        AuthorizedTargetKind::Url => Url::parse(&target.canonical).ok()?.host_str()?.parse().ok(),
        _ => None,
    }
}

fn network_contains_network(scope: IpNet, candidate: IpNet) -> bool {
    if scope.addr().is_ipv4() != candidate.addr().is_ipv4()
        || scope.prefix_len() > candidate.prefix_len()
    {
        return false;
    }
    scope.contains(&candidate.network()) && scope.contains(&candidate.broadcast())
}

fn url_contains(scope: &str, requested: &str) -> bool {
    let (Ok(scope), Ok(requested)) = (Url::parse(scope), Url::parse(requested)) else {
        return false;
    };
    if scope.scheme() != requested.scheme()
        || scope.host_str() != requested.host_str()
        || scope.port_or_known_default() != requested.port_or_known_default()
    {
        return false;
    }

    let scope_path = normalized_url_path(scope.path());
    let requested_path = normalized_url_path(requested.path());
    requested_path == scope_path
        || (scope_path.ends_with('/') && requested_path.starts_with(&scope_path))
        || requested_path.starts_with(&format!("{scope_path}/"))
}

fn normalized_url_path(path: &str) -> String {
    let normalized = if path.is_empty() { "/" } else { path };
    if normalized.len() > 1 {
        normalized.trim_end_matches('/').to_string()
    } else {
        normalized.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScopeBudget {
    pub max_executions: u32,
    pub max_concurrent_processes: u16,
    pub max_runtime_seconds: u64,
    pub max_output_bytes: u64,
}

impl Default for ScopeBudget {
    fn default() -> Self {
        Self {
            max_executions: 25,
            max_concurrent_processes: 4,
            max_runtime_seconds: 14_400,
            max_output_bytes: 500_000_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngagementScope {
    pub id: String,
    pub revision: u64,
    pub name: String,
    pub principal_id: String,
    pub targets: Vec<AuthorizedTarget>,
    pub workflow_ids: Vec<String>,
    pub allowed_risk_tier: RiskTier,
    pub starts_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub budget: ScopeBudget,
    pub signature: String,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl EngagementScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        principal_id: impl Into<String>,
        targets: Vec<AuthorizedTarget>,
        workflow_ids: Vec<String>,
        allowed_risk_tier: RiskTier,
        starts_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        budget: ScopeBudget,
    ) -> Result<Self, String> {
        if targets.is_empty() {
            return Err("An engagement scope must contain at least one target".to_string());
        }
        if expires_at <= starts_at {
            return Err("Engagement expiry must be after its start time".to_string());
        }
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            revision: 1,
            name: name.into(),
            principal_id: principal_id.into(),
            targets,
            workflow_ids,
            allowed_risk_tier,
            starts_at,
            expires_at,
            budget,
            signature: String::new(),
            created_at: Utc::now(),
            revoked_at: None,
        })
    }

    pub fn validate_use(
        &self,
        principal_id: &str,
        workflow_id: &str,
        requested_target: &str,
        required_risk: RiskTier,
        now: DateTime<Utc>,
    ) -> Result<AuthorizedTarget, String> {
        if self.revoked_at.is_some() {
            return Err("grant_revoked".to_string());
        }
        if now < self.starts_at || now >= self.expires_at {
            return Err("grant_expired".to_string());
        }
        if self.principal_id != principal_id {
            return Err("capability_denied".to_string());
        }
        if required_risk > self.allowed_risk_tier {
            return Err("capability_denied".to_string());
        }
        if !self.workflow_ids.is_empty()
            && !self
                .workflow_ids
                .iter()
                .any(|allowed| allowed == workflow_id)
        {
            return Err("capability_denied".to_string());
        }
        let requested = AuthorizedTarget::parse(requested_target)?;
        if !self.targets.iter().any(|scope| scope.contains(&requested)) {
            return Err("scope_mismatch".to_string());
        }
        Ok(requested)
    }

    pub fn sign(&mut self, secret: &[u8]) -> Result<(), String> {
        self.signature = compute_scope_signature(self, secret)?;
        Ok(())
    }

    pub fn verify_signature(&self, secret: &[u8]) -> Result<bool, String> {
        let expected = compute_scope_signature(self, secret)?;
        let expected = hex::decode(expected).map_err(|error| error.to_string())?;
        let provided = hex::decode(&self.signature).map_err(|error| error.to_string())?;
        Ok(constant_time_eq(&expected, &provided))
    }
}

fn compute_scope_signature(scope: &EngagementScope, secret: &[u8]) -> Result<String, String> {
    let mut unsigned = scope.clone();
    unsigned.signature.clear();
    let payload = serde_json::to_vec(&unsigned).map_err(|error| error.to_string())?;
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|error| error.to_string())?;
    mac.update(&payload);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpClientProfile {
    pub id: String,
    pub name: String,
    pub capabilities: Vec<Capability>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl McpClientProfile {
    pub fn owner_automation() -> Self {
        Self {
            id: "local-owner-automation".to_string(),
            name: "Local owner automation".to_string(),
            capabilities: vec![
                Capability::ReadStatus,
                Capability::ReadTools,
                Capability::ReadWorkflows,
                Capability::ReadScans,
                Capability::ReadEvidence,
                Capability::ReadReports,
                Capability::ValidateMission,
                Capability::ExecuteWorkflow,
                Capability::ExecuteToolAction,
                Capability::CancelExecution,
                Capability::GenerateReport,
                Capability::MaintainTools,
                Capability::MaintainAdapters,
                Capability::ManageEngagements,
                Capability::ManageWorkflowDrafts,
                Capability::UpdateRuntimeSettings,
                Capability::DeleteScanRecord,
                Capability::DeleteReport,
            ],
            created_at: Utc::now(),
            last_seen_at: None,
            revoked_at: None,
        }
    }

    pub fn allows(&self, capability: &Capability) -> bool {
        self.revoked_at.is_none() && self.capabilities.contains(capability)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowTrustSource {
    Packaged,
    UserReviewed,
    DeterministicVerifier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowRevisionRecord {
    pub id: String,
    pub workflow_id: String,
    pub revision_hash: String,
    pub document: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub immutable: bool,
}

impl WorkflowRevisionRecord {
    pub fn from_document(
        workflow_id: impl Into<String>,
        document: serde_json::Value,
    ) -> Result<Self, String> {
        let canonical = serde_json::to_vec(&document).map_err(|error| error.to_string())?;
        let revision_hash = hex::encode(Sha256::digest(canonical));
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            workflow_id: workflow_id.into(),
            revision_hash,
            document,
            created_at: Utc::now(),
            immutable: true,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowTrustRecord {
    pub revision_hash: String,
    pub source: WorkflowTrustSource,
    pub verifier_version: Option<String>,
    pub evidence_hash: Option<String>,
    pub trusted_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpAuditEvent {
    pub id: String,
    pub principal_id: String,
    pub capability: Capability,
    pub request_id: String,
    pub scope_id: Option<String>,
    pub sanitized_arguments: serde_json::Value,
    pub outcome: String,
    pub correlation_id: Option<String>,
    pub previous_hash: Option<String>,
    pub event_hash: String,
    pub created_at: DateTime<Utc>,
}

impl McpAuditEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal_id: impl Into<String>,
        capability: Capability,
        request_id: impl Into<String>,
        scope_id: Option<String>,
        sanitized_arguments: serde_json::Value,
        outcome: impl Into<String>,
        correlation_id: Option<String>,
        previous_hash: Option<String>,
        signing_key: &[u8],
    ) -> Result<Self, String> {
        let mut event = Self {
            id: Uuid::new_v4().to_string(),
            principal_id: principal_id.into(),
            capability,
            request_id: request_id.into(),
            scope_id,
            sanitized_arguments,
            outcome: outcome.into(),
            correlation_id,
            previous_hash,
            event_hash: String::new(),
            created_at: Utc::now(),
        };
        event.event_hash = event.compute_hash(signing_key)?;
        Ok(event)
    }

    pub fn verify_hash(&self, signing_key: &[u8]) -> Result<bool, String> {
        let expected =
            hex::decode(self.compute_hash(signing_key)?).map_err(|error| error.to_string())?;
        let provided = hex::decode(&self.event_hash).map_err(|error| error.to_string())?;
        Ok(constant_time_eq(&expected, &provided))
    }

    fn compute_hash(&self, signing_key: &[u8]) -> Result<String, String> {
        let mut unsigned = self.clone();
        unsigned.event_hash.clear();
        let encoded = serde_json::to_vec(&unsigned).map_err(|error| error.to_string())?;
        let mut mac = HmacSha256::new_from_slice(signing_key).map_err(|error| error.to_string())?;
        mac.update(&encoded);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorizedTarget, Capability, EngagementScope, McpAuditEvent, RiskTier, ScopeBudget,
    };
    use chrono::{Duration, Utc};

    #[test]
    fn cidr_scope_contains_only_addresses_inside_network() {
        let scope = AuthorizedTarget::parse("192.0.2.0/24").unwrap();
        assert!(scope.contains(&AuthorizedTarget::parse("192.0.2.50").unwrap()));
        assert!(!scope.contains(&AuthorizedTarget::parse("198.51.100.5").unwrap()));
    }

    #[test]
    fn url_scope_requires_same_origin_and_path_boundary() {
        let scope = AuthorizedTarget::parse("https://example.com/app").unwrap();
        assert!(scope.contains(&AuthorizedTarget::parse("https://example.com/app/login").unwrap()));
        assert!(
            !scope.contains(&AuthorizedTarget::parse("https://example.com/application").unwrap())
        );
        assert!(!scope.contains(&AuthorizedTarget::parse("http://example.com/app").unwrap()));
    }

    #[test]
    fn scope_requires_matching_principal_workflow_and_target() {
        let now = Utc::now();
        let mut scope = EngagementScope::new(
            "Example",
            "local-owner-automation",
            vec![AuthorizedTarget::parse("example.com").unwrap()],
            vec!["full-recon".to_string()],
            RiskTier::Active,
            now - Duration::minutes(1),
            now + Duration::hours(1),
            ScopeBudget::default(),
        )
        .unwrap();
        scope.sign(b"test-secret").unwrap();
        assert!(scope.verify_signature(b"test-secret").unwrap());
        assert!(scope
            .validate_use(
                "local-owner-automation",
                "full-recon",
                "example.com",
                RiskTier::Active,
                now,
            )
            .is_ok());
        assert_eq!(
            scope
                .validate_use(
                    "local-owner-automation",
                    "full-recon",
                    "other.example",
                    RiskTier::Active,
                    now,
                )
                .unwrap_err(),
            "scope_mismatch"
        );
    }

    #[test]
    fn audit_hash_is_keyed_and_detects_tampering() {
        let mut event = McpAuditEvent::new(
            "local-owner-automation",
            Capability::ReadStatus,
            "request-1",
            None,
            serde_json::json!({ "safe": true }),
            "success",
            None,
            Some("previous-hash".to_string()),
            b"audit-signing-key",
        )
        .unwrap();

        assert!(event.verify_hash(b"audit-signing-key").unwrap());
        assert!(!event.verify_hash(b"wrong-key").unwrap());
        event.outcome = "tampered".to_string();
        assert!(!event.verify_hash(b"audit-signing-key").unwrap());
    }
}
