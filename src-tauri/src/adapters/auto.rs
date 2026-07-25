//! Automatic adapter discovery for catalog tools installed on the current host.
//!
//! The generator treats the installed binary's `--help` output as evidence, not as execution
//! authority. Only explicit, high-confidence target flags become ready profiles. Ambiguous
//! positional/stdin contracts are retained for review and cannot build commands.

use crate::adapters::{AdapterInfo, AdapterRegistry, CommandPreview};
use crate::runtime::process::hidden_tokio_command;
use crate::tools::discovery::ToolRecord;
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};

const CACHE_SCHEMA_VERSION: u32 = 1;
const HELP_TIMEOUT_SECONDS: u64 = 4;
const HELP_OUTPUT_LIMIT: usize = 64 * 1024;
const READY_CONFIDENCE: f64 = 0.80;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AutoAdapterStatus {
    Ready,
    ReviewRequired,
}

impl AutoAdapterStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::ReviewRequired => "review_required",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum AutoTargetBinding {
    Flag(String),
    Positional,
    Stdin,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AutoTargetTransform {
    AsProvided,
    EnsureHttpUrl,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum AutoOutputBinding {
    Flag(String),
    Stdout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoAdapterEvidence {
    pub probe_args: Vec<String>,
    pub help_sha256: String,
    pub binary_path: String,
    pub binary_fingerprint: String,
    pub binary_version: Option<String>,
    pub inference_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoAdapterProfile {
    pub name: String,
    pub tool_name: String,
    pub description: String,
    pub category: String,
    pub risk_level: String,
    pub requires_authorization: bool,
    pub timeout: u64,
    pub expected_outputs: Vec<String>,
    pub status: AutoAdapterStatus,
    pub confidence: f64,
    pub generated_at: String,
    pub target_kind: String,
    pub target_binding: AutoTargetBinding,
    pub target_transform: AutoTargetTransform,
    pub fixed_args: Vec<String>,
    pub output_binding: AutoOutputBinding,
    pub evidence: AutoAdapterEvidence,
}

impl AutoAdapterProfile {
    pub fn to_info(&self) -> AdapterInfo {
        AdapterInfo {
            name: self.name.clone(),
            tool_name: self.tool_name.clone(),
            description: self.description.clone(),
            category: self.category.clone(),
            risk_level: self.risk_level.clone(),
            requires_authorization: self.requires_authorization,
            timeout: self.timeout,
            expected_outputs: self.expected_outputs.clone(),
            origin: "auto_detected".to_string(),
            status: self.status.as_str().to_string(),
            confidence: self.confidence,
            generated_at: Some(self.generated_at.clone()),
            verified_version: self.evidence.binary_version.clone(),
        }
    }

    pub fn build_command(
        &self,
        target: &str,
        output_file: Option<&str>,
    ) -> Result<CommandPreview, String> {
        if self.status != AutoAdapterStatus::Ready {
            return Err(format!(
                "Auto-adapter for '{}' requires review before command previews are enabled",
                self.tool_name
            ));
        }
        let target = validate_runtime_value("Target", target)?;
        let target = match self.target_transform {
            AutoTargetTransform::AsProvided => target.to_string(),
            AutoTargetTransform::EnsureHttpUrl => ensure_http_url(target),
        };

        let mut argv = vec![self.tool_name.clone()];
        let stdin = match &self.target_binding {
            AutoTargetBinding::Flag(flag) => {
                validate_flag(flag)?;
                argv.push(flag.clone());
                argv.push(target);
                None
            }
            AutoTargetBinding::Positional => {
                argv.push(target);
                None
            }
            AutoTargetBinding::Stdin => Some(target),
            AutoTargetBinding::Unknown => {
                return Err(format!(
                    "Auto-adapter for '{}' has no verified target binding",
                    self.tool_name
                ));
            }
        };

        for argument in &self.fixed_args {
            validate_runtime_value("Fixed argument", argument)?;
            argv.push(argument.clone());
        }

        if let Some(output_file) = output_file {
            let output_file = validate_runtime_value("Output path", output_file)?;
            match &self.output_binding {
                AutoOutputBinding::Flag(flag) => {
                    validate_flag(flag)?;
                    argv.push(flag.clone());
                    argv.push(output_file.to_string());
                }
                AutoOutputBinding::Stdout => {
                    return Err(format!(
                        "{} writes to stdout; the runtime must capture its output",
                        self.tool_name
                    ));
                }
            }
        }

        Ok(CommandPreview { argv, stdin })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AutoAdapterCache {
    schema_version: u32,
    profiles: HashMap<String, AutoAdapterProfile>,
}

pub struct AutoAdapterService {
    cache_path: PathBuf,
    profiles: RwLock<HashMap<String, AutoAdapterProfile>>,
}

impl AutoAdapterService {
    pub async fn load(cache_path: PathBuf) -> Self {
        let profiles = match tokio::fs::read_to_string(&cache_path).await {
            Ok(contents) => match serde_json::from_str::<AutoAdapterCache>(&contents) {
                Ok(cache) if cache.schema_version == CACHE_SCHEMA_VERSION => cache.profiles,
                Ok(_) => {
                    eprintln!("Ignoring incompatible auto-adapter cache schema");
                    HashMap::new()
                }
                Err(error) => {
                    eprintln!("Ignoring invalid auto-adapter cache: {}", error);
                    HashMap::new()
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(error) => {
                eprintln!("Failed to read auto-adapter cache: {}", error);
                HashMap::new()
            }
        };

        Self {
            cache_path,
            profiles: RwLock::new(profiles),
        }
    }

    pub async fn list_profiles(&self) -> Vec<AutoAdapterProfile> {
        let mut profiles = self
            .profiles
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        profiles.sort_by(|left, right| left.tool_name.cmp(&right.tool_name));
        profiles
    }

    pub async fn get_profile(&self, tool_name: &str) -> Option<AutoAdapterProfile> {
        self.profiles
            .read()
            .await
            .get(&tool_name.to_ascii_lowercase())
            .cloned()
    }

    pub async fn has_ready_profile(&self, tool_name: &str) -> bool {
        self.get_profile(tool_name)
            .await
            .is_some_and(|profile| profile.status == AutoAdapterStatus::Ready)
    }

    pub async fn ensure_profile(
        &self,
        record: &ToolRecord,
    ) -> Result<Option<AutoAdapterProfile>, String> {
        if !is_auto_adapter_candidate(record) || AdapterRegistry::new().has_adapter(&record.name) {
            return Ok(None);
        }

        let path = record
            .path
            .as_deref()
            .ok_or_else(|| format!("Installed tool '{}' has no resolved path", record.name))?;
        let fingerprint = binary_fingerprint(Path::new(path)).await?;
        if let Some(existing) = self.get_profile(&record.name).await {
            if existing.evidence.binary_path == path
                && existing.evidence.binary_fingerprint == fingerprint
                && existing.evidence.binary_version == record.version
            {
                return Ok(Some(existing));
            }
        }

        let profile = generate_profile(record, &fingerprint).await?;
        self.profiles
            .write()
            .await
            .insert(record.name.to_ascii_lowercase(), profile.clone());
        self.persist().await?;
        Ok(Some(profile))
    }

    pub async fn sync_installed_tools(
        self: &Arc<Self>,
        records: impl IntoIterator<Item = ToolRecord>,
    ) -> Vec<String> {
        let semaphore = Arc::new(Semaphore::new(4));
        let mut tasks = tokio::task::JoinSet::new();
        for record in records {
            if !is_auto_adapter_candidate(&record)
                || AdapterRegistry::new().has_adapter(&record.name)
            {
                continue;
            }
            let service = Arc::clone(self);
            let semaphore = Arc::clone(&semaphore);
            tasks.spawn(async move {
                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .map_err(|error| format!("Auto-adapter worker could not start: {}", error))?;
                let tool_name = record.name.clone();
                service
                    .ensure_profile(&record)
                    .await
                    .map(|_| ())
                    .map_err(|error| format!("{}: {}", tool_name, error))
            });
        }

        let mut failures = Vec::new();
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push(error),
                Err(error) => failures.push(format!("Auto-adapter task failed: {}", error)),
            }
        }
        failures
    }

    async fn persist(&self) -> Result<(), String> {
        if let Some(parent) = self.cache_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|error| format!("Failed to create auto-adapter directory: {}", error))?;
        }
        let cache = AutoAdapterCache {
            schema_version: CACHE_SCHEMA_VERSION,
            profiles: self.profiles.read().await.clone(),
        };
        let json = serde_json::to_vec_pretty(&cache)
            .map_err(|error| format!("Failed to serialize auto-adapters: {}", error))?;
        tokio::fs::write(&self.cache_path, json)
            .await
            .map_err(|error| format!("Failed to persist auto-adapters: {}", error))
    }
}

fn is_auto_adapter_candidate(record: &ToolRecord) -> bool {
    record.installed
        && record.status == "available"
        && record
            .path
            .as_deref()
            .is_some_and(|path| !path.trim().is_empty())
        && !record.category.eq_ignore_ascii_case("utility")
        && record.install_method.as_deref() != Some("runtime")
        && record.install_method.as_deref() != Some("manual")
}

async fn generate_profile(
    record: &ToolRecord,
    fingerprint: &str,
) -> Result<AutoAdapterProfile, String> {
    let path = record.path.as_deref().ok_or_else(|| {
        format!(
            "Installed tool '{}' cannot be probed without a path",
            record.name
        )
    })?;
    let help = probe_help(path).await?;
    let help_sha256 = format!("{:x}", Sha256::digest(help.as_bytes()));
    let inference = infer_contract(&help, &record.output_format);
    let status = if inference.confidence >= READY_CONFIDENCE
        && matches!(inference.target_binding, AutoTargetBinding::Flag(_))
    {
        AutoAdapterStatus::Ready
    } else {
        AutoAdapterStatus::ReviewRequired
    };

    Ok(AutoAdapterProfile {
        name: display_name(&record.name),
        tool_name: record.name.to_ascii_lowercase(),
        description: format!(
            "{} (adapter inferred from installed CLI help)",
            record.description
        ),
        category: record.category.clone(),
        risk_level: infer_risk(&record.category).to_string(),
        requires_authorization: true,
        timeout: infer_timeout(&record.category),
        expected_outputs: vec![if record.output_format.trim().is_empty() {
            "text".to_string()
        } else {
            record.output_format.to_ascii_lowercase()
        }],
        status,
        confidence: inference.confidence,
        generated_at: Utc::now().to_rfc3339(),
        target_kind: inference.target_kind,
        target_binding: inference.target_binding,
        target_transform: inference.target_transform,
        fixed_args: inference.fixed_args,
        output_binding: inference.output_binding,
        evidence: AutoAdapterEvidence {
            probe_args: vec!["--help".to_string()],
            help_sha256,
            binary_path: path.to_string(),
            binary_fingerprint: fingerprint.to_string(),
            binary_version: record.version.clone(),
            inference_notes: inference.notes,
        },
    })
}

async fn probe_help(path: &str) -> Result<String, String> {
    let mut command = hidden_tokio_command(path);
    command
        .arg("--help")
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .kill_on_drop(true);
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(HELP_TIMEOUT_SECONDS),
        command.output(),
    )
    .await
    .map_err(|_| format!("{} --help timed out", path))?
    .map_err(|error| format!("Failed to probe {} --help: {}", path, error))?;

    let mut combined = Vec::with_capacity(output.stdout.len() + output.stderr.len() + 1);
    combined.extend_from_slice(&output.stdout);
    combined.push(b'\n');
    combined.extend_from_slice(&output.stderr);
    combined.truncate(HELP_OUTPUT_LIMIT);
    let help = String::from_utf8_lossy(&combined).trim().to_string();
    if help.len() < 20 {
        return Err(format!(
            "{} --help did not return usable CLI documentation",
            path
        ));
    }
    Ok(help)
}

struct InferredContract {
    target_kind: String,
    target_binding: AutoTargetBinding,
    target_transform: AutoTargetTransform,
    fixed_args: Vec<String>,
    output_binding: AutoOutputBinding,
    confidence: f64,
    notes: Vec<String>,
}

fn infer_contract(help: &str, output_format: &str) -> InferredContract {
    let lower = strip_ansi(help).to_ascii_lowercase();
    let mut notes = vec!["Local --help output captured successfully".to_string()];
    let mut confidence: f64 = 0.35;

    let (target_binding, target_kind, target_transform) =
        if let Some(flag) = flag_with_keywords(&lower, &["--url", "-u"], &["url"]) {
            confidence += 0.50;
            notes.push(format!("Explicit URL target flag detected: {}", flag));
            (
                AutoTargetBinding::Flag(flag),
                "url".to_string(),
                AutoTargetTransform::EnsureHttpUrl,
            )
        } else if let Some(flag) = flag_with_keywords(&lower, &["--domain", "-d"], &["domain"]) {
            confidence += 0.50;
            notes.push(format!("Explicit domain target flag detected: {}", flag));
            (
                AutoTargetBinding::Flag(flag),
                "domain".to_string(),
                AutoTargetTransform::AsProvided,
            )
        } else if let Some(flag) = flag_with_keywords(
            &lower,
            &[
                "--addresses",
                "-a",
                "--host",
                "--hostname",
                "--target",
                "-target",
            ],
            &["address", "host", "target", "cidr"],
        ) {
            confidence += 0.50;
            notes.push(format!("Explicit host target flag detected: {}", flag));
            (
                AutoTargetBinding::Flag(flag),
                "host".to_string(),
                AutoTargetTransform::AsProvided,
            )
        } else if lower.contains("reads from stdin") || lower.contains("read from stdin") {
            confidence += 0.20;
            notes.push("Possible stdin target contract detected; review required".to_string());
            (
                AutoTargetBinding::Stdin,
                "host".to_string(),
                AutoTargetTransform::AsProvided,
            )
        } else if usage_mentions_target(&lower) {
            confidence += 0.20;
            notes.push("Possible positional target contract detected; review required".to_string());
            (
                AutoTargetBinding::Positional,
                infer_positional_kind(&lower).to_string(),
                if lower.contains("<url>") || lower.contains("[url]") {
                    AutoTargetTransform::EnsureHttpUrl
                } else {
                    AutoTargetTransform::AsProvided
                },
            )
        } else {
            notes.push("No unambiguous target contract detected".to_string());
            (
                AutoTargetBinding::Unknown,
                "host".to_string(),
                AutoTargetTransform::AsProvided,
            )
        };

    let output_binding = if let Some(flag) = flag_with_keywords(
        &lower,
        &["--output", "--output-file", "-o"],
        &["output", "file", "save", "write"],
    ) {
        confidence += 0.05;
        notes.push(format!("Output file flag detected: {}", flag));
        AutoOutputBinding::Flag(flag)
    } else {
        notes.push("No output flag inferred; stdout capture required".to_string());
        AutoOutputBinding::Stdout
    };

    let mut fixed_args = Vec::new();
    if output_format.eq_ignore_ascii_case("json") {
        if flag_present(&lower, "--json") {
            fixed_args.push("--json".to_string());
            confidence += 0.05;
            notes.push("Machine-readable --json output detected".to_string());
        } else if flag_present(&lower, "-json") {
            fixed_args.push("-json".to_string());
            confidence += 0.05;
            notes.push("Machine-readable -json output detected".to_string());
        }
    }

    InferredContract {
        target_kind,
        target_binding,
        target_transform,
        fixed_args,
        output_binding,
        confidence: confidence.min(1.0),
        notes,
    }
}

fn flag_with_keywords(help: &str, flags: &[&str], keywords: &[&str]) -> Option<String> {
    for line in help.lines() {
        if !keywords.iter().any(|keyword| line.contains(keyword)) {
            continue;
        }
        for flag in flags {
            if flag_present(line, flag) {
                return Some((*flag).to_string());
            }
        }
    }
    None
}

fn flag_present(text: &str, flag: &str) -> bool {
    let pattern = format!(r"(?:^|[\s,\[(]){}(?:$|[\s,=\[\]<>])", regex::escape(flag));
    Regex::new(&pattern)
        .map(|regex| regex.is_match(text))
        .unwrap_or(false)
}

fn usage_mentions_target(help: &str) -> bool {
    help.lines().any(|line| {
        (line.contains("usage:") || line.starts_with("usage "))
            && ["<url>", "[url]", "<host>", "[host]", "<target>", "[target]"]
                .iter()
                .any(|placeholder| line.contains(placeholder))
    }) || help
        .lines()
        .any(|line| line.trim_start().starts_with("masscan "))
}

fn infer_positional_kind(help: &str) -> &'static str {
    if help.contains("<url>") || help.contains("[url]") {
        "url"
    } else if help.contains("<domain>") || help.contains("[domain]") {
        "domain"
    } else {
        "host"
    }
}

fn strip_ansi(value: &str) -> String {
    Regex::new(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
        .map(|regex| regex.replace_all(value, "").into_owned())
        .unwrap_or_else(|_| value.to_string())
}

fn infer_risk(category: &str) -> &'static str {
    let category = category.to_ascii_lowercase();
    if [
        "vulnerability",
        "exploit",
        "fuzz",
        "brute",
        "password",
        "network",
        "port",
    ]
    .iter()
    .any(|keyword| category.contains(keyword))
    {
        "high"
    } else {
        "medium"
    }
}

fn infer_timeout(category: &str) -> u64 {
    if infer_risk(category) == "high" {
        1800
    } else {
        900
    }
}

fn display_name(tool_name: &str) -> String {
    tool_name
        .split(['-', '_'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut characters = part.chars();
            characters
                .next()
                .map(|first| first.to_uppercase().collect::<String>() + characters.as_str())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

async fn binary_fingerprint(path: &Path) -> Result<String, String> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|error| format!("Failed to inspect {}: {}", path.display(), error))?;
    let modified = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    Ok(format!("{}:{}", metadata.len(), modified))
}

fn validate_runtime_value<'a>(field: &str, value: &'a str) -> Result<&'a str, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{} cannot be empty", field));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{} cannot contain control characters", field));
    }
    Ok(value)
}

fn validate_flag(flag: &str) -> Result<(), String> {
    let flag = validate_runtime_value("Adapter flag", flag)?;
    if !flag.starts_with('-') || flag.chars().any(char::is_whitespace) {
        return Err("Adapter flags must be single option tokens".to_string());
    }
    Ok(())
}

fn ensure_http_url(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{}", target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, category: &str, output_format: &str) -> ToolRecord {
        ToolRecord {
            name: name.to_string(),
            description: "Test tool".to_string(),
            category: category.to_string(),
            status: "available".to_string(),
            installed: true,
            command_template: vec![name.to_string()],
            output_format: output_format.to_string(),
            version: Some("1.0.0".to_string()),
            raw_version: None,
            path: Some(format!("/tmp/{}", name)),
            os_dependencies: vec![],
            missing_dependencies: vec![],
            last_checked: None,
            last_seen: None,
            last_error: None,
            install_method: Some("go".to_string()),
            alternative_install_methods: None,
            available_install_methods: vec!["go".to_string()],
        }
    }

    #[test]
    fn infers_explicit_url_profile() {
        let help = "Usage: probe [options]\n  -u, --url string  target URL\n  -o, --output file save output\n  --json output JSON";
        let inferred = infer_contract(help, "json");
        assert_eq!(
            inferred.target_binding,
            AutoTargetBinding::Flag("--url".to_string())
        );
        assert_eq!(inferred.target_kind, "url");
        assert!(inferred.confidence >= READY_CONFIDENCE);
        assert_eq!(inferred.fixed_args, vec!["--json"]);
    }

    #[test]
    fn infers_domain_short_flag_when_long_flag_is_absent() {
        let help = "usage: enum -d DOMAIN\n  -d DOMAIN   domain name to enumerate";
        let inferred = infer_contract(help, "text");
        assert_eq!(
            inferred.target_binding,
            AutoTargetBinding::Flag("-d".to_string())
        );
        assert_eq!(inferred.target_kind, "domain");
    }

    #[test]
    fn positional_contract_never_reaches_ready_threshold() {
        let help = "Usage: scanner <target> [options]\nScan an authorized target";
        let inferred = infer_contract(help, "text");
        assert_eq!(inferred.target_binding, AutoTargetBinding::Positional);
        assert!(inferred.confidence < READY_CONFIDENCE);
    }

    #[test]
    fn runtime_and_utility_tools_are_not_candidates() {
        let mut tool = record("python", "utility", "text");
        tool.install_method = Some("runtime".to_string());
        assert!(!is_auto_adapter_candidate(&tool));
    }

    #[test]
    fn ready_profile_builds_only_structured_arguments() {
        let profile = AutoAdapterProfile {
            name: "Probe".to_string(),
            tool_name: "probe".to_string(),
            description: "Probe".to_string(),
            category: "web".to_string(),
            risk_level: "medium".to_string(),
            requires_authorization: true,
            timeout: 900,
            expected_outputs: vec!["json".to_string()],
            status: AutoAdapterStatus::Ready,
            confidence: 0.9,
            generated_at: "2026-07-21T00:00:00Z".to_string(),
            target_kind: "url".to_string(),
            target_binding: AutoTargetBinding::Flag("--url".to_string()),
            target_transform: AutoTargetTransform::EnsureHttpUrl,
            fixed_args: vec!["--json".to_string()],
            output_binding: AutoOutputBinding::Flag("--output".to_string()),
            evidence: AutoAdapterEvidence {
                probe_args: vec!["--help".to_string()],
                help_sha256: "hash".to_string(),
                binary_path: "/tmp/probe".to_string(),
                binary_fingerprint: "1:1".to_string(),
                binary_version: Some("1.0.0".to_string()),
                inference_notes: vec![],
            },
        };
        let command = profile
            .build_command("example.com", Some("/tmp/output.json"))
            .unwrap();
        assert_eq!(
            command.argv,
            vec![
                "probe",
                "--url",
                "https://example.com",
                "--json",
                "--output",
                "/tmp/output.json"
            ]
        );
        assert!(command.stdin.is_none());
    }

    #[test]
    fn review_profile_cannot_build_commands() {
        let mut inferred = infer_contract("Usage: scanner <target>", "text");
        assert!(inferred.confidence < READY_CONFIDENCE);
        inferred.target_binding = AutoTargetBinding::Unknown;
    }
}
