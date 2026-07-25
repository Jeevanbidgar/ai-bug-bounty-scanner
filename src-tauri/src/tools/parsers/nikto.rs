use super::traits::{OutputParser, ParsedFinding};
use anyhow::{bail, Context, Result};
use serde_json::{Map, Value};
use std::fs::File;
use std::path::Path;

pub struct NiktoParser;

impl NiktoParser {
    fn text(object: &Map<String, Value>, key: &str) -> Option<String> {
        object
            .get(key)
            .and_then(|value| match value {
                Value::String(value) => Some(value.clone()),
                Value::Number(value) => Some(value.to_string()),
                _ => None,
            })
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn finding_url(host: &Map<String, Value>, path: Option<String>) -> Option<String> {
        let path = path?;
        if path.starts_with("http://") || path.starts_with("https://") {
            return Some(path);
        }

        let hostname = Self::text(host, "host")?;
        if hostname.starts_with("http://") || hostname.starts_with("https://") {
            return Some(format!(
                "{}/{}",
                hostname.trim_end_matches('/'),
                path.trim_start_matches('/')
            ));
        }

        let port = Self::text(host, "port");
        let uses_tls = host.get("ssl_info").is_some() || port.as_deref() == Some("443");
        let scheme = if uses_tls { "https" } else { "http" };
        let authority = match port.as_deref() {
            Some("80") if scheme == "http" => hostname,
            Some("443") if scheme == "https" => hostname,
            Some(port) => format!("{hostname}:{port}"),
            None => hostname,
        };
        Some(format!(
            "{scheme}://{}/{}",
            authority.trim_end_matches('/'),
            path.trim_start_matches('/')
        ))
    }

    fn parse_host(host: Value) -> Vec<ParsedFinding> {
        let Value::Object(host) = host else {
            return Vec::new();
        };
        let Some(Value::Array(vulnerabilities)) = host.get("vulnerabilities") else {
            return Vec::new();
        };

        vulnerabilities
            .iter()
            .filter_map(|record| {
                let Value::Object(record_object) = record else {
                    return None;
                };
                let id = Self::text(record_object, "id").unwrap_or_else(|| "unknown".to_string());
                let message = Self::text(record_object, "msg");
                let title = message
                    .clone()
                    .unwrap_or_else(|| format!("Nikto finding {id}"));
                let method = Self::text(record_object, "method");
                let references = Self::text(record_object, "references");
                let evidence = [
                    method.map(|value| format!("HTTP method: {value}")),
                    references.map(|value| format!("References: {value}")),
                    Some(format!("Nikto ID: {id}")),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join("\n");

                Some(ParsedFinding {
                    title,
                    severity: None,
                    description: message,
                    cvss: None,
                    url: Self::finding_url(&host, Self::text(record_object, "url")),
                    parameter: None,
                    payload: None,
                    remediation: None,
                    evidence: Some(evidence),
                    raw_data: serde_json::to_string(record).ok(),
                })
            })
            .collect()
    }
}

impl OutputParser for NiktoParser {
    fn parse(&self, file_path: &Path) -> Result<Vec<ParsedFinding>> {
        let file = File::open(file_path)
            .with_context(|| format!("failed to open Nikto output {}", file_path.display()))?;
        let document: Value = serde_json::from_reader(file)
            .with_context(|| format!("invalid Nikto JSON in {}", file_path.display()))?;

        let hosts = match document {
            Value::Array(hosts) => hosts,
            host @ Value::Object(_) => vec![host],
            _ => bail!("Nikto JSON must contain a host object or host array"),
        };

        Ok(hosts.into_iter().flat_map(Self::parse_host).collect())
    }

    fn tool_name(&self) -> &str {
        "nikto"
    }

    fn can_parse(&self, file_path: &Path) -> bool {
        file_path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn parses_current_nikto_multi_host_report() {
        let output = r#"[{
          "host": "example.test",
          "ip": "192.0.2.10",
          "port": 443,
          "ssl_info": {"issuer": "Example CA"},
          "vulnerabilities": [{
            "id": "999001",
            "references": "CVE-2026-0001",
            "method": "GET",
            "url": "/admin/",
            "msg": "Administrative console was exposed"
          }]
        }]"#;
        let mut file = NamedTempFile::with_suffix(".json").unwrap();
        file.write_all(output.as_bytes()).unwrap();

        let findings = NiktoParser.parse(file.path()).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Administrative console was exposed");
        assert_eq!(
            findings[0].url.as_deref(),
            Some("https://example.test/admin/")
        );
        assert!(findings[0]
            .evidence
            .as_deref()
            .unwrap()
            .contains("Nikto ID: 999001"));
    }
}
