use super::traits::{OutputParser, ParsedFinding};
use anyhow::{bail, Context, Result};
use serde_json::{Map, Value};
use std::fs::File;
use std::path::Path;

pub struct WpScanParser;

impl WpScanParser {
    fn text(object: &Map<String, Value>, key: &str) -> Option<String> {
        object
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    }

    fn scalar_text(value: &Value) -> Option<String> {
        match value {
            Value::String(value) => Some(value.clone()),
            Value::Number(value) => Some(value.to_string()),
            Value::Bool(value) => Some(value.to_string()),
            _ => None,
        }
    }

    fn references_text(value: Option<&Value>) -> Option<String> {
        let Value::Object(references) = value? else {
            return None;
        };
        let text = references
            .iter()
            .filter_map(|(kind, values)| {
                let values = match values {
                    Value::Array(values) => values
                        .iter()
                        .filter_map(Self::scalar_text)
                        .collect::<Vec<_>>(),
                    value => Self::scalar_text(value).into_iter().collect(),
                };
                (!values.is_empty()).then(|| format!("{kind}: {}", values.join(", ")))
            })
            .collect::<Vec<_>>()
            .join("; ");
        (!text.is_empty()).then_some(text)
    }

    fn string_list(value: Option<&Value>) -> Option<String> {
        let Value::Array(values) = value? else {
            return None;
        };
        let text = values
            .iter()
            .filter_map(Self::scalar_text)
            .collect::<Vec<_>>()
            .join("\n");
        (!text.is_empty()).then_some(text)
    }

    fn cvss(vulnerability: &Map<String, Value>) -> Option<f64> {
        vulnerability
            .get("cvss")
            .and_then(Value::as_object)
            .and_then(|cvss| cvss.get("score"))
            .and_then(|score| match score {
                Value::Number(score) => score.as_f64(),
                Value::String(score) => score.parse().ok(),
                _ => None,
            })
    }

    fn severity(cvss: Option<f64>) -> Option<String> {
        cvss.map(|score| match score {
            score if score >= 9.0 => "critical",
            score if score >= 7.0 => "high",
            score if score >= 4.0 => "medium",
            score if score > 0.0 => "low",
            _ => "info",
        })
        .map(ToOwned::to_owned)
    }

    fn parse_vulnerability(
        vulnerability: &Value,
        context_url: Option<&str>,
    ) -> Option<ParsedFinding> {
        let Value::Object(vulnerability) = vulnerability else {
            return None;
        };
        let title = Self::text(vulnerability, "title")?;
        let cvss = Self::cvss(vulnerability);
        let references = Self::references_text(vulnerability.get("references"));
        let fixed_in = Self::text(vulnerability, "fixed_in");
        let poc = Self::text(vulnerability, "poc");
        let evidence = [
            references
                .clone()
                .map(|value| format!("References: {value}")),
            poc.map(|value| format!("Proof of concept:\n{value}")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n");

        Some(ParsedFinding {
            title,
            severity: Self::severity(cvss),
            description: references,
            cvss,
            url: context_url.map(ToOwned::to_owned),
            parameter: None,
            payload: None,
            remediation: fixed_in.map(|version| {
                format!("Update the affected component to version {version} or later.")
            }),
            evidence: (!evidence.is_empty()).then_some(evidence),
            raw_data: serde_json::to_string(vulnerability).ok(),
        })
    }

    fn parse_interesting_finding(record: &Value) -> Option<ParsedFinding> {
        let Value::Object(record) = record else {
            return None;
        };
        let finding_type = Self::text(record, "type");
        let title = Self::text(record, "to_s")
            .or_else(|| finding_type.clone())
            .unwrap_or_else(|| "WPScan informational finding".to_string());
        let description = [
            finding_type.map(|value| format!("Type: {value}")),
            Self::text(record, "found_by").map(|value| format!("Detected by: {value}")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n");
        let evidence = [
            Self::references_text(record.get("references"))
                .map(|value| format!("References: {value}")),
            Self::string_list(record.get("interesting_entries")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n");

        Some(ParsedFinding {
            title,
            severity: Some("info".to_string()),
            description: (!description.is_empty()).then_some(description),
            cvss: None,
            url: Self::text(record, "url"),
            parameter: None,
            payload: None,
            remediation: None,
            evidence: (!evidence.is_empty()).then_some(evidence),
            raw_data: serde_json::to_string(record).ok(),
        })
    }

    fn visit(value: &Value, context_url: Option<&str>, findings: &mut Vec<ParsedFinding>) {
        let Value::Object(object) = value else {
            return;
        };
        let local_url = Self::text(object, "location")
            .or_else(|| Self::text(object, "url"))
            .or_else(|| context_url.map(ToOwned::to_owned));

        if let Some(Value::Array(vulnerabilities)) = object.get("vulnerabilities") {
            findings.extend(vulnerabilities.iter().filter_map(|vulnerability| {
                Self::parse_vulnerability(vulnerability, local_url.as_deref())
            }));
        }

        if let Some(Value::Array(interesting)) = object.get("interesting_findings") {
            findings.extend(
                interesting
                    .iter()
                    .filter_map(Self::parse_interesting_finding),
            );
        }

        for (key, child) in object {
            if matches!(key.as_str(), "vulnerabilities" | "interesting_findings") {
                continue;
            }
            let child_url = if key.starts_with("http://") || key.starts_with("https://") {
                Some(key.as_str())
            } else {
                local_url.as_deref()
            };
            match child {
                Value::Object(_) => Self::visit(child, child_url, findings),
                Value::Array(values) => {
                    for value in values {
                        Self::visit(value, child_url, findings);
                    }
                }
                _ => {}
            }
        }
    }
}

impl OutputParser for WpScanParser {
    fn parse(&self, file_path: &Path) -> Result<Vec<ParsedFinding>> {
        let file = File::open(file_path)
            .with_context(|| format!("failed to open WPScan output {}", file_path.display()))?;
        let document: Value = serde_json::from_reader(file)
            .with_context(|| format!("invalid WPScan JSON in {}", file_path.display()))?;
        let Value::Object(root) = &document else {
            bail!("WPScan JSON must be a top-level object");
        };

        let target_url =
            Self::text(root, "target_url").or_else(|| Self::text(root, "effective_url"));
        let mut findings = Vec::new();
        Self::visit(&document, target_url.as_deref(), &mut findings);
        Ok(findings)
    }

    fn tool_name(&self) -> &str {
        "wpscan"
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
    fn parses_vulnerabilities_and_interesting_findings() {
        let output = r#"{
          "target_url": "https://example.test/",
          "interesting_findings": [{
            "url": "https://example.test/readme.html",
            "to_s": "WordPress readme file exposed",
            "type": "readme",
            "found_by": "Direct Access",
            "references": {},
            "interesting_entries": ["HTTP 200"]
          }],
          "plugins": {
            "sample-plugin": {
              "slug": "sample-plugin",
              "location": "https://example.test/wp-content/plugins/sample-plugin/",
              "vulnerabilities": [{
                "title": "Sample Plugin - Authenticated SQL Injection",
                "cvss": {"score": "8.8", "vector": "CVSS:3.1/..."},
                "fixed_in": "2.4.1",
                "references": {"cve": ["2026-0001"]}
              }]
            }
          }
        }"#;
        let mut file = NamedTempFile::with_suffix(".json").unwrap();
        file.write_all(output.as_bytes()).unwrap();

        let findings = WpScanParser.parse(file.path()).unwrap();

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity.as_deref(), Some("info"));
        assert_eq!(findings[1].severity.as_deref(), Some("high"));
        assert_eq!(findings[1].cvss, Some(8.8));
        assert_eq!(
            findings[1].url.as_deref(),
            Some("https://example.test/wp-content/plugins/sample-plugin/")
        );
    }

    #[test]
    fn inherits_timthumb_url_from_collection_key() {
        let output = r#"{
          "timthumbs": {
            "https://example.test/tt.php": {
              "vulnerabilities": [{"title": "TimThumb remote code execution"}]
            }
          }
        }"#;
        let mut file = NamedTempFile::with_suffix(".json").unwrap();
        file.write_all(output.as_bytes()).unwrap();

        let findings = WpScanParser.parse(file.path()).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].url.as_deref(),
            Some("https://example.test/tt.php")
        );
    }
}
