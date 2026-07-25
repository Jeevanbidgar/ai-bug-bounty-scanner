use super::traits::{OutputParser, ParsedFinding};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::fs::File;
use std::path::Path;

pub struct DalfoxParser;

impl DalfoxParser {
    fn text(record: &Value, key: &str) -> Option<String> {
        record
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    }

    fn parse_finding(record: Value) -> Option<ParsedFinding> {
        let finding_type = Self::text(&record, "type");
        let type_description = Self::text(&record, "type_description");
        let parameter = Self::text(&record, "param");
        let title = Self::text(&record, "message_str")
            .or_else(|| type_description.clone())
            .or_else(|| {
                finding_type
                    .as_deref()
                    .map(|kind| format!("Dalfox {kind} XSS finding"))
            })?;

        let severity = Self::text(&record, "severity")
            .map(|severity| severity.to_ascii_lowercase())
            .or_else(|| match finding_type.as_deref() {
                Some("V") | Some("A") => Some("high".to_string()),
                Some("R") => Some("medium".to_string()),
                Some("I") => Some("info".to_string()),
                _ => None,
            });

        let description = [
            type_description,
            Self::text(&record, "cwe").map(|value| format!("Classification: {value}")),
            Self::text(&record, "inject_type").map(|value| format!("Injection context: {value}")),
            Self::text(&record, "method").map(|value| format!("HTTP method: {value}")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n");

        Some(ParsedFinding {
            title,
            severity,
            description: (!description.is_empty()).then_some(description),
            cvss: None,
            url: Self::text(&record, "data"),
            parameter,
            payload: Self::text(&record, "payload"),
            remediation: None,
            evidence: Self::text(&record, "evidence"),
            raw_data: serde_json::to_string(&record).ok(),
        })
    }
}

impl OutputParser for DalfoxParser {
    fn parse(&self, file_path: &Path) -> Result<Vec<ParsedFinding>> {
        let file = File::open(file_path)
            .with_context(|| format!("failed to open Dalfox output {}", file_path.display()))?;
        let mut document: Value = serde_json::from_reader(file)
            .with_context(|| format!("invalid Dalfox JSON in {}", file_path.display()))?;

        let records = match &mut document {
            Value::Array(records) => std::mem::take(records),
            Value::Object(object) => match object.remove("findings") {
                Some(Value::Array(records)) => records,
                _ => bail!("Dalfox JSON does not contain a findings array"),
            },
            _ => bail!("Dalfox JSON must be an object or array"),
        };

        Ok(records
            .into_iter()
            .filter_map(Self::parse_finding)
            .collect())
    }

    fn tool_name(&self) -> &str {
        "dalfox"
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
    fn parses_current_dalfox_json_envelope() {
        let output = r#"{
          "meta": {"findings_count": 1},
          "findings": [{
            "type": "V",
            "type_description": "Verified XSS - payload confirmed executed in parsed DOM",
            "inject_type": "inHTML",
            "method": "GET",
            "data": "https://example.test/?q=payload",
            "param": "q",
            "payload": "<svg/onload=alert(1)>",
            "evidence": "payload executed",
            "cwe": "CWE-79",
            "severity": "High",
            "message_id": 1234,
            "message_str": "Reflected XSS via parameter q"
          }]
        }"#;
        let mut file = NamedTempFile::with_suffix(".json").unwrap();
        file.write_all(output.as_bytes()).unwrap();

        let findings = DalfoxParser.parse(file.path()).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Reflected XSS via parameter q");
        assert_eq!(findings[0].severity.as_deref(), Some("high"));
        assert_eq!(findings[0].parameter.as_deref(), Some("q"));
    }

    #[test]
    fn accepts_legacy_top_level_array() {
        let mut file = NamedTempFile::with_suffix(".json").unwrap();
        file.write_all(br#"[{"type":"R","message_str":"Reflected input"}]"#)
            .unwrap();

        let findings = DalfoxParser.parse(file.path()).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity.as_deref(), Some("medium"));
    }
}
