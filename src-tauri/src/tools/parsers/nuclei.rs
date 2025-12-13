use serde::Deserialize;
use super::traits::{OutputParser, ParsedFinding};
use anyhow::Result;
use std::path::Path;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, Deserialize)]
struct NucleiClassification {
    #[serde(rename = "cvss-score")]
    cvss_score: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct NucleiInfo {
    name: Option<String>,
    severity: Option<String>,
    description: Option<String>,
    remediation: Option<String>,
    classification: Option<NucleiClassification>,
}

#[derive(Debug, Deserialize)]
struct NucleiResult {
    #[serde(rename = "template-id")]
    template_id: String,
    info: NucleiInfo,
    #[serde(rename = "matched-at")]
    matched_at: Option<String>,
    #[serde(rename = "curl-command")]
    curl_command: Option<String>,
    #[serde(rename = "extracted-results")]
    extracted_results: Option<Vec<String>>,
}

pub struct NucleiParser;

impl OutputParser for NucleiParser {
    fn tool_name(&self) -> &str {
        "nuclei"
    }

    fn can_parse(&self, file_path: &Path) -> bool {
        // Basic check: is it a .json or .jsonl file?
        file_path.extension().map_or(false, |ext| ext == "json" || ext == "jsonl")
    }

    fn parse(&self, file_path: &Path) -> Result<Vec<ParsedFinding>> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        let mut findings = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() { continue; }

            // Nuclei output is usually JSONL (one JSON per line)
            // We interpret each line as a potential finding
            if let Ok(record) = serde_json::from_str::<NucleiResult>(&line) {
                findings.push(ParsedFinding {
                    title: record.info.name.unwrap_or(record.template_id),
                    severity: record.info.severity,
                    description: record.info.description,
                    cvss: record.info.classification.and_then(|c| c.cvss_score),
                    url: record.matched_at.clone(),
                    parameter: None,
                    payload: None,
                    remediation: record.info.remediation,
                    evidence: record.curl_command.or_else(|| 
                        record.extracted_results.map(|r| r.join("\n"))
                    ),
                    raw_data: Some(line),
                });
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_nuclei_jsonl() {
        let jsonl = r#"{"template-id":"cve-2021-1234","info":{"name":"Test CVE","severity":"critical","description":"Test Desc"},"matched-at":"http://example.com","type":"http"}"#;
        
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", jsonl).unwrap();
        
        let parser = NucleiParser;
        let findings = parser.parse(file.path()).unwrap();
        
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Test CVE");
        assert_eq!(findings[0].severity, Some("critical".to_string()));
        assert_eq!(findings[0].url, Some("http://example.com".to_string()));
    }
}