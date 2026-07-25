use anyhow::{anyhow, Result};

use crate::database::{Scan, Vulnerability};

pub fn generate_report(format: &str, scan: &Scan, findings: &[Vulnerability]) -> Result<String> {
    match format.to_ascii_lowercase().as_str() {
        "html" => Ok(generate_html(scan, findings)),
        "json" => Ok(serde_json::to_string_pretty(&report_json(scan, findings))?),
        "sarif" => Ok(serde_json::to_string_pretty(&sarif_json(scan, findings))?),
        _ => Err(anyhow!(
            "Supported report formats are HTML, JSON, and SARIF"
        )),
    }
}

pub fn extension(format: &str) -> Result<&'static str> {
    match format.to_ascii_lowercase().as_str() {
        "html" => Ok("html"),
        "json" => Ok("json"),
        "sarif" => Ok("sarif.json"),
        _ => Err(anyhow!(
            "Supported report formats are HTML, JSON, and SARIF"
        )),
    }
}

pub fn highest_severity(findings: &[Vulnerability]) -> &'static str {
    for severity in ["critical", "high", "medium", "low"] {
        if findings
            .iter()
            .any(|finding| finding.severity.eq_ignore_ascii_case(severity))
        {
            return severity;
        }
    }
    "none"
}

fn report_json(scan: &Scan, findings: &[Vulnerability]) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": "1.0",
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "scan": {
            "id": scan.id,
            "name": scan.name,
            "target": scan.target,
            "workflowId": scan.workflow_id,
            "status": scan.status,
            "startedAt": scan.started,
            "completedAt": scan.completed,
        },
        "summary": {
            "total": findings.len(),
            "critical": count_severity(findings, "critical"),
            "high": count_severity(findings, "high"),
            "medium": count_severity(findings, "medium"),
            "low": count_severity(findings, "low"),
        },
        "findings": findings,
    })
}

fn sarif_json(scan: &Scan, findings: &[Vulnerability]) -> serde_json::Value {
    let rules = findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "id": finding.id,
                "name": finding.title,
                "shortDescription": { "text": finding.title },
                "fullDescription": { "text": finding.description },
                "help": { "text": finding.remediation.clone().unwrap_or_default() },
                "properties": {
                    "security-severity": finding.cvss.map(|score| score.to_string()),
                    "tags": [finding.severity.to_ascii_lowercase(), finding.discovered_by]
                }
            })
        })
        .collect::<Vec<_>>();
    let results = findings
        .iter()
        .map(|finding| {
            let location = finding.url.as_ref().map(|url| {
                serde_json::json!({
                    "physicalLocation": {
                        "artifactLocation": { "uri": url }
                    }
                })
            });
            serde_json::json!({
                "ruleId": finding.id,
                "level": sarif_level(&finding.severity),
                "message": { "text": finding.description },
                "locations": location.into_iter().collect::<Vec<_>>(),
                "properties": {
                    "target": scan.target,
                    "tool": finding.discovered_by,
                    "confirmed": finding.confirmed,
                    "falsePositive": finding.false_positive
                }
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "UniHack",
                    "informationUri": "https://github.com/Jeevanbidgar/UniHack-Cross-Platform-Tool-Orchestrator",
                    "rules": rules
                }
            },
            "automationDetails": { "id": scan.id },
            "results": results
        }]
    })
}

fn generate_html(scan: &Scan, findings: &[Vulnerability]) -> String {
    let rows = findings
        .iter()
        .map(|finding| {
            format!(
                "<tr><td><span class=\"severity {}\">{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&finding.severity.to_ascii_lowercase()),
                html_escape(&finding.severity),
                html_escape(&finding.title),
                html_escape(finding.url.as_deref().unwrap_or("-")),
                html_escape(finding.remediation.as_deref().unwrap_or("Review and remediate the finding.")),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>
body{{font:14px system-ui,sans-serif;margin:40px;color:#172033;background:#f8fafc}}main{{max-width:1100px;margin:auto;background:white;padding:32px;border-radius:12px}}h1{{margin-top:0}}.summary{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:24px 0}}.metric{{padding:14px;border:1px solid #dbe3ee;border-radius:8px}}.metric b{{display:block;font-size:24px}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:10px;border-bottom:1px solid #e5e7eb;vertical-align:top}}.severity{{font-weight:700}}.critical{{color:#991b1b}}.high{{color:#c2410c}}.medium{{color:#a16207}}.low{{color:#1d4ed8}}footer{{margin-top:28px;color:#64748b}}
</style></head><body><main><h1>{title}</h1><p><b>Target:</b> {target}<br><b>Scan:</b> {scan_id}<br><b>Generated:</b> {generated}</p>
<section class="summary"><div class="metric"><b>{total}</b>Total</div><div class="metric"><b>{critical}</b>Critical</div><div class="metric"><b>{high}</b>High</div><div class="metric"><b>{medium}</b>Medium</div><div class="metric"><b>{low}</b>Low</div></section>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Remediation</th></tr></thead><tbody>{rows}</tbody></table>
<footer>Generated locally by UniHack. Validate automated findings before disclosure or remediation.</footer></main></body></html>"#,
        title = html_escape(&scan.name),
        target = html_escape(&scan.target),
        scan_id = html_escape(&scan.id),
        generated = chrono::Utc::now().to_rfc3339(),
        total = findings.len(),
        critical = count_severity(findings, "critical"),
        high = count_severity(findings, "high"),
        medium = count_severity(findings, "medium"),
        low = count_severity(findings, "low"),
        rows = rows,
    )
}

fn count_severity(findings: &[Vulnerability], severity: &str) -> usize {
    findings
        .iter()
        .filter(|finding| finding.severity.eq_ignore_ascii_case(severity))
        .count()
}

fn sarif_level(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::{generate_report, highest_severity};
    use crate::database::{Scan, Vulnerability};
    use chrono::Utc;

    fn scan() -> Scan {
        Scan {
            id: "scan-1".into(),
            name: "Example <Audit>".into(),
            target: "example.com".into(),
            status: "completed".into(),
            scan_type: "test".into(),
            workflow_id: None,
            started: Utc::now(),
            completed: Some(Utc::now()),
            progress: 100,
            current_test: None,
            current_step: None,
            total_steps: Some(1),
            duration: None,
            estimated_time: None,
            description: None,
            tags: None,
            working_directory: None,
            agents: None,
            command_log: None,
            target_validated: true,
            vulnerabilities: Some(1),
            critical: Some(0),
            high: Some(1),
            medium: Some(0),
            low: Some(0),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn finding() -> Vulnerability {
        Vulnerability {
            id: "finding-1".into(),
            scan_id: "scan-1".into(),
            title: "Unsafe <title>".into(),
            severity: "high".into(),
            cvss: Some(8.0),
            description: "Description".into(),
            url: Some("https://example.com/?a=1&b=2".into()),
            parameter: None,
            payload: None,
            remediation: Some("Fix it".into()),
            discovered_by: "nuclei".into(),
            timestamp: Utc::now(),
            false_positive: false,
            confirmed: false,
            evidence: None,
        }
    }

    #[test]
    fn generates_supported_formats_and_escapes_html() {
        let scan = scan();
        let findings = vec![finding()];
        let html = generate_report("html", &scan, &findings).unwrap();
        assert!(html.contains("Example &lt;Audit&gt;"));
        assert!(!html.contains("Unsafe <title>"));
        assert!(generate_report("json", &scan, &findings)
            .unwrap()
            .contains("finding-1"));
        assert!(generate_report("sarif", &scan, &findings)
            .unwrap()
            .contains("2.1.0"));
        assert_eq!(highest_severity(&findings), "high");
    }
}
