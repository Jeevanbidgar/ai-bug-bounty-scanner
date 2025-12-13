use anyhow::Result;
use std::path::Path;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedFinding {
    pub title: String,
    pub severity: Option<String>, // "critical", "high", "medium", "low", "info"
    pub description: Option<String>,
    pub cvss: Option<f64>,
    pub url: Option<String>,
    pub parameter: Option<String>,
    pub payload: Option<String>,
    pub remediation: Option<String>,
    pub evidence: Option<String>,
    pub raw_data: Option<String>, // Store original JSON/XML snippet
}

pub trait OutputParser: Send + Sync {
    /// Parse a file and return a list of findings
    fn parse(&self, file_path: &Path) -> Result<Vec<ParsedFinding>>;
    
    /// Get the tool name this parser supports
    fn tool_name(&self) -> &str;
    
    /// Check if this parser can handle the given file
    fn can_parse(&self, file_path: &Path) -> bool;
}

