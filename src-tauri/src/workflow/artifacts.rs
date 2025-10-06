use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::workflow::types::WorkflowArtifact;

/// Manages workflow artifacts with enrichment and cleanup
pub struct ArtifactManager {
    base_directory: PathBuf,
    max_age_days: i64,
    max_size_bytes: u64,
}

impl ArtifactManager {
    /// Create a new ArtifactManager
    pub fn new(base_directory: PathBuf) -> Self {
        Self {
            base_directory,
            max_age_days: 30,           // Default: keep artifacts for 30 days
            max_size_bytes: 10_000_000, // Default: 10 MB per artifact
        }
    }

    /// Set maximum age for artifacts (in days)
    pub fn with_max_age(mut self, days: i64) -> Self {
        self.max_age_days = days;
        self
    }

    /// Set maximum size for artifacts (in bytes)
    pub fn with_max_size(mut self, bytes: u64) -> Self {
        self.max_size_bytes = bytes;
        self
    }

    /// Enrich a workflow artifact with metadata
    pub async fn enrich_artifact(&self, artifact: &mut WorkflowArtifact) -> Result<()> {
        let file_path_str = artifact
            .file_path
            .as_ref()
            .ok_or_else(|| anyhow!("Artifact has no file path"))?;
        let path = Path::new(file_path_str);

        if !path.exists() {
            return Err(anyhow!("Artifact file does not exist: {}", file_path_str));
        }

        // Get file metadata
        let metadata = fs::metadata(path)?;
        artifact.size = Some(metadata.len());

        // Calculate file hash (SHA256)
        let hash = self.calculate_file_hash(path)?;
        artifact.hash = Some(hash);

        // Count lines for text files
        if self.is_text_file(path) {
            let line_count = self.count_lines(path)?;

            // Store metadata as JSON
            let mut metadata_map = HashMap::new();
            metadata_map.insert("line_count".to_string(), line_count.to_string());
            metadata_map.insert("is_text".to_string(), "true".to_string());

            // Store as JSON string in metadata_ field
            artifact.metadata_ = Some(serde_json::to_string(&metadata_map)?);

            eprintln!("Artifact '{}' has {} lines", artifact.name, line_count);
        }

        Ok(())
    }

    /// Calculate SHA256 hash of a file
    fn calculate_file_hash(&self, path: &Path) -> Result<String> {
        let mut file = fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let result = hasher.finalize();
        Ok(format!("{:x}", result))
    }

    /// Check if a file is a text file
    fn is_text_file(&self, path: &Path) -> bool {
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            matches!(
                ext_str.as_str(),
                "txt"
                    | "log"
                    | "json"
                    | "yaml"
                    | "yml"
                    | "xml"
                    | "csv"
                    | "md"
                    | "html"
                    | "js"
                    | "ts"
                    | "py"
                    | "rs"
            )
        } else {
            false
        }
    }

    /// Count lines in a text file
    fn count_lines(&self, path: &Path) -> Result<usize> {
        let content = fs::read_to_string(path)?;
        Ok(content.lines().count())
    }

    /// Resolve artifact reference from template variable
    /// Example: {{artifacts.step_id.artifact_name}} -> /path/to/artifact
    pub fn resolve_artifact_reference(
        &self,
        reference: &str,
        artifacts: &HashMap<String, Vec<WorkflowArtifact>>,
    ) -> Option<String> {
        // Parse reference: "artifacts.step_id.artifact_name"
        let parts: Vec<&str> = reference.split('.').collect();

        if parts.len() != 3 || parts[0] != "artifacts" {
            return None;
        }

        let step_id = parts[1];
        let artifact_name = parts[2];

        // Find artifact in the specified step
        if let Some(step_artifacts) = artifacts.get(step_id) {
            for artifact in step_artifacts {
                if artifact.name == artifact_name {
                    return artifact.file_path.clone();
                }
            }
        }

        None
    }

    /// Clean up old artifacts based on age
    pub async fn cleanup_old_artifacts(&self, execution_id: &str) -> Result<usize> {
        let execution_dir = self.base_directory.join(execution_id);

        if !execution_dir.exists() {
            return Ok(0);
        }

        let cutoff_date = Utc::now() - Duration::days(self.max_age_days);
        let mut deleted_count = 0;

        // Iterate through artifacts in the execution directory
        for entry in fs::read_dir(&execution_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                let metadata = fs::metadata(&path)?;

                if let Ok(modified) = metadata.modified() {
                    let modified_datetime: DateTime<Utc> = modified.into();

                    if modified_datetime < cutoff_date {
                        fs::remove_file(&path)?;
                        deleted_count += 1;
                        eprintln!("Deleted old artifact: {}", path.display());
                    }
                }
            }
        }

        Ok(deleted_count)
    }

    /// Clean up artifacts exceeding size limit
    pub async fn cleanup_large_artifacts(&self, execution_id: &str) -> Result<usize> {
        let execution_dir = self.base_directory.join(execution_id);

        if !execution_dir.exists() {
            return Ok(0);
        }

        let mut deleted_count = 0;

        for entry in fs::read_dir(&execution_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                let metadata = fs::metadata(&path)?;

                if metadata.len() > self.max_size_bytes {
                    fs::remove_file(&path)?;
                    deleted_count += 1;
                    eprintln!(
                        "Deleted large artifact ({}): {}",
                        metadata.len(),
                        path.display()
                    );
                }
            }
        }

        Ok(deleted_count)
    }

    /// Get total size of artifacts for an execution
    pub async fn get_execution_artifacts_size(&self, execution_id: &str) -> Result<u64> {
        let execution_dir = self.base_directory.join(execution_id);

        if !execution_dir.exists() {
            return Ok(0);
        }

        let mut total_size = 0u64;

        for entry in fs::read_dir(&execution_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                let metadata = fs::metadata(&path)?;
                total_size += metadata.len();
            }
        }

        Ok(total_size)
    }

    /// List all artifacts for an execution
    pub async fn list_execution_artifacts(&self, execution_id: &str) -> Result<Vec<PathBuf>> {
        let execution_dir = self.base_directory.join(execution_id);

        if !execution_dir.exists() {
            return Ok(Vec::new());
        }

        let mut artifacts = Vec::new();

        for entry in fs::read_dir(&execution_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                artifacts.push(path);
            }
        }

        Ok(artifacts)
    }

    /// Create artifact directory for an execution
    pub fn create_artifact_directory(&self, execution_id: &str) -> Result<PathBuf> {
        let execution_dir = self.base_directory.join(execution_id);

        if !execution_dir.exists() {
            fs::create_dir_all(&execution_dir)?;
        }

        Ok(execution_dir)
    }

    /// Delete all artifacts for an execution
    pub async fn delete_execution_artifacts(&self, execution_id: &str) -> Result<()> {
        let execution_dir = self.base_directory.join(execution_id);

        if execution_dir.exists() {
            fs::remove_dir_all(&execution_dir)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_artifact_enrichment() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ArtifactManager::new(temp_dir.path().to_path_buf());

        // Create a test file
        let test_file = temp_dir.path().join("test.txt");
        let mut file = fs::File::create(&test_file).unwrap();
        writeln!(file, "Line 1").unwrap();
        writeln!(file, "Line 2").unwrap();
        writeln!(file, "Line 3").unwrap();

        let mut artifact = WorkflowArtifact {
            id: "test-artifact".to_string(),
            execution_id: "test-execution".to_string(),
            step_id: "test-step".to_string(),
            name: "test.txt".to_string(),
            artifact_type: "output".to_string(),
            file_path: Some(test_file.to_string_lossy().to_string()),
            content: None,
            metadata_: None,
            size: None,
            hash: None,
            created_at: Utc::now(),
        };

        manager.enrich_artifact(&mut artifact).await.unwrap();

        assert!(artifact.size.is_some());
        assert!(artifact.hash.is_some());
        assert!(artifact.size.unwrap() > 0);
    }

    #[tokio::test]
    async fn test_artifact_reference_resolution() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ArtifactManager::new(temp_dir.path().to_path_buf());

        let mut artifacts = HashMap::new();
        artifacts.insert(
            "step1".to_string(),
            vec![WorkflowArtifact {
                id: "artifact1".to_string(),
                execution_id: "exec1".to_string(),
                step_id: "step1".to_string(),
                name: "output.txt".to_string(),
                file_path: Some("/path/to/output.txt".to_string()),
                artifact_type: "output".to_string(),
                content: None,
                metadata_: None,
                size: None,
                hash: None,
                created_at: Utc::now(),
            }],
        );

        let resolved = manager.resolve_artifact_reference("artifacts.step1.output.txt", &artifacts);

        assert_eq!(resolved, Some("/path/to/output.txt".to_string()));
    }
}
