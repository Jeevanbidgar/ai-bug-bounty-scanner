use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub max_parallel_steps: usize,
    pub default_step_timeout_seconds: u64,
    pub max_output_lines_per_stream: usize,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            max_parallel_steps: 4,
            default_step_timeout_seconds: 300,
            max_output_lines_per_stream: 10_000,
        }
    }
}

impl AppSettings {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=16).contains(&self.max_parallel_steps) {
            return Err("Parallel steps must be between 1 and 16".to_string());
        }
        if !(30..=86_400).contains(&self.default_step_timeout_seconds) {
            return Err("Default step timeout must be between 30 and 86400 seconds".to_string());
        }
        if !(100..=100_000).contains(&self.max_output_lines_per_stream) {
            return Err("Captured lines per stream must be between 100 and 100000".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::AppSettings;

    #[test]
    fn validates_runtime_limits() {
        assert!(AppSettings::default().validate().is_ok());

        let settings = AppSettings {
            max_parallel_steps: 0,
            ..AppSettings::default()
        };
        assert!(settings.validate().is_err());
    }
}
