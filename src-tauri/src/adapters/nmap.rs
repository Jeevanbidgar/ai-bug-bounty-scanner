use super::types::*;
use std::collections::HashMap;

/// Nmap adapter for comprehensive network scanning
pub struct NmapAdapter;

impl NmapAdapter {
    /// Create command arguments for nmap
    pub fn build_command(target: &str, output_file: Option<&str>, options: &HashMap<String, String>) -> Vec<String> {
        let mut args = Vec::new();

        // Add target
        args.push(target.to_string());

        // Add output file if specified
        if let Some(output) = output_file {
            args.push("-oN".to_string()); // Normal output format
            args.push(output.to_string());
        }

        // Add custom options
        for (key, value) in options {
            match key.as_str() {
                "ports" => {
                    args.push("-p".to_string());
                    args.push(value.clone());
                }
                "top_ports" => {
                    args.push("--top-ports".to_string());
                    args.push(value.clone());
                }
                "port_ratio" => {
                    args.push("--port-ratio".to_string());
                    args.push(value.clone());
                }
                "scan_type" => {
                    match value.as_str() {
                        "syn" => args.push("-sS".to_string()),
                        "connect" => args.push("-sT".to_string()),
                        "ack" => args.push("-sA".to_string()),
                        "window" => args.push("-sW".to_string()),
                        "maimon" => args.push("-sM".to_string()),
                        "udp" => args.push("-sU".to_string()),
                        "sctp" => args.push("-sY".to_string()),
                        "ip" => args.push("-sO".to_string()),
                        "ping" => args.push("-sn".to_string()),
                        _ => args.push(format!("-s{}", value)),
                    }
                }
                "timing" => {
                    args.push(format!("-T{}", value));
                }
                "min_rate" => {
                    args.push("--min-rate".to_string());
                    args.push(value.clone());
                }
                "max_rate" => {
                    args.push("--max-rate".to_string());
                    args.push(value.clone());
                }
                "min_parallelism" => {
                    args.push("--min-parallelism".to_string());
                    args.push(value.clone());
                }
                "max_parallelism" => {
                    args.push("--max-parallelism".to_string());
                    args.push(value.clone());
                }
                "service_detection" if value == "true" => args.push("-sV".to_string()),
                "os_detection" if value == "true" => args.push("-O".to_string()),
                "traceroute" if value == "true" => args.push("--traceroute".to_string()),
                "script_scan" if value == "true" => args.push("-sC".to_string()),
                "script" => {
                    args.push("--script".to_string());
                    args.push(value.clone());
                }
                "version_light" if value == "true" => args.push("--version-light".to_string()),
                "version_all" if value == "true" => args.push("--version-all".to_string()),
                "aggressive" if value == "true" => args.push("-A".to_string()),
                "spoof_mac" => {
                    args.push("--spoof-mac".to_string());
                    args.push(value.clone());
                }
                "dns_servers" => {
                    for server in value.split(',') {
                        args.push("--dns-servers".to_string());
                        args.push(server.trim().to_string());
                    }
                }
                "verbose" if value == "true" => args.push("-v".to_string()),
                "debug" if value == "true" => args.push("-d".to_string()),
                "reason" if value == "true" => args.push("--reason".to_string()),
                "packet_trace" if value == "true" => args.push("--packet-trace".to_string()),
                "iflist" if value == "true" => args.push("--iflist".to_string()),
                "append_output" if value == "true" => args.push("--append-output".to_string()),
                "resume" => {
                    args.push("--resume".to_string());
                    args.push(value.clone());
                }
                "stylesheet" => {
                    args.push("--stylesheet".to_string());
                    args.push(value.clone());
                }
                "script_args" => {
                    args.push("--script-args".to_string());
                    args.push(value.clone());
                }
                "script_args_file" => {
                    args.push("--script-args-file".to_string());
                    args.push(value.clone());
                }
                "script_trace" if value == "true" => args.push("--script-trace".to_string()),
                "script_updatedb" if value == "true" => args.push("--script-updatedb".to_string()),
                "script_help" => {
                    args.push("--script-help".to_string());
                    args.push(value.clone());
                }
                _ => {
                    // Unknown options are ignored for safety
                }
            }
        }

        args
    }

    /// Get environment variables for nmap
    pub fn get_environment(_options: &HashMap<String, String>) -> HashMap<String, String> {
        HashMap::new()
    }

    /// Get working directory for nmap (uses current directory)
    pub fn get_working_directory() -> Option<String> {
        None
    }

    /// Get timeout in milliseconds for nmap (depends on scan type and target)
    pub fn get_timeout_ms(target: &str, options: &HashMap<String, String>) -> u64 {
        let base_timeout = 300000; // 5 minutes base

        // Adjust based on scan type
        if let Some(scan_type) = options.get("scan_type") {
            match scan_type.as_str() {
                "udp" => base_timeout * 3, // UDP scans are slower
                "sctp" => base_timeout * 2, // SCTP scans are slower
                "ping" => base_timeout / 3, // Ping scans are faster
                _ => base_timeout,
            }
        } else if let Some(timing) = options.get("timing") {
            // Adjust based on timing template
            match timing.as_str() {
                "1" | "2" => base_timeout / 2, // Faster timing
                "4" | "5" => base_timeout * 2, // Slower timing
                _ => base_timeout,
            }
        } else {
            // Default timing based on target type
            if target.contains('/') {
                // CIDR notation or range - could be large
                base_timeout * 2
            } else if target.parse::<std::net::Ipv4Addr>().is_ok() {
                // Single IP - standard timeout
                base_timeout
            } else {
                // Domain - moderate timeout
                base_timeout
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nmap_basic_command() {
        let args = NmapAdapter::build_command("192.168.1.1", None, &HashMap::new());
        assert!(args.contains(&"192.168.1.1".to_string()));
    }

    #[test]
    fn test_nmap_with_ports() {
        let mut options = HashMap::new();
        options.insert("ports".to_string(), "80,443,22".to_string());

        let args = NmapAdapter::build_command("example.com", None, &options);
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"80,443,22".to_string()));
    }

    #[test]
    fn test_nmap_with_scan_type() {
        let mut options = HashMap::new();
        options.insert("scan_type".to_string(), "syn".to_string());

        let args = NmapAdapter::build_command("example.com", None, &options);
        assert!(args.contains(&"-sS".to_string()));
    }

    #[test]
    fn test_nmap_with_service_detection() {
        let mut options = HashMap::new();
        options.insert("service_detection".to_string(), "true".to_string());

        let args = NmapAdapter::build_command("example.com", None, &options);
        assert!(args.contains(&"-sV".to_string()));
    }

    #[test]
    fn test_nmap_with_output() {
        let args = NmapAdapter::build_command("example.com", Some("output.txt"), &HashMap::new());
        assert!(args.contains(&"-oN".to_string()));
        assert!(args.contains(&"output.txt".to_string()));
    }
}