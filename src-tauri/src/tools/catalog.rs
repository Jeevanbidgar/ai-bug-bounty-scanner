// Tool catalog with comprehensive security tool definitions
//
// This module defines all security tools supported by the scanner,
// including their command candidates, version flags, categories, and dependencies.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub category: String,
    pub command_candidates: Vec<String>,
    pub version_args: Vec<String>,
    pub output_format: String,
    pub os_dependencies: Vec<String>,
}

impl ToolDefinition {
    pub fn new(
        name: &str,
        description: &str,
        category: &str,
        commands: Vec<&str>,
    ) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            category: category.to_string(),
            command_candidates: commands.iter().map(|s| s.to_string()).collect(),
            version_args: vec!["--version".to_string()],
            output_format: "text".to_string(),
            os_dependencies: vec![],
        }
    }

    pub fn with_version_args(mut self, args: Vec<&str>) -> Self {
        self.version_args = args.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_output_format(mut self, format: &str) -> Self {
        self.output_format = format.to_string();
        self
    }

    pub fn with_os_dependencies(mut self, deps: Vec<&str>) -> Self {
        self.os_dependencies = deps.iter().map(|s| s.to_string()).collect();
        self
    }
}

/// Get the complete catalog of all supported security tools
pub fn get_tool_catalog() -> HashMap<String, ToolDefinition> {
    let mut catalog = HashMap::new();

    // === Subdomain Enumeration & DNS ===
    catalog.insert("subfinder".to_string(), 
        ToolDefinition::new(
            "subfinder",
            "Fast passive subdomain discovery tool",
            "recon",
            vec!["subfinder"]
        ).with_output_format("json")
    );

    catalog.insert("amass".to_string(),
        ToolDefinition::new(
            "amass",
            "Comprehensive network reconnaissance tool",
            "recon",
            vec!["amass"]
        ).with_output_format("json")
    );

    catalog.insert("assetfinder".to_string(),
        ToolDefinition::new(
            "assetfinder",
            "Find domains and subdomains",
            "recon",
            vec!["assetfinder", "assetfinder.exe"]
        )
    );

    catalog.insert("knockpy".to_string(),
        ToolDefinition::new(
            "knockpy",
            "Subdomain scanner",
            "recon",
            vec!["knockpy"]
        )
    );

    catalog.insert("sublist3r".to_string(),
        ToolDefinition::new(
            "sublist3r",
            "Fast subdomains enumeration tool",
            "recon",
            vec!["sublist3r"]
        )
    );

    catalog.insert("dnsrecon".to_string(),
        ToolDefinition::new(
            "dnsrecon",
            "DNS enumeration script",
            "recon",
            vec!["dnsrecon"]
        )
    );

    catalog.insert("fierce".to_string(),
        ToolDefinition::new(
            "fierce",
            "DNS reconnaissance tool",
            "recon",
            vec!["fierce"]
        )
    );

    catalog.insert("dnsenum".to_string(),
        ToolDefinition::new(
            "dnsenum",
            "DNS enumeration tool",
            "recon",
            vec!["dnsenum"]
        )
    );

    // === Port Scanning ===
    catalog.insert("nmap".to_string(),
        ToolDefinition::new(
            "nmap",
            "Network discovery and security auditing tool",
            "network",
            vec!["nmap"]
        ).with_version_args(vec!["-V"])
         .with_output_format("xml")
         .with_os_dependencies(vec!["libpcap"])
    );

    catalog.insert("naabu".to_string(),
        ToolDefinition::new(
            "naabu",
            "Fast port scanner",
            "network",
            vec!["naabu"]
        ).with_os_dependencies(vec!["libpcap"])
    );

    catalog.insert("masscan".to_string(),
        ToolDefinition::new(
            "masscan",
            "TCP port scanner",
            "network",
            vec!["masscan"]
        ).with_os_dependencies(vec!["libpcap"])
    );

    catalog.insert("rustscan".to_string(),
        ToolDefinition::new(
            "rustscan",
            "Modern port scanner",
            "network",
            vec!["rustscan"]
        )
    );

    // === HTTP Probing & Web Analysis ===
    catalog.insert("httpx".to_string(),
        ToolDefinition::new(
            "httpx",
            "Fast HTTP probe",
            "web",
            vec!["httpx", "httpx.exe"]
        ).with_output_format("json")
    );

    catalog.insert("httprobe".to_string(),
        ToolDefinition::new(
            "httprobe",
            "HTTP/HTTPS probe",
            "web",
            vec!["httprobe"]
        )
    );

    catalog.insert("meg".to_string(),
        ToolDefinition::new(
            "meg",
            "Fetch many paths for many hosts",
            "web",
            vec!["meg"]
        )
    );

    // === Web Crawling & Spidering ===
    catalog.insert("katana".to_string(),
        ToolDefinition::new(
            "katana",
            "Web crawler from ProjectDiscovery",
            "web",
            vec!["katana", "katana.exe"]
        ).with_output_format("json")
    );

    catalog.insert("gospider".to_string(),
        ToolDefinition::new(
            "gospider",
            "Fast web spider",
            "web",
            vec!["gospider"]
        )
    );

    catalog.insert("hakrawler".to_string(),
        ToolDefinition::new(
            "hakrawler",
            "Simple, fast web crawler",
            "web",
            vec!["hakrawler"]
        )
    );

    // === URL Discovery ===
    catalog.insert("gau".to_string(),
        ToolDefinition::new(
            "gau",
            "Get all URLs from various sources",
            "recon",
            vec!["gau"]
        )
    );

    catalog.insert("waybackurls".to_string(),
        ToolDefinition::new(
            "waybackurls",
            "Wayback Machine URL fetcher",
            "recon",
            vec!["waybackurls"]
        )
    );

    catalog.insert("gauplus".to_string(),
        ToolDefinition::new(
            "gauplus",
            "Modified GAU with additional features",
            "recon",
            vec!["gauplus"]
        )
    );

    // === Vulnerability Scanning ===
    catalog.insert("nuclei".to_string(),
        ToolDefinition::new(
            "nuclei",
            "Fast and customizable vulnerability scanner",
            "vulnerability",
            vec!["nuclei"]
        ).with_output_format("jsonl")
    );

    catalog.insert("nikto".to_string(),
        ToolDefinition::new(
            "nikto",
            "Web server scanner",
            "vulnerability",
            vec!["nikto"]
        )
    );

    catalog.insert("wpscan".to_string(),
        ToolDefinition::new(
            "wpscan",
            "WordPress vulnerability scanner",
            "vulnerability",
            vec!["wpscan"]
        )
    );

    catalog.insert("joomscan".to_string(),
        ToolDefinition::new(
            "joomscan",
            "Joomla vulnerability scanner",
            "vulnerability",
            vec!["joomscan"]
        )
    );

    // === Directory & File Brute Forcing ===
    catalog.insert("ffuf".to_string(),
        ToolDefinition::new(
            "ffuf",
            "Fast web fuzzer",
            "web",
            vec!["ffuf"]
        ).with_output_format("json")
    );

    catalog.insert("gobuster".to_string(),
        ToolDefinition::new(
            "gobuster",
            "Directory/DNS brute force tool",
            "web",
            vec!["gobuster"]
        )
    );

    catalog.insert("dirbuster".to_string(),
        ToolDefinition::new(
            "dirbuster",
            "Web directory brute forcer",
            "web",
            vec!["dirbuster"]
        )
    );

    catalog.insert("feroxbuster".to_string(),
        ToolDefinition::new(
            "feroxbuster",
            "Fast content discovery tool",
            "web",
            vec!["feroxbuster"]
        )
    );

    catalog.insert("wfuzz".to_string(),
        ToolDefinition::new(
            "wfuzz",
            "Web application fuzzer",
            "web",
            vec!["wfuzz"]
        )
    );

    // === Parameter Discovery & Fuzzing ===
    catalog.insert("arjun".to_string(),
        ToolDefinition::new(
            "arjun",
            "HTTP parameter discovery tool",
            "web",
            vec!["arjun", "arjun.exe"]
        )
    );

    catalog.insert("param-miner".to_string(),
        ToolDefinition::new(
            "param-miner",
            "Parameter mining tool",
            "web",
            vec!["param-miner"]
        )
    );

    // === SQL Injection ===
    catalog.insert("sqlmap".to_string(),
        ToolDefinition::new(
            "sqlmap",
            "Automatic SQL injection tool",
            "web",
            vec!["sqlmap"]
        )
    );

    // === XSS Detection ===
    catalog.insert("dalfox".to_string(),
        ToolDefinition::new(
            "dalfox",
            "Fast XSS scanner",
            "web",
            vec!["dalfox"]
        )
    );

    catalog.insert("xsstrike".to_string(),
        ToolDefinition::new(
            "xsstrike",
            "XSS detection suite",
            "web",
            vec!["xsstrike"]
        )
    );

    // === Technology Detection ===
    catalog.insert("wappalyzer".to_string(),
        ToolDefinition::new(
            "wappalyzer",
            "Technology detection",
            "recon",
            vec!["wappalyzer"]
        )
    );

    catalog.insert("whatweb".to_string(),
        ToolDefinition::new(
            "whatweb",
            "Web technology identification",
            "recon",
            vec!["whatweb"]
        )
    );

    // === Screenshot & Visual Recon ===
    catalog.insert("gowitness".to_string(),
        ToolDefinition::new(
            "gowitness",
            "Web screenshot utility",
            "recon",
            vec!["gowitness"]
        )
    );

    catalog.insert("aquatone".to_string(),
        ToolDefinition::new(
            "aquatone",
            "Domain flyover tool",
            "recon",
            vec!["aquatone"]
        )
    );

    catalog.insert("eyewitness".to_string(),
        ToolDefinition::new(
            "eyewitness",
            "Website screenshot tool",
            "recon",
            vec!["eyewitness"]
        )
    );

    // === JavaScript Analysis ===
    catalog.insert("linkfinder".to_string(),
        ToolDefinition::new(
            "linkfinder",
            "Find endpoints in JS files",
            "recon",
            vec!["linkfinder"]
        )
    );

    catalog.insert("subjs".to_string(),
        ToolDefinition::new(
            "subjs",
            "Find JavaScript files",
            "recon",
            vec!["subjs"]
        )
    );

    // === SSRF & Testing ===
    catalog.insert("interactsh-client".to_string(),
        ToolDefinition::new(
            "interactsh-client",
            "OAST client",
            "testing",
            vec!["interactsh-client"]
        )
    );

    // === Exploitation Frameworks ===
    catalog.insert("metasploit".to_string(),
        ToolDefinition::new(
            "metasploit",
            "Penetration testing framework",
            "exploitation",
            vec!["msfconsole"]
        )
    );

    catalog.insert("searchsploit".to_string(),
        ToolDefinition::new(
            "searchsploit",
            "Exploit database search",
            "exploitation",
            vec!["searchsploit"]
        )
    );

    // === Network Tools ===
    catalog.insert("netcat".to_string(),
        ToolDefinition::new(
            "netcat",
            "Network utility",
            "network",
            vec!["nc", "netcat"]
        ).with_version_args(vec!["-h"])
    );

    catalog.insert("socat".to_string(),
        ToolDefinition::new(
            "socat",
            "Multipurpose relay",
            "network",
            vec!["socat"]
        ).with_version_args(vec!["-V"])
    );

    // === Git Tools ===
    catalog.insert("git".to_string(),
        ToolDefinition::new(
            "git",
            "Version control system",
            "utility",
            vec!["git"]
        )
    );

    catalog.insert("trufflehog".to_string(),
        ToolDefinition::new(
            "trufflehog",
            "Find secrets in git repos",
            "security",
            vec!["trufflehog"]
        )
    );

    catalog.insert("gitleaks".to_string(),
        ToolDefinition::new(
            "gitleaks",
            "Secret scanning tool",
            "security",
            vec!["gitleaks"]
        )
    );

    // === Cloud Security ===
    catalog.insert("s3scanner".to_string(),
        ToolDefinition::new(
            "s3scanner",
            "S3 bucket scanner",
            "cloud",
            vec!["s3scanner"]
        )
    );

    catalog.insert("cloudfail".to_string(),
        ToolDefinition::new(
            "cloudfail",
            "Find origin servers",
            "cloud",
            vec!["cloudfail"]
        )
    );

    // === Utilities ===
    catalog.insert("curl".to_string(),
        ToolDefinition::new(
            "curl",
            "Transfer data with URLs",
            "utility",
            vec!["curl"]
        )
    );

    catalog.insert("wget".to_string(),
        ToolDefinition::new(
            "wget",
            "Network downloader",
            "utility",
            vec!["wget"]
        )
    );

    catalog.insert("jq".to_string(),
        ToolDefinition::new(
            "jq",
            "JSON processor",
            "utility",
            vec!["jq"]
        )
    );

    catalog.insert("python".to_string(),
        ToolDefinition::new(
            "python",
            "Python interpreter",
            "utility",
            vec!["python", "python3"]
        ).with_version_args(vec!["--version"])
    );

    catalog.insert("go".to_string(),
        ToolDefinition::new(
            "go",
            "Go programming language",
            "utility",
            vec!["go"]
        ).with_version_args(vec!["version"])
    );

    catalog
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catalog_size() {
        let catalog = get_tool_catalog();
        assert!(catalog.len() >= 70, "Catalog should have at least 70 tools");
    }

    #[test]
    fn test_subfinder_definition() {
        let catalog = get_tool_catalog();
        let subfinder = catalog.get("subfinder").unwrap();
        assert_eq!(subfinder.name, "subfinder");
        assert_eq!(subfinder.category, "recon");
        assert_eq!(subfinder.output_format, "json");
    }

    #[test]
    fn test_all_tools_have_commands() {
        let catalog = get_tool_catalog();
        for (name, tool) in catalog.iter() {
            assert!(!tool.command_candidates.is_empty(), 
                "Tool {} should have at least one command candidate", name);
        }
    }
}
