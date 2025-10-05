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
    
    // Installation metadata (Phase 2)
    pub go_module: Option<String>,        // Go module path for `go install`
    pub pipx_package: Option<String>,     // pipx package name for Python CLI tools
    pub git_repo: Option<String>,         // Git repository URL for Python tools
    pub apt_package: Option<String>,      // APT package name (Linux)
    pub winget_id: Option<String>,        // WinGet package ID (Windows)
    pub cargo_package: Option<String>,    // Cargo package name for Rust tools
    pub gem_package: Option<String>,      // Ruby gem package name
    pub npm_package: Option<String>,      // npm package name for Node.js tools
    pub install_method: String,           // Primary installation method: "go", "pipx", "git-pip", "apt", "winget", "cargo", "gem", "npm", "manual", "runtime"
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
            go_module: None,
            pipx_package: None,
            git_repo: None,
            apt_package: None,
            winget_id: None,
            cargo_package: None,
            gem_package: None,
            npm_package: None,
            install_method: "manual".to_string(),
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
    
    // Installation metadata builders (Phase 2)
    pub fn with_go_module(mut self, module: &str) -> Self {
        self.go_module = Some(module.to_string());
        self.install_method = "go".to_string();
        self
    }
    
    pub fn with_git_repo(mut self, repo: &str) -> Self {
        self.git_repo = Some(repo.to_string());
        self.install_method = "git-pip".to_string();
        self
    }
    
    pub fn with_apt_package(mut self, package: &str) -> Self {
        self.apt_package = Some(package.to_string());
        self.install_method = "apt".to_string();
        self
    }
    
    pub fn with_winget_id(mut self, id: &str) -> Self {
        self.winget_id = Some(id.to_string());
        self.install_method = "winget".to_string();
        self
    }
    
    pub fn with_cargo_package(mut self, package: &str) -> Self {
        self.cargo_package = Some(package.to_string());
        self.install_method = "cargo".to_string();
        self
    }
    
    pub fn with_gem_package(mut self, package: &str) -> Self {
        self.gem_package = Some(package.to_string());
        self.install_method = "gem".to_string();
        self
    }
    
    pub fn with_npm_package(mut self, package: &str) -> Self {
        self.npm_package = Some(package.to_string());
        self.install_method = "npm".to_string();
        self
    }
    
    pub fn with_manual_install(mut self) -> Self {
        self.install_method = "manual".to_string();
        self.install_method = "winget".to_string();
        self
    }
    
    pub fn with_install_method(mut self, method: &str) -> Self {
        self.install_method = method.to_string();
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
        )
        .with_output_format("json")
        .with_go_module("github.com/projectdiscovery/subfinder/v2/cmd/subfinder")
    );

    catalog.insert("amass".to_string(),
        ToolDefinition::new(
            "amass",
            "Comprehensive network reconnaissance tool",
            "recon",
            vec!["amass"]
        )
        .with_output_format("json")
        .with_go_module("github.com/owasp-amass/amass/v4/...")
    );

    catalog.insert("assetfinder".to_string(),
        ToolDefinition::new(
            "assetfinder",
            "Find domains and subdomains",
            "recon",
            vec!["assetfinder", "assetfinder.exe"]
        )
        .with_go_module("github.com/tomnomnom/assetfinder")
    );

    catalog.insert("knockpy".to_string(),
        ToolDefinition::new(
            "knockpy",
            "Subdomain scanner",
            "recon",
            vec!["knockpy"]
        )
        .with_git_repo("https://github.com/guelfoweb/knock.git")
    );

    catalog.insert("sublist3r".to_string(),
        ToolDefinition::new(
            "sublist3r",
            "Fast subdomains enumeration tool",
            "recon",
            vec!["sublist3r"]
        )
        .with_git_repo("https://github.com/aboul3la/Sublist3r.git")
    );

    catalog.insert("dnsrecon".to_string(),
        ToolDefinition::new(
            "dnsrecon",
            "DNS enumeration script",
            "recon",
            vec!["dnsrecon"]
        )
        .with_git_repo("https://github.com/darkoperator/dnsrecon.git")
    );

    catalog.insert("fierce".to_string(),
        ToolDefinition::new(
            "fierce",
            "DNS reconnaissance tool",
            "recon",
            vec!["fierce"]
        )
        .with_git_repo("https://github.com/mschwager/fierce.git")
    );

    catalog.insert("dnsenum".to_string(),
        ToolDefinition::new(
            "dnsenum",
            "DNS enumeration tool",
            "recon",
            vec!["dnsenum"]
        )
        .with_os_dependencies(vec!["perl"])
        .with_apt_package("dnsenum")
        .with_install_method("manual")
    );

    // === Port Scanning ===
    catalog.insert("nmap".to_string(),
        ToolDefinition::new(
            "nmap",
            "Network discovery and security auditing tool",
            "network",
            vec!["nmap"]
        )
        .with_version_args(vec!["-V"])
        .with_output_format("xml")
        .with_os_dependencies(vec!["libpcap"])
        .with_apt_package("nmap")
        .with_winget_id("Nmap.Nmap")
    );

    catalog.insert("naabu".to_string(),
        ToolDefinition::new(
            "naabu",
            "Fast port scanner",
            "network",
            vec!["naabu"]
        )
        .with_os_dependencies(vec!["libpcap"])
        .with_go_module("github.com/projectdiscovery/naabu/v2/cmd/naabu")
    );

    catalog.insert("masscan".to_string(),
        ToolDefinition::new(
            "masscan",
            "TCP port scanner",
            "network",
            vec!["masscan"]
        )
        .with_os_dependencies(vec!["libpcap"])
        .with_apt_package("masscan")
        .with_install_method("manual")
    );

    catalog.insert("rustscan".to_string(),
        ToolDefinition::new(
            "rustscan",
            "Modern port scanner",
            "network",
            vec!["rustscan"]
        )
        .with_cargo_package("rustscan")
    );

    // === HTTP Probing & Web Analysis ===
    catalog.insert("httpx".to_string(),
        ToolDefinition::new(
            "httpx",
            "Fast HTTP probe",
            "web",
            vec!["httpx", "httpx.exe"]
        )
        .with_output_format("json")
        .with_go_module("github.com/projectdiscovery/httpx/cmd/httpx")
    );

    catalog.insert("httprobe".to_string(),
        ToolDefinition::new(
            "httprobe",
            "HTTP/HTTPS probe",
            "web",
            vec!["httprobe"]
        )
        .with_go_module("github.com/tomnomnom/httprobe")
    );

    catalog.insert("meg".to_string(),
        ToolDefinition::new(
            "meg",
            "Fetch many paths for many hosts",
            "web",
            vec!["meg"]
        )
        .with_go_module("github.com/tomnomnom/meg")
    );

    // === Web Crawling & Spidering ===
    catalog.insert("katana".to_string(),
        ToolDefinition::new(
            "katana",
            "Web crawler from ProjectDiscovery",
            "web",
            vec!["katana", "katana.exe"]
        )
        .with_output_format("json")
        .with_go_module("github.com/projectdiscovery/katana/cmd/katana")
    );

    catalog.insert("gospider".to_string(),
        ToolDefinition::new(
            "gospider",
            "Fast web spider",
            "web",
            vec!["gospider"]
        )
        .with_go_module("github.com/jaeles-project/gospider")
    );

    catalog.insert("hakrawler".to_string(),
        ToolDefinition::new(
            "hakrawler",
            "Simple, fast web crawler",
            "web",
            vec!["hakrawler"]
        )
        .with_go_module("github.com/hakluke/hakrawler")
    );

    // === URL Discovery ===
    catalog.insert("gau".to_string(),
        ToolDefinition::new(
            "gau",
            "Get all URLs from various sources",
            "recon",
            vec!["gau"]
        )
        .with_go_module("github.com/lc/gau/v2/cmd/gau")
    );

    catalog.insert("waybackurls".to_string(),
        ToolDefinition::new(
            "waybackurls",
            "Wayback Machine URL fetcher",
            "recon",
            vec!["waybackurls"]
        )
        .with_go_module("github.com/tomnomnom/waybackurls")
    );

    catalog.insert("gauplus".to_string(),
        ToolDefinition::new(
            "gauplus",
            "Modified GAU with additional features",
            "recon",
            vec!["gauplus"]
        )
        .with_go_module("github.com/bp0lr/gauplus")
    );

    // === Vulnerability Scanning ===
    catalog.insert("nuclei".to_string(),
        ToolDefinition::new(
            "nuclei",
            "Fast and customizable vulnerability scanner",
            "vulnerability",
            vec!["nuclei"]
        )
        .with_output_format("jsonl")
        .with_go_module("github.com/projectdiscovery/nuclei/v3/cmd/nuclei")
    );

    catalog.insert("nikto".to_string(),
        ToolDefinition::new(
            "nikto",
            "Web server scanner",
            "vulnerability",
            vec!["nikto"]
        )
        .with_os_dependencies(vec!["perl"])
        .with_apt_package("nikto")
        .with_install_method("manual")
    );

    catalog.insert("wpscan".to_string(),
        ToolDefinition::new(
            "wpscan",
            "WordPress vulnerability scanner",
            "vulnerability",
            vec!["wpscan"]
        )
        .with_gem_package("wpscan")
        .with_apt_package("wpscan")
    );

    catalog.insert("joomscan".to_string(),
        ToolDefinition::new(
            "joomscan",
            "Joomla vulnerability scanner",
            "vulnerability",
            vec!["joomscan"]
        )
        .with_os_dependencies(vec!["perl"])
        .with_git_repo("https://github.com/OWASP/joomscan.git")
    );

    // === Directory & File Brute Forcing ===
    catalog.insert("ffuf".to_string(),
        ToolDefinition::new(
            "ffuf",
            "Fast web fuzzer",
            "web",
            vec!["ffuf"]
        )
        .with_output_format("json")
        .with_go_module("github.com/ffuf/ffuf/v2")
    );

    catalog.insert("gobuster".to_string(),
        ToolDefinition::new(
            "gobuster",
            "Directory/DNS brute force tool",
            "web",
            vec!["gobuster"]
        )
        .with_go_module("github.com/OJ/gobuster/v3")
    );

    catalog.insert("dirbuster".to_string(),
        ToolDefinition::new(
            "dirbuster",
            "Web directory brute forcer (Java)",
            "web",
            vec!["dirbuster"]
        )
        .with_os_dependencies(vec!["java"])
        .with_apt_package("dirbuster")
        .with_install_method("manual")
    );

    catalog.insert("feroxbuster".to_string(),
        ToolDefinition::new(
            "feroxbuster",
            "Fast content discovery tool",
            "web",
            vec!["feroxbuster"]
        )
        .with_cargo_package("feroxbuster")
    );

    catalog.insert("wfuzz".to_string(),
        ToolDefinition::new(
            "wfuzz",
            "Web application fuzzer",
            "web",
            vec!["wfuzz"]
        )
        .with_git_repo("https://github.com/xmendez/wfuzz.git")
    );

    // === Parameter Discovery & Fuzzing ===
    catalog.insert("arjun".to_string(),
        ToolDefinition::new(
            "arjun",
            "HTTP parameter discovery tool",
            "web",
            vec!["arjun", "arjun.exe"]
        )
        .with_git_repo("https://github.com/s0md3v/Arjun.git")
    );

    catalog.insert("param-miner".to_string(),
        ToolDefinition::new(
            "param-miner",
            "Parameter mining tool",
            "web",
            vec!["param-miner"]
        )
        .with_install_method("manual")
    );

    // === SQL Injection ===
    catalog.insert("sqlmap".to_string(),
        ToolDefinition::new(
            "sqlmap",
            "Automatic SQL injection tool",
            "web",
            vec!["sqlmap"]
        )
        .with_git_repo("https://github.com/sqlmapproject/sqlmap.git")
    );

    // === XSS Detection ===
    catalog.insert("dalfox".to_string(),
        ToolDefinition::new(
            "dalfox",
            "Fast XSS scanner",
            "web",
            vec!["dalfox"]
        )
        .with_go_module("github.com/hahwul/dalfox/v2")
    );

    catalog.insert("xsstrike".to_string(),
        ToolDefinition::new(
            "xsstrike",
            "XSS detection suite",
            "web",
            vec!["xsstrike"]
        )
        .with_git_repo("https://github.com/s0md3v/XSStrike.git")
    );

    // === Technology Detection ===
    catalog.insert("wappalyzer".to_string(),
        ToolDefinition::new(
            "wappalyzer",
            "Technology detection",
            "recon",
            vec!["wappalyzer"]
        )
        .with_npm_package("wappalyzer")
    );

    catalog.insert("whatweb".to_string(),
        ToolDefinition::new(
            "whatweb",
            "Web technology identification",
            "recon",
            vec!["whatweb"]
        )
        .with_os_dependencies(vec!["ruby"])
        .with_gem_package("whatweb")
        .with_apt_package("whatweb")
    );

    // === Screenshot & Visual Recon ===
    catalog.insert("gowitness".to_string(),
        ToolDefinition::new(
            "gowitness",
            "Web screenshot utility",
            "recon",
            vec!["gowitness"]
        )
        .with_go_module("github.com/sensepost/gowitness")
    );

    catalog.insert("aquatone".to_string(),
        ToolDefinition::new(
            "aquatone",
            "Domain flyover tool (DEPRECATED - upstream archived, Go 1.20+ incompatible)",
            "recon",
            vec!["aquatone"]
        )
        .with_install_method("manual")
        // Note: Original repo is archived and doesn't compile with modern Go
        // Binary releases or older forks may still work
    );

    catalog.insert("eyewitness".to_string(),
        ToolDefinition::new(
            "eyewitness",
            "Website screenshot tool",
            "recon",
            vec!["eyewitness"]
        )
        .with_git_repo("https://github.com/FortyNorthSecurity/EyeWitness.git")
    );

    // === JavaScript Analysis ===
    catalog.insert("linkfinder".to_string(),
        ToolDefinition::new(
            "linkfinder",
            "Find endpoints in JS files",
            "recon",
            vec!["linkfinder"]
        )
        .with_git_repo("https://github.com/GerbenJavado/LinkFinder.git")
    );

    catalog.insert("subjs".to_string(),
        ToolDefinition::new(
            "subjs",
            "Find JavaScript files",
            "recon",
            vec!["subjs"]
        )
        .with_go_module("github.com/lc/subjs")
    );

    // === SSRF & Testing ===
    catalog.insert("interactsh-client".to_string(),
        ToolDefinition::new(
            "interactsh-client",
            "OAST client",
            "testing",
            vec!["interactsh-client"]
        )
        .with_go_module("github.com/projectdiscovery/interactsh/cmd/interactsh-client")
    );

    // === Exploitation Frameworks ===
    catalog.insert("metasploit".to_string(),
        ToolDefinition::new(
            "metasploit",
            "Penetration testing framework",
            "exploitation",
            vec!["msfconsole"]
        )
        .with_apt_package("metasploit-framework")
        .with_install_method("manual")
    );

    catalog.insert("searchsploit".to_string(),
        ToolDefinition::new(
            "searchsploit",
            "Exploit database search",
            "exploitation",
            vec!["searchsploit"]
        )
        .with_apt_package("exploitdb")
        .with_install_method("manual")
    );

    // === Network Tools ===
    catalog.insert("netcat".to_string(),
        ToolDefinition::new(
            "netcat",
            "Network utility",
            "network",
            vec!["nc", "netcat"]
        )
        .with_version_args(vec!["-h"])
        .with_apt_package("netcat-openbsd")
        .with_winget_id("nmap.ncat")
    );

    catalog.insert("socat".to_string(),
        ToolDefinition::new(
            "socat",
            "Multipurpose relay",
            "network",
            vec!["socat"]
        )
        .with_version_args(vec!["-V"])
        .with_apt_package("socat")
        .with_install_method("manual")
    );

    // === Git Tools ===
    catalog.insert("git".to_string(),
        ToolDefinition::new(
            "git",
            "Version control system",
            "utility",
            vec!["git"]
        )
        .with_winget_id("Git.Git")
        .with_install_method("runtime")
    );

    catalog.insert("trufflehog".to_string(),
        ToolDefinition::new(
            "trufflehog",
            "Find secrets in git repos",
            "security",
            vec!["trufflehog"]
        )
        .with_go_module("github.com/trufflesecurity/trufflehog/v3")
    );

    catalog.insert("gitleaks".to_string(),
        ToolDefinition::new(
            "gitleaks",
            "Secret scanning tool",
            "security",
            vec!["gitleaks"]
        )
        .with_go_module("github.com/gitleaks/gitleaks/v8")
    );

    // === Cloud Security ===
    catalog.insert("s3scanner".to_string(),
        ToolDefinition::new(
            "s3scanner",
            "S3 bucket scanner",
            "cloud",
            vec!["s3scanner"]
        )
        .with_go_module("github.com/sa7mon/s3scanner")
    );

    catalog.insert("cloudfail".to_string(),
        ToolDefinition::new(
            "cloudfail",
            "Find origin servers behind CDN",
            "cloud",
            vec!["cloudfail"]
        )
        .with_git_repo("https://github.com/m0rtem/CloudFail.git")
    );

    // === Utilities ===
    catalog.insert("curl".to_string(),
        ToolDefinition::new(
            "curl",
            "Transfer data with URLs",
            "utility",
            vec!["curl"]
        )
        .with_install_method("runtime")
    );

    catalog.insert("wget".to_string(),
        ToolDefinition::new(
            "wget",
            "Network downloader",
            "utility",
            vec!["wget"]
        )
        .with_winget_id("GnuWin32.Wget")
        .with_install_method("runtime")
    );

    catalog.insert("jq".to_string(),
        ToolDefinition::new(
            "jq",
            "JSON processor",
            "utility",
            vec!["jq"]
        )
        .with_apt_package("jq")
        .with_winget_id("jqlang.jq")
    );

    catalog.insert("python".to_string(),
        ToolDefinition::new(
            "python",
            "Python interpreter",
            "utility",
            vec!["python", "python3"]
        )
        .with_version_args(vec!["--version"])
        .with_winget_id("Python.Python.3.12")
        .with_install_method("runtime")
    );

    catalog.insert("go".to_string(),
        ToolDefinition::new(
            "go",
            "Go programming language",
            "utility",
            vec!["go"]
        )
        .with_version_args(vec!["version"])
        .with_apt_package("golang-go")
        .with_winget_id("GoLang.Go")
        .with_install_method("runtime")
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
