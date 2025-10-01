"""
Tool Registry - Comprehensive catalog of security tools with priorities and adapter difficulties

⚠️ DEPRECATED: This module is kept for reference only.
   All tool management now uses backend.tool_discovery.tool_discovery_service
   which provides:
   - Real-time tool discovery
   - Cross-platform PATH resolution
   - Version detection
   - OS dependency checking
   - Automatic caching

This registry contains all the tools mentioned by the user, organized by category
with their adapter implementation complexity and priority levels.
"""

from typing import Dict, List, Optional
from enum import Enum
from dataclasses import dataclass
from datetime import datetime

class ToolCategory(str, Enum):
    SUBDOMAIN_DNS = "subdomain_dns"
    URL_HISTORICAL = "url_historical"
    PORT_NETWORK = "port_network"
    WEB_VULN = "web_vuln"
    FUZZING = "fuzzing"
    INJECTION = "injection"
    SIGNATURE = "signature"
    TLS_WAF = "tls_waf"
    API_AUTH = "api_auth"
    HOST_AUDIT = "host_audit"
    METADATA = "metadata"
    REPORTING = "reporting"
    OSINT = "osint"
    ML_FP = "ml_fp"

class ToolPriority(str, Enum):
    MVP = "mvp"          # Must-have for Minimum Viable Product
    PHASE_2 = "phase_2"  # Nice-to-have for Phase 2
    OPTIONAL = "optional" # Optional enhancements
    MANUAL = "manual"     # Manual-only (too risky for automation)

class AdapterDifficulty(str, Enum):
    EASY = "easy"         # Simple wrapper, low complexity
    MEDIUM = "medium"     # Moderate complexity, some edge cases
    HARD = "hard"         # Complex integration, many edge cases
    VERY_HIGH_RISK = "very_high_risk"  # Too risky for automation

@dataclass
class ToolInfo:
    name: str
    description: str
    category: ToolCategory
    priority: ToolPriority
    adapter_difficulty: AdapterDifficulty
    passive_active: str  # "passive", "active", or "passive/active"
    requires_auth: bool = False
    api_keys_required: bool = False
    high_risk: bool = False
    notes: str = ""
    command_template: str = ""
    timeout: int = 300  # seconds
    container_image: Optional[str] = None

class ToolRegistry:
    """Registry of all available security tools"""

    def __init__(self):
        self.tools = self._build_tool_catalog()

    def _build_tool_catalog(self) -> Dict[str, ToolInfo]:
        """Build the comprehensive tool catalog"""

        tools = {}

        # Subdomain & DNS Discovery / OSINT
        tools['subfinder'] = ToolInfo(
            name='subfinder',
            description='Fast passive subdomain discovery',
            category=ToolCategory.SUBDOMAIN_DNS,
            priority=ToolPriority.MVP,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='passive',
            command_template='subfinder -d {target} -o {output_file}',
            timeout=600
        )

        tools['amass'] = ToolInfo(
            name='amass',
            description='DNS + active/passive enumeration (brute, API sources)',
            category=ToolCategory.SUBDOMAIN_DNS,
            priority=ToolPriority.MVP,
            adapter_difficulty=AdapterDifficulty.MEDIUM,
            passive_active='passive/active',
            command_template='amass enum -passive -d {target} -o {output_file}',
            timeout=1200
        )

        tools['assetfinder'] = ToolInfo(
            name='assetfinder',
            description='Additional domain discovery',
            category=ToolCategory.SUBDOMAIN_DNS,
            priority=ToolPriority.PHASE_2,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='passive',
            command_template='assetfinder --subs-only {target} > {output_file}',
            timeout=300
        )

        tools['crt.sh'] = ToolInfo(
            name='crt.sh',
            description='Certificate-based discovery',
            category=ToolCategory.SUBDOMAIN_DNS,
            priority=ToolPriority.PHASE_2,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='passive',
            command_template='curl -s "https://crt.sh/?q={target}&output=json" | jq -r \'.[] | .name_value\' > {output_file}',
            timeout=60
        )

        tools['theharvester'] = ToolInfo(
            name='theharvester',
            description='Email/OSINT collection',
            category=ToolCategory.OSINT,
            priority=ToolPriority.PHASE_2,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='passive',
            command_template='theHarvester -d {target} -l 500 -b all -f {output_file}',
            timeout=600
        )

        # URL / Historical Sources
        tools['waybackurls'] = ToolInfo(
            name='waybackurls',
            description='Archive URL harvesting',
            category=ToolCategory.URL_HISTORICAL,
            priority=ToolPriority.MVP,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='passive',
            command_template='waybackurls {target} > {output_file}',
            timeout=300
        )

        tools['gau'] = ToolInfo(
            name='gau',
            description='Aggregated URLs (Common Crawl)',
            category=ToolCategory.URL_HISTORICAL,
            priority=ToolPriority.MVP,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='passive',
            command_template='gau {target} --o {output_file}',
            timeout=600
        )

        tools['hakrawler'] = ToolInfo(
            name='hakrawler',
            description='Quick crawling for endpoints',
            category=ToolCategory.URL_HISTORICAL,
            priority=ToolPriority.PHASE_2,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='passive/light active',
            command_template='hakrawler -url {target} -depth 2 -scope subs -o {output_file}',
            timeout=300
        )

        # Port / Network Scanning
        tools['naabu'] = ToolInfo(
            name='naabu',
            description='Extremely fast port scanner',
            category=ToolCategory.PORT_NETWORK,
            priority=ToolPriority.MVP,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='active',
            command_template='naabu -host {target} -o {output_file}',
            timeout=600
        )

        tools['nmap'] = ToolInfo(
            name='nmap',
            description='Deep scanning + scripts',
            category=ToolCategory.PORT_NETWORK,
            priority=ToolPriority.MVP,
            adapter_difficulty=AdapterDifficulty.MEDIUM,
            passive_active='active',
            requires_auth=True,
            command_template='nmap -sV -sC -O -p- {target} -oN {output_file} -oX {xml_output_file}',
            timeout=1800
        )

        tools['masscan'] = ToolInfo(
            name='masscan',
            description='Very fast Internet-scale scanner (dangerous)',
            category=ToolCategory.PORT_NETWORK,
            priority=ToolPriority.OPTIONAL,
            adapter_difficulty=AdapterDifficulty.HARD,
            passive_active='active',
            high_risk=True,
            notes='Very high risk; do not automate',
            command_template='masscan -p1-65535 {target} --rate=1000 -oX {output_file}',
            timeout=600
        )

        # Web Application & Vulnerability Scanning
        tools['nuclei'] = ToolInfo(
            name='nuclei',
            description='Templates for CVEs & misconfigs',
            category=ToolCategory.WEB_VULN,
            priority=ToolPriority.MVP,
            adapter_difficulty=AdapterDifficulty.MEDIUM,
            passive_active='passive/active',
            command_template='nuclei -u {target} -o {output_file}',
            timeout=900
        )

        tools['owasp_zap'] = ToolInfo(
            name='owasp_zap',
            description='Spider + passive/active scanning + API',
            category=ToolCategory.WEB_VULN,
            priority=ToolPriority.PHASE_2,
            adapter_difficulty=AdapterDifficulty.MEDIUM,
            passive_active='active',
            command_template='zap.sh -cmd -autorun /zap/policies/api-scan.policy -t {target} -r {output_file}',
            timeout=1800,
            container_image='owasp/zap2docker-stable'
        )

        tools['nikto'] = ToolInfo(
            name='nikto',
            description='Web server scanner (noisy)',
            category=ToolCategory.WEB_VULN,
            priority=ToolPriority.OPTIONAL,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='active',
            command_template='nikto -h {target} -o {output_file}',
            timeout=600
        )

        tools['wpscan'] = ToolInfo(
            name='wpscan',
            description='WordPress enumeration',
            category=ToolCategory.WEB_VULN,
            priority=ToolPriority.OPTIONAL,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='active',
            command_template='wpscan --url {target} --enumerate vp,vt,tt,cb,dbe,u,m --format json --output {output_file}',
            timeout=900
        )

        # Fuzzing & Directory Brute Forcing
        tools['ffuf'] = ToolInfo(
            name='ffuf',
            description='Fast web fuzzer',
            category=ToolCategory.FUZZING,
            priority=ToolPriority.PHASE_2,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='active',
            command_template='ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -o {output_file}',
            timeout=900
        )

        tools['gobuster'] = ToolInfo(
            name='gobuster',
            description='Directory brute force',
            category=ToolCategory.FUZZING,
            priority=ToolPriority.PHASE_2,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='active',
            command_template='gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -o {output_file}',
            timeout=900
        )

        tools['wfuzz'] = ToolInfo(
            name='wfuzz',
            description='Flexible web fuzzing',
            category=ToolCategory.FUZZING,
            priority=ToolPriority.PHASE_2,
            adapter_difficulty=AdapterDifficulty.MEDIUM,
            passive_active='active',
            command_template='wfuzz -c -z file,wordlist/general/common.txt --hc 404 {target}/FUZZ',
            timeout=600
        )

        # Injection / Exploitation Tools (HIGH RISK)
        tools['sqlmap'] = ToolInfo(
            name='sqlmap',
            description='Automated SQLi discovery/exploitation',
            category=ToolCategory.INJECTION,
            priority=ToolPriority.PHASE_2,
            adapter_difficulty=AdapterDifficulty.MEDIUM,
            passive_active='active',
            high_risk=True,
            requires_auth=True,
            notes='Require strict gating — do not auto-run',
            command_template='sqlmap -u "{target}" --batch --output-dir={output_dir}',
            timeout=1800
        )

        # Signature & Template Engines
        tools['gitscanner'] = ToolInfo(
            name='gitscanner',
            description='Secret detection in repos',
            category=ToolCategory.SIGNATURE,
            priority=ToolPriority.PHASE_2,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='passive',
            command_template='gitscanner -r {target} > {output_file}',
            timeout=300
        )

        # TLS / WAF / Fingerprinting
        tools['testssl'] = ToolInfo(
            name='testssl',
            description='TLS scanning',
            category=ToolCategory.TLS_WAF,
            priority=ToolPriority.PHASE_2,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='passive/active',
            command_template='testssl.sh {target} > {output_file}',
            timeout=600
        )

        tools['wafw00f'] = ToolInfo(
            name='wafw00f',
            description='WAF detection',
            category=ToolCategory.TLS_WAF,
            priority=ToolPriority.PHASE_2,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='passive',
            command_template='wafw00f {target} > {output_file}',
            timeout=300
        )

        tools['sslyze'] = ToolInfo(
            name='sslyze',
            description='TLS analysis',
            category=ToolCategory.TLS_WAF,
            priority=ToolPriority.PHASE_2,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='passive',
            command_template='sslyze --regular {target} > {output_file}',
            timeout=300
        )

        # API / Auth Scanning
        tools['gptools'] = ToolInfo(
            name='gptools',
            description='Automated API fuzzers',
            category=ToolCategory.API_AUTH,
            priority=ToolPriority.PHASE_2,
            adapter_difficulty=AdapterDifficulty.MEDIUM,
            passive_active='active',
            command_template='gptools fuzz {target} -o {output_file}',
            timeout=900
        )

        # Host Auditing & Configuration
        tools['lynis'] = ToolInfo(
            name='lynis',
            description='Host security auditing',
            category=ToolCategory.HOST_AUDIT,
            priority=ToolPriority.OPTIONAL,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='active (local)',
            command_template='lynis audit system > {output_file}',
            timeout=600
        )

        # Metadata / Content Analysis
        tools['exiftool'] = ToolInfo(
            name='exiftool',
            description='Image metadata discovery',
            category=ToolCategory.METADATA,
            priority=ToolPriority.PHASE_2,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='passive',
            command_template='exiftool -r {target} > {output_file}',
            timeout=300
        )

        tools['file'] = ToolInfo(
            name='file',
            description='Artifact analysis',
            category=ToolCategory.METADATA,
            priority=ToolPriority.OPTIONAL,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='passive',
            command_template='file {target} > {output_file}',
            timeout=60
        )

        # Reporting / Processing / Enrichment
        tools['jq'] = ToolInfo(
            name='jq',
            description='Data munging',
            category=ToolCategory.REPORTING,
            priority=ToolPriority.MVP,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='passive',
            command_template='jq . {input_file} > {output_file}',
            timeout=60
        )

        # Mock adapter for testing
        tools['mock'] = ToolInfo(
            name='mock',
            description='Mock tool for unit tests',
            category=ToolCategory.REPORTING,
            priority=ToolPriority.MVP,
            adapter_difficulty=AdapterDifficulty.EASY,
            passive_active='passive',
            notes='Mock adapter for testing purposes',
            command_template='echo "Mock output" > {output_file}',
            timeout=10
        )

        return tools

    def get_tool(self, name: str) -> Optional[ToolInfo]:
        """Get tool information by name"""
        return self.tools.get(name)

    def get_tools_by_category(self, category: ToolCategory) -> List[ToolInfo]:
        """Get all tools in a category"""
        return [tool for tool in self.tools.values() if tool.category == category]

    def get_tools_by_priority(self, priority: ToolPriority) -> List[ToolInfo]:
        """Get all tools with a specific priority"""
        return [tool for tool in self.tools.values() if tool.priority == priority]

    def get_mvp_tools(self) -> List[ToolInfo]:
        """Get all MVP (Minimum Viable Product) tools"""
        return self.get_tools_by_priority(ToolPriority.MVP)

    def get_high_risk_tools(self) -> List[ToolInfo]:
        """Get all high-risk tools that require special handling"""
        return [tool for tool in self.tools.values() if tool.high_risk]

    def get_tools_requiring_auth(self) -> List[ToolInfo]:
        """Get all tools that require authentication/authorization"""
        return [tool for tool in self.tools.values() if tool.requires_auth]

    def list_categories(self) -> List[str]:
        """List all available categories"""
        categories = set()
        for tool in self.tools.values():
            categories.add(tool.category.value)
        return sorted(list(categories))

    def get_category_display_name(self, category: ToolCategory) -> str:
        """Get human-readable category name"""
        category_names = {
            ToolCategory.SUBDOMAIN_DNS: "Subdomain & DNS Discovery",
            ToolCategory.URL_HISTORICAL: "URL & Historical Sources",
            ToolCategory.PORT_NETWORK: "Port & Network Scanning",
            ToolCategory.WEB_VULN: "Web Vulnerability Scanning",
            ToolCategory.FUZZING: "Fuzzing & Directory Brute Forcing",
            ToolCategory.INJECTION: "Injection & Exploitation",
            ToolCategory.SIGNATURE: "Signature & Template Engines",
            ToolCategory.TLS_WAF: "TLS, WAF & Fingerprinting",
            ToolCategory.API_AUTH: "API & Authentication",
            ToolCategory.HOST_AUDIT: "Host Auditing",
            ToolCategory.METADATA: "Metadata & Content Analysis",
            ToolCategory.REPORTING: "Reporting & Processing",
            ToolCategory.OSINT: "OSINT & People Search",
            ToolCategory.ML_FP: "ML & False Positive Reduction"
        }
        return category_names.get(category, category.value)

    def export_catalog(self) -> Dict:
        """Export the entire catalog as a dictionary"""
        return {
            'metadata': {
                'exported_at': datetime.now().isoformat(),
                'total_tools': len(self.tools),
                'categories': len(self.list_categories()),
                'mvp_tools': len(self.get_mvp_tools())
            },
            'tools': {
                name: {
                    'name': tool.name,
                    'description': tool.description,
                    'category': tool.category.value,
                    'priority': tool.priority.value,
                    'adapter_difficulty': tool.adapter_difficulty.value,
                    'passive_active': tool.passive_active,
                    'requires_auth': tool.requires_auth,
                    'api_keys_required': tool.api_keys_required,
                    'high_risk': tool.high_risk,
                    'notes': tool.notes,
                    'command_template': tool.command_template,
                    'timeout': tool.timeout,
                    'container_image': tool.container_image
                }
                for name, tool in self.tools.items()
            }
        }
