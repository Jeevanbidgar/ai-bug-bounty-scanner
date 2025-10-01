# 🎯 Workflow Library - Ready-Made Security Testing Templates

## Overview

This document describes all available workflow templates in the AI Bug Bounty Scanner. These templates are inspired by industry-standard tools and frameworks including:

- **ProjectDiscovery Nuclei** - Official workflow patterns and templates
- **Osmedeus** - Community-tested offensive recon routines
- **Bug Bounty Community** - Best practices from BigBountyRecon, Reconned, and other frameworks

---

## 📚 Available Workflows

### Total Workflows: **10**

#### **By Category:**

- 🔍 **Reconnaissance**: 5 workflows
- 🛡️ **Vulnerability**: 4 workflows
- 📋 **Audit**: 1 workflow

---

## 🔍 Reconnaissance Workflows

### 1. **Discovery Only** (`discovery-only.yaml`)

**Category**: Reconnaissance  
**Focus**: Basic subdomain and port discovery  
**Duration**: ~10-15 minutes

#### Steps:

1. **Subfinder** - Subdomain Discovery
2. **Naabu** - Port Scanning

#### Outputs:

- `subdomains.txt` - List of discovered subdomains
- `ports.txt` - Open ports on targets

#### Use Cases:

- Initial reconnaissance
- Quick asset discovery
- Scope validation

---

### 2. **Full Reconnaissance** (`full-recon.yaml`)

**Category**: Reconnaissance  
**Focus**: Complete recon pipeline with vulnerability scanning  
**Duration**: ~30-45 minutes

#### Steps:

1. **Subfinder** - Subdomain Discovery
2. **Naabu** - Port Scanning
3. **httpx** - URL Probing & HTTP Service Discovery
4. **Nuclei** - Vulnerability Scanning

#### Outputs:

- `subdomains.txt` - Discovered subdomains
- `ports.txt` - Open ports
- `urls.txt` - Live HTTP/HTTPS URLs
- `nuclei.jsonl` - Vulnerabilities (JSONL format)
- `nuclei-export.json` - Full Nuclei export

#### Use Cases:

- Comprehensive reconnaissance
- Bug bounty initial scans
- Security assessments

---

### 3. **Quick Bug Bounty Recon** (`quick-bug-bounty.yaml`)

**Category**: Reconnaissance  
**Focus**: Fast bug bounty reconnaissance optimized for speed  
**Duration**: ~15-20 minutes

#### Steps:

1. **Subfinder** - Fast Subdomain Discovery
2. **Naabu** - Quick Port Scan (Top 100 ports)
3. **httpx** - Live Host Detection
4. **Nuclei** - Critical Vulnerability Detection (Critical/High only)
5. **Nuclei** - Quick Wins Detection (Low-hanging fruit)

#### Outputs:

- `subdomains.txt` - Discovered subdomains
- `ports.txt` - Open ports
- `live-urls.txt` - Live web services
- `nuclei-critical.jsonl` - Critical/high severity vulnerabilities
- `nuclei-quick-wins.jsonl` - Easy-to-exploit findings

#### Use Cases:

- Time-sensitive bug bounty hunting
- Quick initial assessment
- Low-hanging fruit detection

#### Special Features:

- Optimized for speed with rate limiting
- Focuses on critical issues only
- Tags: `cve`, `exposure`, `misconfig`, `rce`, `sqli`, `xss`, `default-login`, `panel`

---

### 4. **Network Reconnaissance** (`network-recon.yaml`)

**Category**: Reconnaissance  
**Focus**: Network infrastructure discovery and service enumeration  
**Duration**: ~45-60 minutes

#### Steps:

1. **Naabu** - Fast Port Discovery (Top 1000 ports)
2. **Nmap** - Service Version Detection with NSE scripts
3. **httpx** - HTTP Service Discovery
4. **Nuclei** - Network Vulnerability Scanning
5. **Nuclei** - SSL/TLS Security Testing

#### Outputs:

- `ports.txt` - Open ports
- `nmap-scan.xml` - Nmap results (XML)
- `nmap-scan.txt` - Nmap results (text)
- `http-services.txt` - HTTP/HTTPS services
- `nuclei-network.jsonl` - Network vulnerabilities
- `nuclei-ssl.jsonl` - SSL/TLS issues

#### Use Cases:

- Network infrastructure assessment
- Service enumeration
- SSL/TLS configuration review

#### Tags Used:

- `network`, `exposed`, `misconfiguration`, `default-login`, `ssl`, `tls`, `certificate`

---

### 5. **Subdomain Takeover Detection** (`subdomain-takeover.yaml`)

**Category**: Vulnerability (Recon-focused)  
**Focus**: Finding subdomain takeover vulnerabilities  
**Duration**: ~25-30 minutes

#### Steps:

1. **Subfinder** - Passive Subdomain Enumeration (Recursive)
2. **Amass** - Active Subdomain Discovery
3. **httpx** - HTTP Probing with CNAME Detection
4. **Nuclei** - Takeover Vulnerability Detection
5. **Nuclei** - DNS Security Testing

#### Outputs:

- `subdomains.txt` - All discovered subdomains
- `amass-subdomains.txt` - Amass results
- `live-subdomains.txt` - Live subdomains with CNAME data
- `nuclei-takeover.jsonl` - Takeover vulnerabilities
- `nuclei-dns.jsonl` - DNS security issues

#### Use Cases:

- Subdomain takeover hunting
- DNS misconfiguration detection
- Bug bounty high-impact findings

#### Tags Used:

- `takeover`, `dns`, `cname`, `dnssec`, `zone-transfer`

---

## 🛡️ Vulnerability Scanning Workflows

### 6. **Nuclei Only** (`nuclei-only.yaml`)

**Category**: Vulnerability  
**Focus**: Direct vulnerability scanning on provided targets  
**Duration**: ~20-30 minutes

#### Steps:

1. **Nuclei** - Vulnerability Scanning on target domains

#### Outputs:

- `nuclei.jsonl` - Vulnerabilities in JSONL format
- `nuclei-export.json` - Full JSON export

#### Use Cases:

- Scanning known targets
- Re-scanning after remediation
- Targeted vulnerability assessment

---

### 7. **Web Application Security Scan** (`web-application-scan.yaml`)

**Category**: Vulnerability  
**Focus**: Comprehensive web application security testing  
**Duration**: ~50-70 minutes

#### Steps:

1. **Subfinder** - Subdomain Enumeration
2. **httpx** - HTTP Service Discovery
3. **ffuf** - Directory Fuzzing
4. **Nuclei** - Technology Detection
5. **Nuclei** - Vulnerability Scanning (Critical/High/Medium)

#### Outputs:

- `subdomains.txt` - Discovered subdomains
- `live-urls.txt` - Live web services
- `ffuf-results.json` - Discovered directories/files
- `nuclei-tech.jsonl` - Detected technologies
- `nuclei-vulns.jsonl` - Vulnerabilities

#### Use Cases:

- Web application penetration testing
- Directory brute forcing
- Technology fingerprinting
- Comprehensive web vulnerability assessment

#### Tools Used:

- **ffuf** - Fast web fuzzer for directory discovery
- **Nuclei** - Technology detection and vulnerability scanning

---

### 8. **API Security Testing** (`api-security-scan.yaml`)

**Category**: Vulnerability  
**Focus**: API-specific vulnerability detection  
**Duration**: ~60-80 minutes

#### Steps:

1. **Katana** - API Endpoint Crawling
2. **httpx** - API Service Analysis
3. **Nuclei** - API Vulnerability Detection (OWASP API Top 10)
4. **sqlmap** - SQL Injection Testing
5. **Nuclei** - Authentication Testing

#### Outputs:

- `api-endpoints.txt` - Discovered API endpoints
- `live-api-endpoints.txt` - Live API endpoints with metadata
- `nuclei-api-vulns.jsonl` - API vulnerabilities
- `sqlmap/` - SQL injection results
- `nuclei-auth.jsonl` - Auth/authorization issues

#### Use Cases:

- API penetration testing
- OWASP API Top 10 assessment
- Authentication/authorization testing
- SQL injection detection

#### Tags Used:

- `api`, `owasp`, `auth`, `jwt`, `graphql`, `authentication`, `authorization`, `oauth`

#### Tools Used:

- **Katana** - Web crawler for endpoint discovery
- **httpx** - HTTP probing with tech detection
- **Nuclei** - API-specific vulnerability scanning
- **sqlmap** - Automated SQL injection testing

---

### 9. **Cloud Security Assessment** (`cloud-security-scan.yaml`)

**Category**: Vulnerability  
**Focus**: Cloud service misconfigurations and exposed resources  
**Duration**: ~40-50 minutes

#### Steps:

1. **Subfinder** - Subdomain Enumeration
2. **httpx** - Cloud Service Discovery
3. **Nuclei** - Cloud Storage Detection (S3, Azure Blob, GCS)
4. **Nuclei** - Cloud Service Misconfiguration Detection
5. **Nuclei** - Container Security Testing
6. **Nuclei** - Cloud Metadata Testing

#### Outputs:

- `subdomains.txt` - Discovered subdomains
- `live-urls.txt` - Live cloud services
- `nuclei-storage.jsonl` - Cloud storage issues
- `nuclei-cloud.jsonl` - Cloud misconfigurations
- `nuclei-containers.jsonl` - Container security issues
- `nuclei-metadata.jsonl` - Metadata exposure

#### Use Cases:

- Cloud infrastructure assessment
- S3/Azure/GCS bucket security testing
- Container/Kubernetes security
- Cloud metadata exposure detection

#### Tags Used:

- `s3`, `aws`, `azure`, `gcp`, `bucket`, `storage`, `blob`, `cloud`, `kubernetes`, `docker`, `k8s`, `container`, `orchestration`, `metadata`, `aws-metadata`, `azure-metadata`, `gcp-metadata`

---

## 📋 Audit Workflows

### 10. **Comprehensive Security Audit** (`comprehensive-audit.yaml`)

**Category**: Audit  
**Focus**: Complete end-to-end security assessment  
**Duration**: ~120-180 minutes (2-3 hours)

#### Phases:

**Phase 1: Reconnaissance**

- Subfinder (Comprehensive subdomain enumeration)
- Amass (Advanced subdomain discovery)

**Phase 2: Port & Service Discovery**

- Naabu (Full port scan - all ports)
- Nmap (Detailed service version detection with NSE scripts)

**Phase 3: HTTP Service Analysis**

- httpx (Comprehensive HTTP/HTTPS analysis)

**Phase 4: Content Discovery**

- Katana (Web crawling)
- ffuf (Directory fuzzing with recursion)

**Phase 5: Vulnerability Scanning**

- Nuclei (All templates, all severities)

**Phase 6: Specialized Scans**

- Nuclei CVE detection
- Nuclei subdomain takeover check
- sqlmap SQL injection testing

#### Outputs:

- `subdomains.txt` - All discovered subdomains
- `amass-subdomains.txt` - Amass results
- `ports.txt` - All open ports
- `nmap-detailed.xml` - Detailed service information
- `live-urls.txt` - Live web services
- `crawled-urls.txt` - Crawled endpoints
- `ffuf-results.json` - Hidden directories/files
- `nuclei-all-vulns.jsonl` - All vulnerabilities
- `nuclei-cves.jsonl` - CVE detections
- `nuclei-takeover.jsonl` - Takeover vulnerabilities
- `sqlmap/` - SQL injection results

#### Use Cases:

- Complete security audit
- Penetration testing engagement
- Compliance assessments
- Deep security analysis

#### Tools Used:

All available tools for maximum coverage

---

## 🛠️ Tools Used Across Workflows

### Reconnaissance Tools:

- **Subfinder** - Passive subdomain enumeration
- **Amass** - Active subdomain discovery
- **Naabu** - Fast port scanner
- **Nmap** - Service version detection and NSE scripts

### Web Analysis Tools:

- **httpx** - HTTP probing and service analysis
- **Katana** - Web crawler for endpoint discovery
- **ffuf** - Fast web fuzzer

### Vulnerability Scanning:

- **Nuclei** - Template-based vulnerability scanner
- **sqlmap** - Automated SQL injection testing

---

## 📊 Workflow Selection Guide

### **By Time Available:**

- **5-15 minutes**: Discovery Only
- **15-20 minutes**: Quick Bug Bounty Recon
- **20-30 minutes**: Nuclei Only, Subdomain Takeover Detection
- **30-45 minutes**: Full Reconnaissance
- **40-50 minutes**: Cloud Security Assessment
- **45-60 minutes**: Network Reconnaissance
- **50-70 minutes**: Web Application Security Scan
- **60-80 minutes**: API Security Testing
- **2-3 hours**: Comprehensive Security Audit

### **By Goal:**

| Goal                       | Recommended Workflow          |
| -------------------------- | ----------------------------- |
| Quick asset discovery      | Discovery Only                |
| Fast bug bounty scan       | Quick Bug Bounty Recon        |
| Complete recon             | Full Reconnaissance           |
| Network security           | Network Reconnaissance        |
| Subdomain takeover hunting | Subdomain Takeover Detection  |
| Web app testing            | Web Application Security Scan |
| API testing                | API Security Testing          |
| Cloud security             | Cloud Security Assessment     |
| Re-scan known targets      | Nuclei Only                   |
| Complete audit             | Comprehensive Security Audit  |

### **By Target Type:**

| Target Type            | Recommended Workflow                               |
| ---------------------- | -------------------------------------------------- |
| Domain/Website         | Full Reconnaissance, Web Application Security Scan |
| API endpoints          | API Security Testing                               |
| Network infrastructure | Network Reconnaissance                             |
| Cloud services         | Cloud Security Assessment                          |
| Subdomains             | Subdomain Takeover Detection                       |
| Mixed/Unknown          | Comprehensive Security Audit                       |

---

## 🎨 Workflow Features

### All Workflows Include:

✅ **YAML-based templates** - Easy to read and modify  
✅ **DAG execution** - Steps run in optimal order with dependencies  
✅ **Real-time logging** - Live stdout/stderr streaming  
✅ **Timeout protection** - Per-step timeouts to prevent hangs  
✅ **Structured outputs** - JSONL and JSON formats for parsing  
✅ **Variable interpolation** - Dynamic target and workdir substitution  
✅ **Security-first** - No shell execution, argv arrays only

### Nuclei Integration:

🎯 **JSONL Output** - Machine-readable findings (`-jsonl`)  
📦 **JSON Export** - Full export data (`-je`)  
🏷️ **Tag Filtering** - Targeted scans by vulnerability type  
⚡ **Rate Limiting** - Controlled request rates  
📊 **Statistics** - Real-time scan progress

---

## 🚀 Using Workflows

### From Dashboard:

1. Select workflow from dropdown
2. Enter target domain/IP
3. Click "Execute Workflow"
4. View real-time progress in Scans tab

### Input Variables:

- `target` - Domain, URL, IP, or CIDR range
- `workdir` - Output directory (auto-generated if not specified)

### Output Locations:

All artifacts are saved to: `{{workdir}}/` with descriptive filenames

---

## 📚 Template Sources & Inspiration

### ProjectDiscovery Resources:

- [Nuclei Documentation](https://docs.projectdiscovery.io/tools/nuclei/)
- [Nuclei Templates Repository](https://github.com/projectdiscovery/nuclei-templates)
- [Nuclei Workflow Examples](https://docs.projectdiscovery.io/templates/workflows)

### Osmedeus Resources:

- [Osmedeus Workflow Engine](https://github.com/j3ssie/osmedeus)
- [Osmedeus Workflows Repository](https://github.com/osmedeus/osmedeus-workflow)

### Community Resources:

- [BigBountyRecon](https://github.com/Viralmaniar/BigBountyRecon)
- [Reconned](https://github.com/3ndG4me/Reconned)
- [Awesome Bug Bounty](https://github.com/djadmin/awesome-bug-bounty)

---

## 🔐 Security Considerations

### Tool Allowlist:

All tools are explicitly allowed in `src-tauri/tauri.conf.json`:

- subfinder, naabu, nuclei, nmap, sqlmap, httpx, amass, katana, ffuf, gobuster, etc.

### Execution Safety:

- ✅ No shell execution
- ✅ Argv arrays only
- ✅ Input validation
- ✅ Timeout enforcement
- ✅ Process isolation

### Output Validation:

- ✅ JSONL parsing with error handling
- ✅ File size limits
- ✅ Path traversal prevention

---

## 📈 Future Enhancements

### Planned Additions:

- [ ] Custom workflow builder UI
- [ ] Workflow chaining and scheduling
- [ ] Report generation per workflow
- [ ] CI/CD integration templates
- [ ] Cloud provider-specific workflows
- [ ] Mobile application testing workflows
- [ ] IoT/embedded device workflows

### Community Contributions:

We welcome workflow contributions! Submit your custom workflows via pull requests.

---

## 🎓 Learning Resources

### Nuclei Tutorials:

- [Creating Nuclei Templates](https://docs.projectdiscovery.io/templates/introduction)
- [Nuclei GitHub Actions](https://github.com/projectdiscovery/nuclei-action)
- [Nuclei Best Practices](https://docs.projectdiscovery.io/templates/reference/best-practices)

### Osmedeus Guides:

- [Osmedeus Documentation](https://docs.osmedeus.org/)
- [Writing Osmedeus Modules](https://docs.osmedeus.org/modules/)

### Bug Bounty Resources:

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackerOne Disclosure Timeline](https://www.hackerone.com/disclosure-guidelines)
- [Bug Bounty Hunting Methodology](https://github.com/KathanP19/HowToHunt)

---

**Last Updated**: October 1, 2025  
**Total Workflows**: 10  
**Total Tools Integrated**: 14+  
**Supported Platforms**: Windows, Linux, macOS

---

## 📞 Support

For issues, questions, or workflow requests:

- Check the documentation in `/docs`
- Review `DESKTOP_NATIVE_ARCHITECTURE.md` for technical details
- See `COMPLETE_FEATURE_IMPLEMENTATION_PLAN.md` for roadmap

**Ready to start scanning!** 🚀🔒
