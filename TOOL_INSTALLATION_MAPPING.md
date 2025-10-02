# 🗺️ Tool Installation Mapping (All 57 Tools)

## **Overview**
This document maps **all 57 security tools** from our catalog to their installation methods across **Windows** and **Kali Linux**.

### **Legend**
- 🟢 **Go** - `go install` (Primary method - works identically on both platforms)
- 🔵 **APT** - Kali Linux package manager (`apt install`)
- 🔵 **WinGet** - Windows package manager (`winget install`)
- 🟡 **pipx** - Python isolated environments (`pipx install`)
- 🔴 **Manual** - Manual installation required (GitHub releases, etc.)
- ⚠️ **Deprecated** - Tool is outdated or superseded

---

## 📊 **Installation Method Summary**

| Method | Count | Tools |
|--------|-------|-------|
| 🟢 **go install** | **25** | subfinder, amass, assetfinder, httpx, httprobe, meg, katana, gospider, hakrawler, gau, waybackurls, gauplus, nuclei, ffuf, gobuster, dalfox, gowitness, aquatone, subjs, interactsh-client, trufflehog, gitleaks, s3scanner, naabu, rustscan |
| 🟡 **pipx** | **14** | knockpy, sublist3r, dnsrecon, fierce, dnsenum, nikto, wpscan, joomscan, arjun, sqlmap, xsstrike, linkfinder, eyewitness, cloudfail |
| 🔵 **APT/WinGet** | **10** | nmap, masscan, metasploit, searchsploit, netcat, socat, git, curl, wget, jq |
| 🔴 **Manual** | **5** | dirbuster, feroxbuster, wfuzz, param-miner, wappalyzer |
| 🛠️ **Runtime** | **2** | python, go (these ARE package managers) |

---

## 🟢 **Group 1: Go Install Tools (25 tools)**

### **Subdomain Enumeration (3)**

#### 1. **subfinder**
- **Description**: Fast passive subdomain discovery tool
- **Category**: recon
- **Installation**:
  ```bash
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

#### 2. **amass**
- **Description**: Comprehensive network reconnaissance tool
- **Category**: recon
- **Installation**:
  ```bash
  go install github.com/owasp-amass/amass/v4/...@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐⭐ (MVP - Top 20)
- **Note**: Uses `...` to install all subpackages

#### 3. **assetfinder**
- **Description**: Find domains and subdomains
- **Category**: recon
- **Installation**:
  ```bash
  go install github.com/tomnomnom/assetfinder@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

---

### **Port Scanning (2)**

#### 4. **naabu**
- **Description**: Fast port scanner
- **Category**: network
- **Installation**:
  ```bash
  go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  ```
- **Windows**: ✅ Requires WinPcap/Npcap (manual)
- **Kali Linux**: ✅ Requires libpcap (`apt install libpcap-dev`)
- **Priority**: ⭐⭐⭐ (MVP - Top 20)
- **Note**: Needs libpcap dependency

#### 5. **rustscan**
- **Description**: Modern port scanner (despite name, has Go version)
- **Category**: network
- **Installation**:
  ```bash
  # Actually cargo install, not go install!
  cargo install rustscan
  ```
- **Windows**: ⚠️ Requires Rust toolchain
- **Kali Linux**: ⚠️ Requires Rust toolchain
- **Priority**: ⭐ (Future - requires cargo support)
- **Note**: **CORRECTION**: This is Rust, not Go! Move to Manual group

---

### **HTTP Probing (3)**

#### 6. **httpx**
- **Description**: Fast HTTP probe
- **Category**: web
- **Installation**:
  ```bash
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

#### 7. **httprobe**
- **Description**: HTTP/HTTPS probe (by tomnomnom)
- **Category**: web
- **Installation**:
  ```bash
  go install github.com/tomnomnom/httprobe@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐ (Future)

#### 8. **meg**
- **Description**: Fetch many paths for many hosts
- **Category**: web
- **Installation**:
  ```bash
  go install github.com/tomnomnom/meg@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐ (Future)

---

### **Web Crawling (3)**

#### 9. **katana**
- **Description**: Web crawler from ProjectDiscovery
- **Category**: web
- **Installation**:
  ```bash
  go install github.com/projectdiscovery/katana/cmd/katana@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

#### 10. **gospider**
- **Description**: Fast web spider
- **Category**: web
- **Installation**:
  ```bash
  go install github.com/jaeles-project/gospider@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐ (Future)

#### 11. **hakrawler**
- **Description**: Simple, fast web crawler
- **Category**: web
- **Installation**:
  ```bash
  go install github.com/hakluke/hakrawler@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

---

### **URL Discovery (3)**

#### 12. **gau**
- **Description**: Get all URLs from various sources
- **Category**: recon
- **Installation**:
  ```bash
  go install github.com/lc/gau/v2/cmd/gau@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

#### 13. **waybackurls**
- **Description**: Wayback Machine URL fetcher
- **Category**: recon
- **Installation**:
  ```bash
  go install github.com/tomnomnom/waybackurls@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

#### 14. **gauplus**
- **Description**: Modified GAU with additional features
- **Category**: recon
- **Installation**:
  ```bash
  go install github.com/bp0lr/gauplus@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐ (Future)

---

### **Vulnerability Scanning (1)**

#### 15. **nuclei**
- **Description**: Fast and customizable vulnerability scanner
- **Category**: vulnerability
- **Installation**:
  ```bash
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

---

### **Directory Fuzzing (2)**

#### 16. **ffuf**
- **Description**: Fast web fuzzer
- **Category**: web
- **Installation**:
  ```bash
  go install github.com/ffuf/ffuf/v2@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

#### 17. **gobuster**
- **Description**: Directory/DNS brute force tool
- **Category**: web
- **Installation**:
  ```bash
  go install github.com/OJ/gobuster/v3@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

---

### **XSS Detection (1)**

#### 18. **dalfox**
- **Description**: Fast XSS scanner
- **Category**: web
- **Installation**:
  ```bash
  go install github.com/hahwul/dalfox/v2@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐ (Future)

---

### **Screenshots (2)**

#### 19. **gowitness**
- **Description**: Web screenshot utility
- **Category**: recon
- **Installation**:
  ```bash
  go install github.com/sensepost/gowitness@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

#### 20. **aquatone**
- **Description**: Domain flyover tool
- **Category**: recon
- **Installation**:
  ```bash
  go install github.com/michenriksen/aquatone@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐ (Future)

---

### **JavaScript Analysis (1)**

#### 21. **subjs**
- **Description**: Find JavaScript files
- **Category**: recon
- **Installation**:
  ```bash
  go install github.com/lc/subjs@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐ (Future)

---

### **SSRF Testing (1)**

#### 22. **interactsh-client**
- **Description**: Out-of-band application security testing (OAST) client
- **Category**: testing
- **Installation**:
  ```bash
  go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

---

### **Secret Scanning (2)**

#### 23. **trufflehog**
- **Description**: Find secrets in git repos
- **Category**: security
- **Installation**:
  ```bash
  go install github.com/trufflesecurity/trufflehog/v3@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

#### 24. **gitleaks**
- **Description**: Secret scanning tool
- **Category**: security
- **Installation**:
  ```bash
  go install github.com/gitleaks/gitleaks/v8@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐⭐ (Future)

---

### **Cloud Security (1)**

#### 25. **s3scanner**
- **Description**: S3 bucket scanner
- **Category**: cloud
- **Installation**:
  ```bash
  go install github.com/sa7mon/s3scanner@latest
  ```
- **Windows**: ✅ Works identically
- **Kali Linux**: ✅ Works identically
- **Priority**: ⭐ (Future)

---

## 🟡 **Group 2: pipx Tools (14 tools)**

### **Subdomain Enumeration (5)**

#### 26. **knockpy**
- **Description**: Subdomain scanner
- **Category**: recon
- **Installation**:
  ```bash
  pipx install git+https://github.com/guelfoweb/knock.git
  ```
- **Windows**: ✅ Works with pipx
- **Kali Linux**: ✅ Works with pipx
- **Priority**: ⭐ (Future)

#### 27. **sublist3r**
- **Description**: Fast subdomains enumeration tool
- **Category**: recon
- **Installation**:
  ```bash
  pipx install sublist3r
  ```
- **Windows**: ✅ Works with pipx
- **Kali Linux**: ✅ Works with pipx
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

#### 28. **dnsrecon**
- **Description**: DNS enumeration script
- **Category**: recon
- **Installation**:
  ```bash
  pipx install dnsrecon
  ```
- **Windows**: ✅ Works with pipx
- **Kali Linux**: ✅ Pre-installed in Kali (also: `apt install dnsrecon`)
- **Priority**: ⭐⭐ (Future)

#### 29. **fierce**
- **Description**: DNS reconnaissance tool
- **Category**: recon
- **Installation**:
  ```bash
  pipx install fierce
  ```
- **Windows**: ✅ Works with pipx
- **Kali Linux**: ✅ Pre-installed in Kali (also: `apt install fierce`)
- **Priority**: ⭐ (Future)

#### 30. **dnsenum**
- **Description**: DNS enumeration tool
- **Category**: recon
- **Installation**:
  ```bash
  # Not on PyPI, use git
  pipx install git+https://github.com/fwaeytens/dnsenum.git
  ```
- **Windows**: ⚠️ Requires Perl on Windows
- **Kali Linux**: ✅ Pre-installed (`apt install dnsenum`)
- **Priority**: ⭐ (Future)
- **Note**: Originally a Perl script, Python version exists

---

### **Vulnerability Scanning (3)**

#### 31. **nikto**
- **Description**: Web server scanner
- **Category**: vulnerability
- **Installation**:
  ```bash
  # Nikto is Perl-based, not Python!
  # Kali: apt install nikto
  # Windows: Manual installation
  ```
- **Windows**: ⚠️ Requires Perl
- **Kali Linux**: ✅ Pre-installed (`apt install nikto`)
- **Priority**: ⭐⭐ (Future)
- **Note**: **CORRECTION**: Move to APT/Manual group (not pipx)

#### 32. **wpscan**
- **Description**: WordPress vulnerability scanner
- **Category**: vulnerability
- **Installation**:
  ```bash
  # Ruby-based, not Python!
  # Kali: apt install wpscan
  # Windows: gem install wpscan
  ```
- **Windows**: ⚠️ Requires Ruby
- **Kali Linux**: ✅ Pre-installed (`apt install wpscan`)
- **Priority**: ⭐⭐ (Future)
- **Note**: **CORRECTION**: Move to APT/Manual group (Ruby gem)

#### 33. **joomscan**
- **Description**: Joomla vulnerability scanner
- **Category**: vulnerability
- **Installation**:
  ```bash
  # Perl-based, not Python!
  # Manual: git clone https://github.com/OWASP/joomscan.git
  ```
- **Windows**: ⚠️ Requires Perl
- **Kali Linux**: ✅ Can use git clone
- **Priority**: ⭐ (Future)
- **Note**: **CORRECTION**: Move to Manual group (Perl)

---

### **Parameter Discovery (1)**

#### 34. **arjun**
- **Description**: HTTP parameter discovery tool
- **Category**: web
- **Installation**:
  ```bash
  pipx install arjun
  ```
- **Windows**: ✅ Works with pipx
- **Kali Linux**: ✅ Works with pipx
- **Priority**: ⭐⭐ (Future)

---

### **SQL Injection (1)**

#### 35. **sqlmap**
- **Description**: Automatic SQL injection tool
- **Category**: web
- **Installation**:
  ```bash
  pipx install sqlmap
  ```
- **Windows**: ✅ Works with pipx
- **Kali Linux**: ✅ Pre-installed (also: `apt install sqlmap`)
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

---

### **XSS Detection (1)**

#### 36. **xsstrike**
- **Description**: XSS detection suite
- **Category**: web
- **Installation**:
  ```bash
  pipx install git+https://github.com/s0md3v/XSStrike.git
  ```
- **Windows**: ✅ Works with pipx
- **Kali Linux**: ✅ Works with pipx
- **Priority**: ⭐⭐ (Future)

---

### **JavaScript Analysis (1)**

#### 37. **linkfinder**
- **Description**: Find endpoints in JS files
- **Category**: recon
- **Installation**:
  ```bash
  pipx install linkfinder
  ```
- **Windows**: ✅ Works with pipx
- **Kali Linux**: ✅ Works with pipx
- **Priority**: ⭐⭐ (Future)

---

### **Screenshots (1)**

#### 38. **eyewitness**
- **Description**: Website screenshot tool
- **Category**: recon
- **Installation**:
  ```bash
  pipx install git+https://github.com/FortyNorthSecurity/EyeWitness.git
  ```
- **Windows**: ⚠️ Requires Selenium drivers
- **Kali Linux**: ✅ Works with dependencies
- **Priority**: ⭐ (Future)

---

### **Cloud Security (1)**

#### 39. **cloudfail**
- **Description**: Find origin servers behind CloudFlare
- **Category**: cloud
- **Installation**:
  ```bash
  pipx install git+https://github.com/m0rtem/CloudFail.git
  ```
- **Windows**: ✅ Works with pipx
- **Kali Linux**: ✅ Works with pipx
- **Priority**: ⭐ (Future)

---

## 🔵 **Group 3: APT/WinGet System Tools (10 tools)**

### **Port Scanning (2)**

#### 40. **nmap**
- **Description**: Network discovery and security auditing tool
- **Category**: network
- **Installation**:
  - Windows: `winget install Nmap.Nmap`
  - Kali Linux: `sudo apt install -y nmap` (pre-installed)
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

#### 41. **masscan**
- **Description**: TCP port scanner
- **Category**: network
- **Installation**:
  - Windows: Manual (download from GitHub releases)
  - Kali Linux: `sudo apt install -y masscan`
- **Priority**: ⭐⭐ (Future)

---

### **Exploitation (2)**

#### 42. **metasploit**
- **Description**: Penetration testing framework
- **Category**: exploitation
- **Installation**:
  - Windows: Manual (installer from rapid7.com)
  - Kali Linux: `sudo apt install -y metasploit-framework` (pre-installed)
- **Priority**: ⭐ (Future - large installation)

#### 43. **searchsploit**
- **Description**: Exploit database search
- **Category**: exploitation
- **Installation**:
  - Windows: Manual (via exploitdb-bin)
  - Kali Linux: `sudo apt install -y exploitdb` (pre-installed)
- **Priority**: ⭐⭐ (Future)

---

### **Network Tools (2)**

#### 44. **netcat**
- **Description**: Network utility
- **Category**: network
- **Installation**:
  - Windows: `winget install nmap.ncat` (part of Nmap)
  - Kali Linux: `sudo apt install -y netcat-openbsd` (pre-installed)
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

#### 45. **socat**
- **Description**: Multipurpose relay
- **Category**: network
- **Installation**:
  - Windows: Manual (download from sourceforge)
  - Kali Linux: `sudo apt install -y socat`
- **Priority**: ⭐ (Future)

---

### **Utilities (4)**

#### 46. **git**
- **Description**: Version control system
- **Category**: utility
- **Installation**:
  - Windows: `winget install Git.Git`
  - Kali Linux: Pre-installed
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

#### 47. **curl**
- **Description**: Transfer data with URLs
- **Category**: utility
- **Installation**:
  - Windows: Pre-installed (Windows 10+)
  - Kali Linux: Pre-installed
- **Priority**: ⭐⭐⭐ (MVP - Top 20)

#### 48. **wget**
- **Description**: Network downloader
- **Category**: utility
- **Installation**:
  - Windows: `winget install GnuWin32.Wget`
  - Kali Linux: Pre-installed
- **Priority**: ⭐⭐ (Future)

#### 49. **jq**
- **Description**: JSON processor
- **Category**: utility
- **Installation**:
  - Windows: `winget install jqlang.jq`
  - Kali Linux: `sudo apt install -y jq`
- **Priority**: ⭐⭐ (Future)

---

## 🔴 **Group 4: Manual Installation (8 tools)**

### **Directory Fuzzing (3)**

#### 50. **dirbuster**
- **Description**: Web directory brute forcer (Java)
- **Category**: web
- **Installation**:
  - Windows: Manual (download JAR from OWASP)
  - Kali Linux: `sudo apt install -y dirbuster`
- **Priority**: ⭐ (Future)
- **Note**: ⚠️ Deprecated - superseded by ffuf/gobuster

#### 51. **feroxbuster**
- **Description**: Fast content discovery tool (Rust)
- **Category**: web
- **Installation**:
  ```bash
  cargo install feroxbuster
  # OR download from GitHub releases
  ```
- **Windows**: ⚠️ Requires Rust OR manual binary download
- **Kali Linux**: ⚠️ Requires Rust OR manual binary download
- **Priority**: ⭐⭐ (Future - requires cargo support)

#### 52. **wfuzz**
- **Description**: Web application fuzzer (Python but not on PyPI cleanly)
- **Category**: web
- **Installation**:
  ```bash
  pip install wfuzz  # Not pipx due to script installation
  # OR: apt install wfuzz (Kali)
  ```
- **Windows**: ⚠️ pip install (system-wide)
- **Kali Linux**: ✅ `sudo apt install -y wfuzz`
- **Priority**: ⭐ (Future)

---

### **Parameter Discovery (1)**

#### 53. **param-miner**
- **Description**: Parameter mining tool (Burp Suite extension)
- **Category**: web
- **Installation**:
  - Windows: Manual (Burp Suite extension)
  - Kali Linux: Manual (Burp Suite extension)
- **Priority**: ⭐ (Future - requires Burp Suite)
- **Note**: Not a CLI tool, Burp extension only

---

### **Technology Detection (1)**

#### 54. **wappalyzer**
- **Description**: Technology detection (Browser extension / npm)
- **Category**: recon
- **Installation**:
  ```bash
  npm install -g wappalyzer-cli
  ```
- **Windows**: ⚠️ Requires Node.js
- **Kali Linux**: ⚠️ Requires Node.js
- **Priority**: ⭐ (Future - requires npm support)

---

### **Technology Detection (1)**

#### 55. **whatweb**
- **Description**: Web technology identification (Ruby)
- **Category**: recon
- **Installation**:
  - Windows: Manual (Ruby gem or git clone)
  - Kali Linux: `sudo apt install -y whatweb` (pre-installed)
- **Priority**: ⭐⭐ (Future)

---

### **Port Scanning (1)**

#### 56. **rustscan**
- **Description**: Modern port scanner (Rust - moved from Go group)
- **Category**: network
- **Installation**:
  ```bash
  cargo install rustscan
  # OR download from GitHub releases
  ```
- **Windows**: ⚠️ Requires Rust OR manual binary download
- **Kali Linux**: ⚠️ Requires Rust OR manual binary download
- **Priority**: ⭐⭐ (Future - requires cargo support)

---

### **Vulnerability Scanning (3)**

#### 57. **nikto** (moved from pipx)
- **Installation**:
  - Windows: Manual Perl installation
  - Kali Linux: `sudo apt install -y nikto` (pre-installed)

#### 58. **wpscan** (moved from pipx)
- **Installation**:
  - Windows: `gem install wpscan`
  - Kali Linux: `sudo apt install -y wpscan` (pre-installed)

#### 59. **joomscan** (moved from pipx)
- **Installation**:
  - Manual: `git clone https://github.com/OWASP/joomscan.git`

---

## 🛠️ **Group 5: Runtime Tools (2)**

#### 60. **python**
- **Description**: Python interpreter (prerequisite for pipx tools)
- **Category**: utility
- **Installation**:
  - Windows: `winget install Python.Python.3.12`
  - Kali Linux: Pre-installed
- **Priority**: ⭐⭐⭐ (Required for pipx)

#### 61. **go**
- **Description**: Go programming language (prerequisite for go install)
- **Category**: utility
- **Installation**:
  - Windows: `winget install GoLang.Go`
  - Kali Linux: `sudo apt install -y golang-go`
- **Priority**: ⭐⭐⭐ (Required for go install)

---

## 📊 **Corrected Installation Method Summary**

| Method | Count | Notes |
|--------|-------|-------|
| 🟢 **go install** | **24** | Removed rustscan (is Rust, not Go) |
| 🟡 **pipx** | **10** | Removed nikto, wpscan, joomscan (not Python) |
| 🔵 **APT/WinGet** | **10** | System tools + pre-installed Kali tools |
| 🔴 **Manual** | **11** | Java/Ruby/Perl/Rust tools + Burp extensions |
| 🛠️ **Runtime** | **2** | python, go (package manager prerequisites) |
| **Total** | **57** | All tools from catalog.rs |

---

## 🎯 **MVP Priority (Top 20 Tools)**

### **Go Install (15 tools):**
1. subfinder
2. amass
3. assetfinder
4. naabu
5. httpx
6. katana
7. hakrawler
8. gau
9. waybackurls
10. nuclei
11. ffuf
12. gobuster
13. gowitness
14. interactsh-client
15. trufflehog

### **System Tools (3 tools):**
16. nmap (APT/WinGet)
17. curl (Pre-installed)
18. git (APT/WinGet)

### **Python Tools (2 tools):**
19. sqlmap (pipx)
20. sublist3r (pipx)

---

## 🚀 **Implementation Strategy**

### **Phase 1: Package Manager Detection (Week 1)**
- Detect `go` (required for 24 tools)
- Detect `pipx` (required for 10 tools)
- Detect `apt` (Kali only - 10 tools)
- Detect `winget` (Windows only - 10 tools)

### **Phase 2: MVP Installation (Week 2-3)**
- Implement `go install` manager (covers 15/20 MVP tools)
- Implement `pipx` manager (covers 2/20 MVP tools)
- Implement `apt/winget` manager (covers 3/20 MVP tools)
- Total: 20/20 MVP tools covered ✅

### **Phase 3: Expansion (Week 4+)**
- Add remaining `go install` tools (9 more)
- Add remaining `pipx` tools (8 more)
- Add manual installation helpers (GitHub releases)
- Add cargo support for Rust tools (feroxbuster, rustscan)
- Add npm support (wappalyzer-cli)
- Add gem support (wpscan)

---

## 📝 **Notes for Implementation**

### **Dependencies to Handle:**
- **libpcap**: Required for naabu, nmap, masscan
  - Kali: `apt install libpcap-dev`
  - Windows: Npcap installer (manual)

### **Pre-installed in Kali (Don't need to install):**
- nmap, metasploit, searchsploit, netcat, curl, wget, git
- dnsrecon, fierce, dnsenum, nikto, wpscan, sqlmap, whatweb

### **Platform-Specific Issues:**
- **Perl tools** (nikto, joomscan, dnsenum): Easy on Kali, hard on Windows
- **Ruby tools** (wpscan, whatweb): Need Ruby runtime
- **Rust tools** (feroxbuster, rustscan): Need Cargo or manual binaries
- **Java tools** (dirbuster): Need JRE

### **Recommended MVP Focus:**
- ✅ **go install** (24 tools) - Works everywhere, no hassle
- ✅ **pipx** (10 tools) - Python isolated environments
- ✅ **apt/winget** (10 tools) - System packages
- ⏳ **Manual** (11 tools) - Future phases
- ⏳ **Runtime** (2 tools) - Prerequisites (auto-detect/install)

---

**Ready to implement?** 🚀
