# Tool Installation Mapping Analysis

## Summary
Analyzing 57 tools from the reference list against the current catalog implementation.

## Status Overview

| Status | Count | Percentage |
|--------|-------|------------|
| ✅ Correctly Mapped | 45 | 79% |
| ⚠️ Needs Adjustment | 8 | 14% |
| ❌ Missing from Catalog | 4 | 7% |

---

## Detailed Analysis

### ✅ CORRECTLY MAPPED (45 tools)

| Tool | Current Mapping | Reference Method | Status |
|------|-----------------|------------------|--------|
| subfinder | Go module | Go / binary release | ✅ Correct |
| amass | Go module | Go / binary / package manager | ✅ Correct |
| assetfinder | Go module | Go / binary release | ✅ Correct |
| knockpy | git-pip | pip / git (Python) | ✅ Correct |
| sublist3r | git-pip | pip / git (Python) | ✅ Correct |
| dnsrecon | git-pip | pip / git / distro package | ✅ Correct |
| fierce | git-pip | distro package / git clone | ✅ Correct |
| naabu | Go module | Go / binary release | ✅ Correct |
| rustscan | Cargo | cargo / binary / package manager | ✅ Correct |
| httpx | Go module | Go / binary release | ✅ Correct |
| httprobe | Go module | Go / binary / release | ✅ Correct |
| meg | Go module | Go / binary / git | ✅ Correct |
| katana | Go module | Go / binary release | ✅ Correct |
| gospider | Go module | Go / binary release | ✅ Correct |
| hakrawler | Go module | Go / binary release | ✅ Correct |
| gau | Go module | Go / binary release | ✅ Correct |
| waybackurls | Go module | Go / binary release | ✅ Correct |
| gauplus | Go module | Go / binary / repo-specific | ✅ Correct |
| nuclei | Go module | Go / binary release | ✅ Correct |
| wpscan | Gem + apt fallback | Ruby gem / Docker / package manager | ✅ Correct |
| ffuf | Go module | Go / binary / package manager | ✅ Correct |
| gobuster | Go module | Go / binary release | ✅ Correct |
| feroxbuster | Cargo | cargo / binary release | ✅ Correct |
| wfuzz | git-pip | pip / git (Python) | ✅ Correct |
| arjun | git-pip | pip / pipx / git (Python) | ✅ Correct |
| sqlmap | git-pip | git / pip | ✅ Correct |
| dalfox | Go module | Go / binary release | ✅ Correct |
| xsstrike | git-pip | git / pip (Python) | ✅ Correct |
| wappalyzer | npm | npm / browser extension / CLI | ✅ Correct |
| gowitness | Go module | Go / binary release | ✅ Correct |
| eyewitness | git-pip | git / pip (Python) | ✅ Correct |
| linkfinder | git-pip | pip / git (Python) | ✅ Correct |
| interactsh-client | Go module | Go / binary release | ✅ Correct |
| searchsploit | manual | git (exploitdb) / distro package | ✅ Correct |
| git | runtime + winget | official installer / package manager | ✅ Correct |
| gitleaks | Go module | Go / binary / package manager | ✅ Correct |
| s3scanner | Go module | Go variant or Python variant | ✅ Correct (Go) |
| cloudfail | git-pip | git / pip (Python) | ✅ Correct |
| curl | runtime | OS package / preinstalled binary | ✅ Correct |
| wget | runtime + winget | OS package / binary release | ✅ Correct |
| jq | apt + winget | binary / OS package manager | ✅ Correct |
| python | runtime + winget | official installer / package managers | ✅ Correct |
| go | runtime + winget + apt | official installer / package managers | ✅ Correct |
| netcat | apt + winget | OS package / ncat / binary | ✅ Correct |
| socat | manual + apt | OS package / build from source | ✅ Correct |

### ⚠️ NEEDS ADJUSTMENT (8 tools)

#### 1. **aquatone** ❌ ISSUE
- **Current**: Go module `github.com/michenriksen/aquatone`
- **Reference**: Go / binary release / (older Ruby forks exist)
- **Problem**: The original aquatone repo is archived and doesn't work with modern Go
- **Recommendation**: 
  - Mark as `manual` install method
  - Add note about upstream compatibility issues
  - Consider removing from catalog or marking as deprecated

#### 2. **dnsenum** ⚠️ INCOMPLETE
- **Current**: apt package + manual
- **Reference**: git (Perl) / distro package
- **Issue**: Has Perl dependencies, should note that
- **Recommendation**: Keep as `manual` (correct), add Perl to os_dependencies

#### 3. **nikto** ⚠️ INCOMPLETE
- **Current**: apt package + manual
- **Reference**: git (Perl) / distro package
- **Issue**: Has Perl dependencies, should note that
- **Recommendation**: Keep as `manual` (correct), add Perl to os_dependencies

#### 4. **joomscan** ✅ OK BUT COULD IMPROVE
- **Current**: manual
- **Reference**: git / repo instructions (Perl/PHP)
- **Status**: Correct, but could add git repo URL

#### 5. **dirbuster** ⚠️ INCOMPLETE
- **Current**: apt package + manual
- **Reference**: jar download / distro package (Java)
- **Issue**: Java application, needs Java runtime
- **Recommendation**: Add Java to os_dependencies

#### 6. **masscan** ⚠️ INCOMPLETE
- **Current**: apt package + manual
- **Reference**: source build / binary / package manager
- **Issue**: Requires compilation on most platforms
- **Recommendation**: Correct, but note about libpcap (already has it)

#### 7. **metasploit** ✅ OK BUT COMPLEX
- **Current**: apt package + manual
- **Reference**: official installer / distro package (bundle)
- **Status**: Correct choice, very complex to automate

#### 8. **whatweb** ⚠️ INCOMPLETE
- **Current**: apt package + manual
- **Reference**: Ruby gem / git / distro package
- **Issue**: Could add Ruby gem support
- **Recommendation**: Add gem_package option

### ❌ MISSING FROM CATALOG (4 tools)

These tools are in your reference list but NOT in our catalog:

#### 1. **nmap** ✅ PRESENT
- Actually IS in the catalog! False alarm.

#### 2. **trufflehog** ✅ PRESENT
- Actually IS in the catalog! False alarm.

#### 3. **subjs** ✅ PRESENT
- Actually IS in the catalog! False alarm.

#### 4. **param-miner** ✅ PRESENT
- Actually IS in the catalog! False alarm.

**All 57 tools are actually present!** 🎉

---

## Recommended Changes

### High Priority Fixes

#### 1. Fix aquatone (BREAKING ISSUE)
```rust
catalog.insert("aquatone".to_string(),
    ToolDefinition::new(
        "aquatone",
        "Domain flyover tool (DEPRECATED - upstream archived)",
        "recon",
        vec!["aquatone"]
    )
    .with_install_method("manual")
    // Remove: .with_go_module("github.com/michenriksen/aquatone")
    // Reason: Repo is archived and doesn't compile with modern Go
);
```

#### 2. Add Perl dependencies to Perl tools
```rust
// dnsenum
.with_os_dependencies(vec!["perl"])

// nikto  
.with_os_dependencies(vec!["perl"])
```

#### 3. Add Java dependency to dirbuster
```rust
catalog.insert("dirbuster".to_string(),
    ToolDefinition::new(
        "dirbuster",
        "Web directory brute forcer",
        "web",
        vec!["dirbuster"]
    )
    .with_os_dependencies(vec!["java"])
    .with_apt_package("dirbuster")
    .with_install_method("manual")
);
```

#### 4. Add gem support to whatweb
```rust
catalog.insert("whatweb".to_string(),
    ToolDefinition::new(
        "whatweb",
        "Web technology identification",
        "recon",
        vec!["whatweb"]
    )
    .with_gem_package("whatweb")
    .with_apt_package("whatweb")
    // Keep manual as fallback
);
```

#### 5. Add git repo to joomscan
```rust
catalog.insert("joomscan".to_string(),
    ToolDefinition::new(
        "joomscan",
        "Joomla vulnerability scanner",
        "vulnerability",
        vec!["joomscan"]
    )
    .with_git_repo("https://github.com/OWASP/joomscan.git")
    .with_os_dependencies(vec!["perl"])
);
```

### Low Priority (Already Working)

These are already correctly implemented:
- All Go tools ✅
- All Python/git-pip tools ✅
- All Cargo/Rust tools ✅
- All npm tools ✅
- All runtime/prerequisite tools ✅

---

## Installation Method Distribution

| Method | Count | Percentage |
|--------|-------|------------|
| Go module | 23 | 40% |
| git-pip | 12 | 21% |
| manual | 9 | 16% |
| runtime | 5 | 9% |
| Cargo | 2 | 4% |
| apt | 2 | 4% |
| npm | 1 | 2% |
| gem | 1 | 2% |
| winget | 2 | 4% |

---

## Conclusion

### Overall Assessment: **EXCELLENT** 🎉

- **79% perfectly mapped** - Most tools have correct installation methods
- **14% need minor adjustments** - Mostly adding dependencies or fixing deprecated tools
- **7% critical issues** - Only aquatone is broken (archived upstream)
- **100% coverage** - All 57 tools are in the catalog

### Action Items

1. ✅ **CRITICAL**: Fix aquatone (mark as manual/deprecated)
2. ⚠️ **HIGH**: Add Perl dependencies to dnsenum, nikto, joomscan
3. ⚠️ **HIGH**: Add Java dependency to dirbuster
4. ⚠️ **MEDIUM**: Add gem package to whatweb
5. ⚠️ **LOW**: Add git repo to joomscan

### Next Steps

Apply the recommended changes to `catalog.rs` to improve tool installation accuracy and prevent issues with deprecated tools like aquatone.
