#!/usr/bin/env python3
"""
Simple validation test for catalog.rs installation metadata
"""

import sys
from pathlib import Path

def test_catalog():
    """Quick validation of catalog.rs"""
    catalog_path = Path('src-tauri/src/tools/catalog.rs')
    
    if not catalog_path.exists():
        print(f"❌ ERROR: Catalog file not found: {catalog_path}")
        return 1
    
    print("🧪 Testing Catalog Installation Metadata")
    print("=" * 70)
    
    content = catalog_path.read_text(encoding='utf-8')
    
    # Count tools
    tool_count = content.count('catalog.insert(')
    print(f"\n✅ Found {tool_count} tool definitions in catalog")
    
    # Test 1: Check for new fields in struct
    print("\n📋 Test 1: Struct Fields")
    print("-" * 70)
    required_fields = [
        'pub go_module: Option<String>',
        'pub pipx_package: Option<String>',
        'pub apt_package: Option<String>',
        'pub winget_id: Option<String>',
        'pub install_method: String'
    ]
    
    for field in required_fields:
        if field in content:
            print(f"✅ {field}")
        else:
            print(f"❌ Missing: {field}")
            return 1
    
    # Test 2: Check for builder methods
    print("\n📋 Test 2: Builder Methods")
    print("-" * 70)
    builder_methods = [
        'pub fn with_go_module',
        'pub fn with_pipx_package',
        'pub fn with_apt_package',
        'pub fn with_winget_id',
        'pub fn with_install_method'
    ]
    
    for method in builder_methods:
        if method in content:
            print(f"✅ {method}")
        else:
            print(f"❌ Missing: {method}")
            return 1
    
    # Test 3: Count installation metadata usage
    print("\n📋 Test 3: Installation Metadata Usage")
    print("-" * 70)
    
    go_count = content.count('.with_go_module(')
    pipx_count = content.count('.with_pipx_package(')
    apt_count = content.count('.with_apt_package(')
    winget_count = content.count('.with_winget_id(')
    manual_count = content.count('.with_install_method("manual")')
    runtime_count = content.count('.with_install_method("runtime")')
    
    print(f"Go tools (with_go_module):           {go_count:2d} tools")
    print(f"Pipx tools (with_pipx_package):      {pipx_count:2d} tools")
    print(f"APT packages (with_apt_package):     {apt_count:2d} tools")
    print(f"WinGet IDs (with_winget_id):         {winget_count:2d} tools")
    print(f"Manual install:                      {manual_count:2d} tools")
    print(f"Runtime tools:                       {runtime_count:2d} tools")
    
    # Test 4: Check MVP tools
    print("\n📋 Test 4: MVP Tools (Top 20)")
    print("-" * 70)
    mvp_tools = [
        ('subfinder', 'github.com/projectdiscovery/subfinder'),
        ('nuclei', 'github.com/projectdiscovery/nuclei'),
        ('httpx', 'github.com/projectdiscovery/httpx'),
        ('ffuf', 'github.com/ffuf/ffuf'),
        ('gobuster', 'github.com/OJ/gobuster'),
        ('katana', 'github.com/projectdiscovery/katana'),
        ('hakrawler', 'github.com/hakluke/hakrawler'),
        ('gau', 'github.com/lc/gau'),
        ('waybackurls', 'github.com/tomnomnom/waybackurls'),
        ('gowitness', 'github.com/sensepost/gowitness'),
        ('trufflehog', 'github.com/trufflesecurity/trufflehog'),
        ('sqlmap', 'with_pipx_package("sqlmap")'),
        ('sublist3r', 'with_pipx_package("sublist3r")'),
        ('nmap', 'with_apt_package("nmap")'),
    ]
    
    missing = []
    for tool, pattern in mvp_tools:
        if pattern in content:
            print(f"✅ {tool:20s} - {pattern[:40]}")
        else:
            print(f"❌ {tool:20s} - Pattern not found: {pattern[:40]}")
            missing.append(tool)
    
    if missing:
        print(f"\n❌ {len(missing)} MVP tools missing installation metadata")
        return 1
    
    # Test 5: Syntax check
    print("\n📋 Test 5: Syntax Validation")
    print("-" * 70)
    
    # Check for common syntax errors
    issues = []
    
    if content.count('catalog.insert(') != content.count(');'):
        issues.append("Mismatched catalog.insert() and closing );")
    
    if '.with_go_module("")' in content:
        issues.append("Empty go_module found")
    
    if '.with_pipx_package("")' in content:
        issues.append("Empty pipx_package found")
    
    if issues:
        for issue in issues:
            print(f"❌ {issue}")
        return 1
    else:
        print("✅ No obvious syntax errors found")
    
    # Final Summary
    print("\n" + "=" * 70)
    print("📊 FINAL SUMMARY")
    print("=" * 70)
    print(f"✅ Total tools: {tool_count}")
    print(f"✅ Go tools: {go_count}")
    print(f"✅ Pipx tools: {pipx_count}")
    print(f"✅ System tools (APT/WinGet): {apt_count + winget_count}")
    print(f"✅ Manual/Runtime tools: {manual_count + runtime_count}")
    print(f"✅ All struct fields present")
    print(f"✅ All builder methods present")
    print(f"✅ All MVP tools configured")
    print(f"✅ No syntax errors detected")
    print("\n🎉 ALL TESTS PASSED!")
    
    return 0

if __name__ == '__main__':
    exit_code = test_catalog()
    sys.exit(exit_code)
