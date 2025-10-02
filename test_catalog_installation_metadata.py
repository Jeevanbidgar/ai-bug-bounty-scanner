#!/usr/bin/env python3
"""
Test script to validate catalog.rs installation metadata
Tests that all tools have proper installation metadata configured
"""

import re
import sys
from pathlib import Path
from collections import defaultdict

def parse_catalog_file(catalog_path):
    """Parse catalog.rs and extract tool definitions"""
    with open(catalog_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find all catalog.insert() calls
    pattern = r'catalog\.insert\("(\w+)"\.to_string\(\),\s*ToolDefinition::new\((.*?)\)\s*(?:\.with_\w+\([^)]+\))*\s*\);'
    
    tools = {}
    current_tool = None
    in_definition = False
    definition_lines = []
    
    lines = content.split('\n')
    for i, line in enumerate(lines):
        # Start of tool definition
        if 'catalog.insert(' in line and '.to_string()' in line:
            match = re.search(r'catalog\.insert\("(\w+)"\.to_string\(\)', line)
            if match:
                current_tool = match.group(1)
                in_definition = True
                definition_lines = [line]
        elif in_definition:
            definition_lines.append(line)
            # End of tool definition
            if line.strip().endswith(');'):
                in_definition = False
                # Parse the complete definition
                full_def = '\n'.join(definition_lines)
                
                tool_data = {
                    'name': current_tool,
                    'go_module': None,
                    'pipx_package': None,
                    'apt_package': None,
                    'winget_id': None,
                    'install_method': None
                }
                
                # Extract installation metadata
                if '.with_go_module(' in full_def:
                    match = re.search(r'\.with_go_module\("([^"]+)"\)', full_def)
                    if match:
                        tool_data['go_module'] = match.group(1)
                        tool_data['install_method'] = 'go'
                
                if '.with_pipx_package(' in full_def:
                    match = re.search(r'\.with_pipx_package\("([^"]+)"\)', full_def)
                    if match:
                        tool_data['pipx_package'] = match.group(1)
                        tool_data['install_method'] = 'pipx'
                
                if '.with_apt_package(' in full_def:
                    match = re.search(r'\.with_apt_package\("([^"]+)"\)', full_def)
                    if match:
                        tool_data['apt_package'] = match.group(1)
                        if not tool_data['install_method']:
                            tool_data['install_method'] = 'apt'
                
                if '.with_winget_id(' in full_def:
                    match = re.search(r'\.with_winget_id\("([^"]+)"\)', full_def)
                    if match:
                        tool_data['winget_id'] = match.group(1)
                        if not tool_data['install_method']:
                            tool_data['install_method'] = 'winget'
                
                if '.with_install_method(' in full_def:
                    match = re.search(r'\.with_install_method\("([^"]+)"\)', full_def)
                    if match:
                        tool_data['install_method'] = match.group(1)
                
                tools[current_tool] = tool_data
                current_tool = None
                definition_lines = []
    
    return tools

def test_catalog_metadata(catalog_path):
    """Run tests on catalog metadata"""
    print("🧪 Testing Catalog Installation Metadata")
    print("=" * 60)
    
    tools = parse_catalog_file(catalog_path)
    print(f"\n✅ Found {len(tools)} tools in catalog")
    
    # Test 1: Check all tools have installation method
    print("\n📋 Test 1: Installation Method Coverage")
    print("-" * 60)
    missing_method = []
    method_counts = defaultdict(int)
    
    for tool_name, tool_data in tools.items():
        if tool_data['install_method']:
            method_counts[tool_data['install_method']] += 1
        else:
            missing_method.append(tool_name)
    
    if missing_method:
        print(f"❌ {len(missing_method)} tools missing installation method:")
        for tool in missing_method:
            print(f"   - {tool}")
    else:
        print(f"✅ All {len(tools)} tools have installation method defined")
    
    print("\n📊 Installation Method Distribution:")
    for method, count in sorted(method_counts.items()):
        print(f"   {method:12s}: {count:2d} tools")
    
    # Test 2: Validate Go tools
    print("\n📋 Test 2: Go Install Tools Validation")
    print("-" * 60)
    go_tools = {name: data for name, data in tools.items() if data['install_method'] == 'go'}
    print(f"Found {len(go_tools)} Go tools")
    
    invalid_go = []
    for tool_name, tool_data in go_tools.items():
        if not tool_data['go_module']:
            invalid_go.append(f"{tool_name} - missing go_module")
        elif not tool_data['go_module'].startswith('github.com/'):
            invalid_go.append(f"{tool_name} - invalid module path: {tool_data['go_module']}")
    
    if invalid_go:
        print(f"❌ {len(invalid_go)} Go tools have issues:")
        for issue in invalid_go:
            print(f"   - {issue}")
    else:
        print(f"✅ All {len(go_tools)} Go tools properly configured")
    
    # Test 3: Validate Pipx tools
    print("\n📋 Test 3: Pipx Tools Validation")
    print("-" * 60)
    pipx_tools = {name: data for name, data in tools.items() if data['install_method'] == 'pipx'}
    print(f"Found {len(pipx_tools)} Pipx tools")
    
    invalid_pipx = []
    for tool_name, tool_data in pipx_tools.items():
        if not tool_data['pipx_package']:
            invalid_pipx.append(f"{tool_name} - missing pipx_package")
    
    if invalid_pipx:
        print(f"❌ {len(invalid_pipx)} Pipx tools have issues:")
        for issue in invalid_pipx:
            print(f"   - {issue}")
    else:
        print(f"✅ All {len(pipx_tools)} Pipx tools properly configured")
    
    # Test 4: Check MVP tools (Top 20)
    print("\n📋 Test 4: MVP Tools (Top 20) Validation")
    print("-" * 60)
    mvp_tools = [
        'subfinder', 'amass', 'assetfinder', 'naabu', 'httpx',
        'katana', 'hakrawler', 'gau', 'waybackurls', 'nuclei',
        'ffuf', 'gobuster', 'gowitness', 'interactsh-client', 'trufflehog',
        'nmap', 'curl', 'git', 'sqlmap', 'sublist3r'
    ]
    
    missing_mvp = []
    for tool in mvp_tools:
        if tool not in tools:
            missing_mvp.append(f"{tool} - not found in catalog")
        elif not tools[tool]['install_method']:
            missing_mvp.append(f"{tool} - missing installation method")
    
    if missing_mvp:
        print(f"❌ {len(missing_mvp)} MVP tools have issues:")
        for issue in missing_mvp:
            print(f"   - {issue}")
    else:
        print(f"✅ All {len(mvp_tools)} MVP tools properly configured")
    
    # Test 5: Print sample tool definitions
    print("\n📋 Test 5: Sample Tool Definitions")
    print("-" * 60)
    sample_tools = ['subfinder', 'nuclei', 'httpx', 'sqlmap', 'nmap']
    
    for tool in sample_tools:
        if tool in tools:
            data = tools[tool]
            print(f"\n{tool}:")
            print(f"  Install Method: {data['install_method']}")
            if data['go_module']:
                print(f"  Go Module: {data['go_module']}")
            if data['pipx_package']:
                print(f"  Pipx Package: {data['pipx_package']}")
            if data['apt_package']:
                print(f"  APT Package: {data['apt_package']}")
            if data['winget_id']:
                print(f"  WinGet ID: {data['winget_id']}")
    
    # Final Summary
    print("\n" + "=" * 60)
    print("📊 FINAL SUMMARY")
    print("=" * 60)
    total_issues = len(missing_method) + len(invalid_go) + len(invalid_pipx) + len(missing_mvp)
    
    if total_issues == 0:
        print("✅ ALL TESTS PASSED!")
        print(f"   - {len(tools)} tools total")
        print(f"   - {len(go_tools)} Go tools")
        print(f"   - {len(pipx_tools)} Pipx tools")
        print(f"   - {len([t for t in tools.values() if t['install_method'] == 'apt'])} APT tools")
        print(f"   - {len([t for t in tools.values() if t['install_method'] == 'winget'])} WinGet tools")
        print(f"   - All MVP tools configured")
        return 0
    else:
        print(f"❌ {total_issues} ISSUES FOUND")
        return 1

if __name__ == '__main__':
    catalog_path = Path(__file__).parent / 'src-tauri' / 'src' / 'tools' / 'catalog.rs'
    
    if not catalog_path.exists():
        print(f"❌ ERROR: Catalog file not found: {catalog_path}")
        sys.exit(1)
    
    exit_code = test_catalog_metadata(catalog_path)
    sys.exit(exit_code)
