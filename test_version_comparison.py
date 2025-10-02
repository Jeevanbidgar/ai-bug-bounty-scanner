#!/usr/bin/env python3
"""
Test script for version comparison system across package managers
Tests Go, APT, WinGet, and pipx version checking functionality
"""

import os
import sys

def test_backend_version_checker():
    """Test that version_checker.rs module exists and is properly integrated"""
    print("=" * 80)
    print("TEST 1: Backend Version Checker Module")
    print("=" * 80)
    
    version_checker_path = "src-tauri/src/tools/package_managers/version_checker.rs"
    
    if not os.path.exists(version_checker_path):
        print(f"❌ FAIL: {version_checker_path} not found")
        return False
    
    with open(version_checker_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    tests = [
        ("VersionCheckResult struct", "pub struct VersionCheckResult"),
        ("check_go_update function", "pub async fn check_go_update"),
        ("check_apt_update function", "pub async fn check_apt_update"),
        ("check_winget_update function", "pub async fn check_winget_update"),
        ("check_pipx_update function", "pub async fn check_pipx_update"),
        ("get_go_binary_version function", "async fn get_go_binary_version"),
        ("get_go_latest_version function", "async fn get_go_latest_version"),
        ("Version parsing", "Version::parse"),
    ]
    
    all_passed = True
    for test_name, search_string in tests:
        if search_string in content:
            print(f"✅ PASS: {test_name} implemented")
        else:
            print(f"❌ FAIL: {test_name} not found")
            all_passed = False
    
    return all_passed


def test_backend_integration():
    """Test that version_checker is integrated into commands"""
    print("\n" + "=" * 80)
    print("TEST 2: Backend Integration")
    print("=" * 80)
    
    # Check mod.rs exports
    mod_path = "src-tauri/src/tools/package_managers/mod.rs"
    with open(mod_path, 'r', encoding='utf-8') as f:
        mod_content = f.read()
    
    tests = [
        ("version_checker module export", "pub mod version_checker"),
        ("VersionCheckResult export", "pub use version_checker::VersionCheckResult"),
        ("check_go_update export", "check_go_update"),
        ("check_apt_update export", "check_apt_update"),
        ("check_winget_update export", "check_winget_update"),
        ("check_pipx_update export", "check_pipx_update"),
    ]
    
    all_passed = True
    for test_name, search_string in tests:
        if search_string in mod_content:
            print(f"✅ PASS: {test_name}")
        else:
            print(f"❌ FAIL: {test_name} not found")
            all_passed = False
    
    # Check commands integration
    commands_path = "src-tauri/src/commands/mod.rs"
    with open(commands_path, 'r', encoding='utf-8') as f:
        commands_content = f.read()
    
    if "pub async fn check_tool_update" in commands_content:
        print(f"✅ PASS: check_tool_update command implemented")
    else:
        print(f"❌ FAIL: check_tool_update command not found")
        all_passed = False
    
    if "VersionCheckResult" in commands_content:
        print(f"✅ PASS: VersionCheckResult import in commands")
    else:
        print(f"❌ FAIL: VersionCheckResult not imported")
        all_passed = False
    
    # Check main.rs registration
    main_path = "src-tauri/src/main.rs"
    with open(main_path, 'r', encoding='utf-8') as f:
        main_content = f.read()
    
    if "crate::commands::check_tool_update" in main_content:
        print(f"✅ PASS: check_tool_update registered in main.rs")
    else:
        print(f"❌ FAIL: check_tool_update not registered")
        all_passed = False
    
    return all_passed


def test_frontend_api_service():
    """Test that API service has checkToolUpdate method"""
    print("\n" + "=" * 80)
    print("TEST 3: Frontend API Service")
    print("=" * 80)
    
    api_path = "frontend/src/services/api.ts"
    with open(api_path, 'r', encoding='utf-8') as f:
        api_content = f.read()
    
    tests = [
        ("checkToolUpdate method", "async checkToolUpdate(toolName: string)"),
        ("has_update field", "has_update: boolean"),
        ("current_version field", "current_version: string | null"),
        ("latest_version field", "latest_version: string | null"),
        ("package_manager field", "package_manager: string"),
        ("check_tool_update invoke", "this.invokeCommand('check_tool_update'"),
    ]
    
    all_passed = True
    for test_name, search_string in tests:
        if search_string in api_content:
            print(f"✅ PASS: {test_name}")
        else:
            print(f"❌ FAIL: {test_name} not found")
            all_passed = False
    
    return all_passed


def test_frontend_modal_integration():
    """Test that ToolDetailModal uses version comparison"""
    print("\n" + "=" * 80)
    print("TEST 4: Frontend Modal Integration")
    print("=" * 80)
    
    modal_path = "frontend/src/components/ToolDetailModal.tsx"
    with open(modal_path, 'r', encoding='utf-8') as f:
        modal_content = f.read()
    
    tests = [
        ("updateAvailable state", "updateAvailable"),
        ("latestVersion state", "latestVersion"),
        ("checkForUpdates call in useEffect", "checkForUpdates()"),
        ("apiService.checkToolUpdate call", "apiService.checkToolUpdate"),
        ("handleCheckForUpdates function", "const handleCheckForUpdates"),
        ("Update Available badge", "updateAvailable && latestVersion"),
        ("Version display with update", "raw_version"),
        ("Update button with animation", "updateAvailable && '✨'"),
    ]
    
    all_passed = True
    for test_name, search_string in tests:
        if search_string in modal_content:
            print(f"✅ PASS: {test_name}")
        else:
            print(f"❌ FAIL: {test_name} not found")
            all_passed = False
    
    return all_passed


def test_version_comparison_logic():
    """Test version comparison logic patterns"""
    print("\n" + "=" * 80)
    print("TEST 5: Version Comparison Logic")
    print("=" * 80)
    
    version_checker_path = "src-tauri/src/tools/package_managers/version_checker.rs"
    with open(version_checker_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    tests = [
        ("Go: go version -m", 'Command::new("go")\n        .arg("version")\n        .arg("-m")'),
        ("Go: go list -m -versions", 'Command::new("go")\n        .arg("list")\n        .arg("-m")\n        .arg("-versions")'),
        ("APT: apt-cache policy", 'Command::new("apt-cache")\n        .arg("policy")'),
        ("WinGet: winget upgrade", 'Command::new("winget")\n        .arg("upgrade")'),
        ("pipx: pipx runpip", 'Command::new("pipx")\n        .arg("runpip")'),
        ("SemVer comparison", "Version::parse"),
        ("Error handling", "VersionCheckResult::error"),
        ("Update detection", "has_update: true"),
        ("No update detection", "has_update: false"),
    ]
    
    all_passed = True
    for test_name, search_string in tests:
        if search_string in content:
            print(f"✅ PASS: {test_name}")
        else:
            print(f"❌ FAIL: {test_name} not found")
            all_passed = False
    
    return all_passed


def test_ui_components():
    """Test UI components for version display"""
    print("\n" + "=" * 80)
    print("TEST 6: UI Components")
    print("=" * 80)
    
    modal_path = "frontend/src/components/ToolDetailModal.tsx"
    with open(modal_path, 'r', encoding='utf-8') as f:
        modal_content = f.read()
    
    tests = [
        ("Update Available badge with version", '<Badge className="bg-green-700 text-green-100 animate-pulse">'),
        ("Update button styling", 'updateAvailable ? \'border-green-600 text-green-400'),
        ("Version display", 'raw_version || tool.version'),
        ("Update button with sparkle", 'Update {updateAvailable && \'✨\'}'),
        ("Version check on mount", 'checkForUpdates()'),
        ("Update check loading state", 'isCheckingUpdate'),
    ]
    
    all_passed = True
    for test_name, search_string in tests:
        if search_string in modal_content:
            print(f"✅ PASS: {test_name}")
        else:
            print(f"❌ FAIL: {test_name} not found")
            all_passed = False
    
    return all_passed


def run_all_tests():
    """Run all validation tests"""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "VERSION COMPARISON SYSTEM TEST SUITE" + " " * 22 + "║")
    print("╚" + "=" * 78 + "╝")
    print()
    
    results = []
    
    results.append(("Backend Version Checker Module", test_backend_version_checker()))
    results.append(("Backend Integration", test_backend_integration()))
    results.append(("Frontend API Service", test_frontend_api_service()))
    results.append(("Frontend Modal Integration", test_frontend_modal_integration()))
    results.append(("Version Comparison Logic", test_version_comparison_logic()))
    results.append(("UI Components", test_ui_components()))
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print("\n" + "=" * 80)
    print(f"TOTAL: {passed}/{total} test suites passed")
    print("=" * 80)
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! Version comparison system is ready!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test suite(s) failed. Please review the implementation.")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
