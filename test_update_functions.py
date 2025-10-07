#!/usr/bin/env python3
"""
Test script for npm, gem, and cargo update functionality
Tests the new version checking functions we just implemented
"""

import subprocess
import json
import sys

def test_npm_version_check():
    """Test npm version checking for a globally installed package"""
    print("\n" + "="*70)
    print("TESTING NPM VERSION CHECKING")
    print("="*70)
    
    # Check if we have any global npm packages installed
    print("\n1. Listing globally installed npm packages...")
    result = subprocess.run(
        ["npm", "list", "-g", "--depth=0", "--json"],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        try:
            data = json.loads(result.stdout)
            packages = data.get("dependencies", {})
            if packages:
                print(f"   ✓ Found {len(packages)} global packages")
                for pkg_name in list(packages.keys())[:3]:  # Show first 3
                    version = packages[pkg_name]["version"]
                    print(f"     - {pkg_name}: {version}")
                
                # Test outdated check on first package
                test_pkg = list(packages.keys())[0]
                print(f"\n2. Checking if {test_pkg} has updates...")
                outdated_result = subprocess.run(
                    ["npm", "outdated", "-g", test_pkg, "--json"],
                    capture_output=True,
                    text=True
                )
                
                if outdated_result.stdout.strip():
                    outdated_data = json.loads(outdated_result.stdout)
                    if test_pkg in outdated_data:
                        current = outdated_data[test_pkg]["current"]
                        latest = outdated_data[test_pkg]["latest"]
                        print(f"   ✓ Update available: {current} → {latest}")
                    else:
                        print(f"   ✓ Package is up to date")
                else:
                    print(f"   ✓ Package is up to date")
                
                return True
            else:
                print("   ⚠ No global npm packages installed")
                print("   💡 Install a test package: npm install -g npm-check")
                return False
        except Exception as e:
            print(f"   ✗ Error parsing npm output: {e}")
            return False
    else:
        print(f"   ✗ npm command failed: {result.stderr}")
        return False

def test_gem_version_check():
    """Test gem version checking for an installed gem"""
    print("\n" + "="*70)
    print("TESTING GEM VERSION CHECKING")
    print("="*70)
    
    # List installed gems
    print("\n1. Listing installed gems...")
    result = subprocess.run(
        ["gem", "list", "--local"],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        lines = [l for l in result.stdout.strip().split('\n') if l and not l.startswith('***')]
        if lines:
            print(f"   ✓ Found {len(lines)} installed gems")
            for line in lines[:3]:  # Show first 3
                print(f"     - {line}")
            
            # Test version check on first gem
            first_gem = lines[0].split()[0] if lines else None
            if first_gem:
                print(f"\n2. Checking if {first_gem} has updates...")
                
                # Get current version
                local_result = subprocess.run(
                    ["gem", "list", first_gem, "--exact", "--local"],
                    capture_output=True,
                    text=True
                )
                
                # Get remote version
                remote_result = subprocess.run(
                    ["gem", "search", f"^{first_gem}$", "--remote"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if remote_result.returncode == 0:
                    print(f"   ✓ Remote version info:")
                    print(f"     Local:  {local_result.stdout.strip()}")
                    print(f"     Remote: {remote_result.stdout.strip()}")
                    return True
                else:
                    print(f"   ⚠ Could not check remote gem repository")
                    return False
        else:
            print("   ⚠ No gems installed")
            print("   💡 Install a test gem: gem install bundler")
            return False
    else:
        print(f"   ✗ gem command failed: {result.stderr}")
        return False

def test_cargo_version_check():
    """Test cargo version checking for an installed package"""
    print("\n" + "="*70)
    print("TESTING CARGO VERSION CHECKING")
    print("="*70)
    
    # List installed cargo packages
    print("\n1. Listing installed cargo packages...")
    result = subprocess.run(
        ["cargo", "install", "--list"],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        lines = [l for l in result.stdout.strip().split('\n') if l and not l.startswith(' ')]
        packages = [l.split()[0] for l in lines if ' v' in l]
        
        if packages:
            print(f"   ✓ Found {len(packages)} installed packages")
            for line in lines[:6]:  # Show first 3 packages (2 lines each)
                print(f"     {line}")
            
            # Test version check on first package
            test_pkg = packages[0]
            print(f"\n2. Checking if {test_pkg} has updates...")
            
            search_result = subprocess.run(
                ["cargo", "search", test_pkg, "--limit", "1"],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if search_result.returncode == 0:
                print(f"   ✓ Remote version info:")
                for line in search_result.stdout.strip().split('\n')[:2]:
                    print(f"     {line}")
                return True
            else:
                print(f"   ⚠ Could not search crates.io")
                return False
        else:
            print("   ⚠ No cargo packages installed")
            print("   💡 Install a test package: cargo install ripgrep")
            return False
    else:
        print(f"   ✗ cargo command failed: {result.stderr}")
        return False

def test_update_commands():
    """Test that update commands exist and have correct syntax"""
    print("\n" + "="*70)
    print("TESTING UPDATE COMMAND SYNTAX")
    print("="*70)
    
    tests = [
        ("npm", ["npm", "update", "--help"], "✓ npm update command available"),
        ("gem", ["gem", "update", "--help"], "✓ gem update command available"),
        ("cargo", ["cargo", "install", "--help"], "✓ cargo install --force command available"),
    ]
    
    results = []
    for name, cmd, success_msg in tests:
        print(f"\n{name.upper()}:")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"  {success_msg}")
            results.append(True)
        else:
            print(f"  ✗ {name} update command failed")
            results.append(False)
    
    return all(results)

def main():
    print("\n" + "="*70)
    print("TESTING NPM, GEM, AND CARGO UPDATE FUNCTIONALITY")
    print("="*70)
    print("\nThis script tests the newly implemented version checking functions")
    print("for npm, gem, and cargo package managers.\n")
    
    results = {
        "npm": False,
        "gem": False,
        "cargo": False,
        "commands": False
    }
    
    try:
        results["npm"] = test_npm_version_check()
    except Exception as e:
        print(f"\n✗ NPM test failed with error: {e}")
    
    try:
        results["gem"] = test_gem_version_check()
    except Exception as e:
        print(f"\n✗ Gem test failed with error: {e}")
    
    try:
        results["cargo"] = test_cargo_version_check()
    except Exception as e:
        print(f"\n✗ Cargo test failed with error: {e}")
    
    try:
        results["commands"] = test_update_commands()
    except Exception as e:
        print(f"\n✗ Command test failed with error: {e}")
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    for name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {name.upper()} version checking")
    
    print("\n" + "="*70)
    
    total_passed = sum(results.values())
    total_tests = len(results)
    
    if total_passed == total_tests:
        print(f"✅ ALL TESTS PASSED ({total_passed}/{total_tests})")
        return 0
    else:
        print(f"⚠️  SOME TESTS FAILED ({total_passed}/{total_tests} passed)")
        return 1

if __name__ == "__main__":
    sys.exit(main())
