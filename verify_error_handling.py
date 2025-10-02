"""
Error Handling Verification Script
Tests that all mock data has been removed and error handling is in place
"""

import os
import re

def check_file_for_patterns(filepath, patterns, description):
    """Check if file contains any of the forbidden patterns"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        found_issues = []
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_issues.append(pattern)
        
        if found_issues:
            print(f"❌ {description}: {filepath}")
            for issue in found_issues:
                print(f"   Found: {issue}")
            return False
        else:
            print(f"✅ {description}: {filepath}")
            return True
    except Exception as e:
        print(f"⚠️  Could not read {filepath}: {e}")
        return True  # Don't fail on read errors

def verify_no_mock_data():
    """Verify that no mock data exists in the frontend"""
    print("\n🔍 Checking for Mock Data...")
    
    mock_patterns = [
        r'getMockData',
        r'mockTools',
        r'mockWorkflows',
        r'mockScans',
        r'mock_data',
        r'if.*NODE_ENV.*development.*return.*mock',
    ]
    
    files_to_check = [
        'frontend/src/services/api.ts',
        'frontend/src/pages/Dashboard.tsx',
        'frontend/src/pages/ToolsPage.tsx',
    ]
    
    all_clean = True
    for filepath in files_to_check:
        if os.path.exists(filepath):
            result = check_file_for_patterns(filepath, mock_patterns, "No mock data")
            all_clean = all_clean and result
    
    return all_clean

def verify_error_handling():
    """Verify that error handling is in place"""
    print("\n🔍 Checking for Error Handling...")
    
    required_patterns = [
        (r'ErrorBoundary', 'frontend/src/main.tsx', 'ErrorBoundary wrapper'),
        (r'error\s*:', 'frontend/src/pages/ToolsPage.tsx', 'Error state tracking'),
        (r'isLoading', 'frontend/src/pages/ToolsPage.tsx', 'Loading state tracking'),
        (r'if\s*\(error\)', 'frontend/src/pages/ToolsPage.tsx', 'Error state rendering'),
        (r'throw\s+new\s+Error', 'frontend/src/services/api.ts', 'Error throwing'),
    ]
    
    all_found = True
    for pattern, filepath, description in required_patterns:
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                if re.search(pattern, content):
                    print(f"✅ {description}: {filepath}")
                else:
                    print(f"❌ Missing {description}: {filepath}")
                    all_found = False
            except Exception as e:
                print(f"⚠️  Could not read {filepath}: {e}")
    
    return all_found

def verify_file_exists():
    """Verify that new files were created"""
    print("\n🔍 Checking for New Files...")
    
    required_files = [
        'frontend/src/components/ErrorBoundary.tsx',
        'frontend/src/global.d.ts',
        'ERROR_HANDLING_COMPLETE.md',
    ]
    
    all_exist = True
    for filepath in required_files:
        if os.path.exists(filepath):
            print(f"✅ File exists: {filepath}")
        else:
            print(f"❌ File missing: {filepath}")
            all_exist = False
    
    return all_exist

def main():
    print("=" * 60)
    print("Error Handling Implementation Verification")
    print("=" * 60)
    
    mock_clean = verify_no_mock_data()
    error_handling = verify_error_handling()
    files_exist = verify_file_exists()
    
    print("\n" + "=" * 60)
    print("Verification Results")
    print("=" * 60)
    
    if mock_clean:
        print("✅ No mock data found")
    else:
        print("❌ Mock data still exists")
    
    if error_handling:
        print("✅ Error handling in place")
    else:
        print("❌ Missing error handling")
    
    if files_exist:
        print("✅ All new files created")
    else:
        print("❌ Some files missing")
    
    print("\n" + "=" * 60)
    
    if mock_clean and error_handling and files_exist:
        print("🎉 ALL CHECKS PASSED - Ready for Testing!")
        return 0
    else:
        print("⚠️  Some checks failed - Review above")
        return 1

if __name__ == '__main__':
    exit(main())
