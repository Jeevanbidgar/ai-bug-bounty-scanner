use ai_bug_bounty_scanner::tools::package_managers::version_checker::{
    check_cargo_update, check_gem_update, check_npm_update,
};

#[tokio::test]
async fn test_npm_update_check() {
    println!("\n=== Testing NPM Update Check ===");

    // Test with @google/gemini-cli (we know it's installed)
    let result = check_npm_update("@google/gemini-cli").await;

    match result {
        Ok(check) => {
            println!("Package Manager: {}", check.package_manager);
            println!("Current Version: {:?}", check.current_version);
            println!("Latest Version: {:?}", check.latest_version);
            println!("Has Update: {}", check.has_update);

            assert_eq!(check.package_manager, "npm");
            assert!(
                check.current_version.is_some(),
                "Should have current version"
            );
        }
        Err(e) => {
            println!("Error: {}", e);
            panic!("NPM check failed: {}", e);
        }
    }
}

#[tokio::test]
async fn test_gem_update_check() {
    println!("\n=== Testing GEM Update Check ===");

    // Test with bundler (we know it's installed)
    let result = check_gem_update("bundler").await;

    match result {
        Ok(check) => {
            println!("Package Manager: {}", check.package_manager);
            println!("Current Version: {:?}", check.current_version);
            println!("Latest Version: {:?}", check.latest_version);
            println!("Has Update: {}", check.has_update);

            assert_eq!(check.package_manager, "gem");
            assert!(
                check.current_version.is_some(),
                "Should have current version"
            );
        }
        Err(e) => {
            println!("Error: {}", e);
            panic!("GEM check failed: {}", e);
        }
    }
}

#[tokio::test]
async fn test_cargo_update_check() {
    println!("\n=== Testing CARGO Update Check ===");

    // Test with bat (we just installed it)
    let result = check_cargo_update("bat").await;

    match result {
        Ok(check) => {
            println!("Package Manager: {}", check.package_manager);
            println!("Current Version: {:?}", check.current_version);
            println!("Latest Version: {:?}", check.latest_version);
            println!("Has Update: {}", check.has_update);

            assert_eq!(check.package_manager, "cargo");
            assert!(
                check.current_version.is_some(),
                "Should have current version"
            );
        }
        Err(e) => {
            println!("Error: {}", e);
            panic!("CARGO check failed: {}", e);
        }
    }
}

#[tokio::test]
async fn test_npm_package_not_installed() {
    println!("\n=== Testing NPM with non-existent package ===");

    let result = check_npm_update("this-package-definitely-does-not-exist-12345").await;

    match result {
        Ok(check) => {
            println!("Error: {:?}", check.error);
            assert!(check.error.is_some(), "Should have an error");
            assert!(
                check.current_version.is_none(),
                "Should not have current version"
            );
        }
        Err(_) => {
            // This is also acceptable
        }
    }
}
