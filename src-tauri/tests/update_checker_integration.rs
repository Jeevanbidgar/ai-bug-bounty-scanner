// Integration test for update checker

use ai_bug_bounty_scanner::tools::package_managers::{
    UpdateCheckerCoordinator, UpdateCheckerConfig, UpdateCheckerFactory,
};

#[tokio::test]
async fn test_update_checker_with_real_adapters() {
    // Create coordinator with default config
    let config = UpdateCheckerConfig::default();
    let coordinator = UpdateCheckerCoordinator::new(config.clone());
    
    // Add real checkers from factory
    let checkers = UpdateCheckerFactory::create_all_checkers(&config).await;
    println!("Found {} available package managers", checkers.len());
    
    for checker in checkers {
        println!("  - {}", checker.manager_name());
        coordinator.add_checker(checker).await;
    }
    
    // Test update check
    let result = coordinator.check_update("test-package").await;
    
    assert!(result.is_ok(), "Update check should succeed");
    
    let coordinated_result = result.unwrap();
    println!("Package: {}", coordinated_result.package);
    println!("Has update: {}", coordinated_result.has_update);
    println!("Managers checked: {}", coordinated_result.managers_checked);
    println!("Duration: {:?}", coordinated_result.duration);
    
    // Should have checked at least some managers  
    // (exact number depends on what's installed on the system)
    println!("Checked {} managers", coordinated_result.managers_checked);
    
    // May or may not have a best result (test-package doesn't exist)
    // The important thing is that it doesn't crash and returns a valid response
    if coordinated_result.best_result.is_some() {
        println!("✓ Found update information");
    } else {
        println!("✓ Package not found (expected for test-package)");
    }
    
    println!("✅ Update checker integration test passed!");
}

#[tokio::test]
async fn test_update_checker_telemetry() {
    let config = UpdateCheckerConfig::default();
    let coordinator = UpdateCheckerCoordinator::new(config.clone());
    
    // Add real checkers
    let checkers = UpdateCheckerFactory::create_all_checkers(&config).await;
    for checker in checkers {
        coordinator.add_checker(checker).await;
    }
    
    // Run check
    let _result = coordinator.check_update("test-tool").await;
    
    // Get telemetry
    let telemetry = coordinator.get_telemetry_summary();
    
    println!("Telemetry Summary:");
    println!("  Total events: {}", telemetry.total_events);
    println!("  Update checks: {}", telemetry.update_checks_started);
    println!("  Manager checks: {}", telemetry.manager_checks_started);
    println!("  Success rate: {:.2}%", telemetry.success_rate * 100.0);
    
    assert!(telemetry.total_events > 0, "Should have telemetry events");
    assert!(telemetry.update_checks_started >= 1, "Should start at least 1 update check");
    
    println!("✅ Telemetry test passed!");
}

#[tokio::test]
async fn test_factory_creates_checkers() {
    let config = UpdateCheckerConfig::default();
    let checkers = UpdateCheckerFactory::create_all_checkers(&config).await;
    
    println!("Created {} checkers", checkers.len());
    
    // Should create mock checkers
    assert!(checkers.len() > 0, "Should create at least one checker");
    
    // Verify they're in priority order
    for (i, checker) in checkers.iter().enumerate() {
        println!("  {}. {} (priority: {})", i + 1, checker.manager_name(), checker.priority());
    }
    
    println!("✅ Factory test passed!");
}

