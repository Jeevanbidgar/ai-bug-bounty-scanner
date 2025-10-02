// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use tauri::Manager;

mod database;
mod workflow;
mod tools;
mod runtime;
mod commands;
mod events;
mod adapters;

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let app_handle = app.handle();
            let app_data_dir = app.path_resolver().app_data_dir()
                .expect("Failed to get app data dir");

            // Create tokio runtime for async operations
            let rt = tokio::runtime::Runtime::new()
                .expect("Failed to create tokio runtime");

            // Initialize database
            let db = Arc::new(
                rt.block_on(async { crate::database::Database::new(app_data_dir.clone()).await })
                    .expect("Failed to initialize database")
            );

            // Create artifacts directory
            let artifacts_dir = app_data_dir.join("artifacts");
            if !artifacts_dir.exists() {
                std::fs::create_dir_all(&artifacts_dir)
                    .expect("Failed to create artifacts directory");
            }

            // Initialize tool discovery with RwLock for async access
            let mut tool_discovery_service = crate::tools::discovery::ToolDiscoveryService::new();
            
            // Load cache from disk
            rt.block_on(async {
                tool_discovery_service.load_cache().await
                    .unwrap_or_else(|e| eprintln!("Warning: Failed to load tool cache: {}", e));
            });
            
            let tool_discovery = Arc::new(tokio::sync::RwLock::new(tool_discovery_service));
            let tool_registry = Arc::new(crate::tools::registry::ToolRegistry::new());

            // Initialize workflow engine (pass tool_discovery and artifacts_dir)
            let workflow_engine = Arc::new(crate::workflow::engine::WorkflowEngine::new(
                app_handle.clone(),
                tool_discovery.clone(),
                artifacts_dir
            ));

            // Create app state
            let app_state = crate::commands::AppState {
                db,
                workflow_engine,
                tool_discovery,
                tool_registry,
            };

            // Store app state
            app.manage(app_state);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            crate::commands::load_workflow_templates,
            crate::commands::get_workflow_details,
            crate::commands::execute_workflow,
            crate::commands::get_workflow_status,
            crate::commands::stop_workflow_execution,
            // Tool management commands
            crate::commands::list_tools,
            crate::commands::get_tool,
            crate::commands::recheck_tool,
            crate::commands::refresh_tools,
            crate::commands::get_tool_categories,
            crate::commands::get_tools_by_category,
            crate::commands::add_manual_tool,
            crate::commands::remove_manual_tool,
            crate::commands::list_manual_tools,
            crate::commands::get_available_tools_count,
            crate::commands::get_os_info,
            // Tool installation commands (Phase 7)
            crate::commands::install_tool,
            crate::commands::update_tool,
            crate::commands::uninstall_tool,
            crate::commands::check_tool_installed,
            crate::commands::get_tool_version,
            crate::commands::get_tool_installation_info,
            // Package manager commands
            crate::commands::detect_package_managers,
            crate::commands::check_package_manager,
            crate::commands::install_package_manager_pipx,
            crate::commands::install_package_manager_go,
            crate::commands::install_package_manager_apt,
            crate::commands::install_package_manager_winget,
            crate::commands::check_elevation_support,
            crate::commands::execute_elevated_command,
            crate::commands::try_command_with_elevation,
            // Scan commands
            crate::commands::list_scans,
            crate::commands::create_scan,
            crate::commands::get_scan,
            crate::commands::update_scan,
            crate::commands::delete_scan,
            crate::commands::get_workflow_artifacts,
            crate::commands::get_workflow_findings,
            crate::commands::get_system_info,
            // Vulnerability commands
            crate::commands::list_vulnerabilities,
            crate::commands::get_scan_vulnerabilities,
            crate::commands::create_vulnerability,
            crate::commands::delete_vulnerability,
            // Report commands
            crate::commands::list_reports,
            crate::commands::get_report,
            crate::commands::create_report,
            crate::commands::delete_report,
            crate::commands::get_stats,
            crate::commands::get_system_metrics,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
