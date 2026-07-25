// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use tauri::{Emitter, Manager};

use ai_bug_bounty_scanner::{commands, database, settings, tools};

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let app_data_dir = app
                .path()
                .app_data_dir()
                .expect("Failed to get app data dir");
            let development_workflows = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("Tauri crate must have a project parent directory")
                .join("app/workflows");
            let bundled_workflows = app
                .path()
                .resource_dir()
                .expect("Failed to get app resource directory")
                .join("workflows");
            let workflows_dir = if development_workflows.exists() {
                development_workflows
            } else {
                bundled_workflows
            };
            let results_dir = app_data_dir.join("results");
            let reports_dir = app_data_dir.join("reports");

            if !workflows_dir.exists() {
                return Err(format!(
                    "Workflow resources were not found at {}",
                    workflows_dir.display()
                )
                .into());
            }
            std::fs::create_dir_all(&results_dir).expect("Failed to create scan results directory");
            std::fs::create_dir_all(&reports_dir)
                .expect("Failed to create report export directory");

            // Create tokio runtime for async operations
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

            // Initialize database
            let db = Arc::new(
                rt.block_on(async { database::Database::open_client(app_data_dir.clone()).await })
                    .expect("Failed to initialize database"),
            );
            let loaded_settings = rt
                .block_on(async { db.get_setting("runtime").await })
                .ok()
                .flatten()
                .and_then(|value| serde_json::from_str::<settings::AppSettings>(&value).ok())
                .filter(|settings| settings.validate().is_ok())
                .unwrap_or_default();
            let settings = Arc::new(tokio::sync::RwLock::new(loaded_settings));
            let auto_adapters = Arc::new(rt.block_on(
                ai_bug_bounty_scanner::adapters::auto::AutoAdapterService::load(
                    app_data_dir.join("auto_adapters.json"),
                ),
            ));

            // Initialize tool discovery with RwLock for async access
            let mut tool_discovery_service = tools::discovery::ToolDiscoveryService::new(
                app_data_dir.join("tool_discovery_cache.json"),
            );

            // Load cache from disk
            rt.block_on(async {
                tool_discovery_service
                    .load_cache()
                    .await
                    .unwrap_or_else(|e| eprintln!("Warning: Failed to load tool cache: {}", e));
            });

            let tool_discovery = Arc::new(tokio::sync::RwLock::new(tool_discovery_service));
            let tool_registry = Arc::new(tools::registry::ToolRegistry::new());

            // Create app state
            let app_state = commands::AppState {
                db,
                tool_discovery,
                tool_registry,
                workflows_dir,
                results_dir,
                reports_dir,
                settings,
                auto_adapters,
            };

            // Store app state
            app.manage(app_state);

            // Relay daemon-owned workflow events through the existing Tauri
            // event names. The dedicated authenticated stream reconnects after
            // daemon restarts without blocking command traffic.
            let relay_app = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    match ai_bug_bounty_scanner::integrations::desktop_daemon().await {
                        Ok(client) => match client.subscribe_events().await {
                            Ok(mut events) => {
                                while let Some(event) = events.recv().await {
                                    if relay_app.emit(&event.name, event.payload).is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(error) => {
                                eprintln!("UniHack event relay could not subscribe: {error}");
                            }
                        },
                        Err(error) => {
                            eprintln!("UniHack event relay could not connect: {error}");
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::load_workflow_templates,
            commands::get_workflow_details,
            commands::execute_workflow,
            commands::start_scan,
            commands::get_workflow_status,
            commands::stop_workflow_execution,
            commands::stop_scan,
            // Tool management commands
            commands::list_tools,
            commands::get_tool,
            commands::test_tool,
            commands::recheck_tool,
            commands::refresh_tools,
            commands::get_tool_categories,
            commands::get_tools_by_category,
            commands::add_manual_tool,
            commands::remove_manual_tool,
            commands::list_manual_tools,
            commands::get_available_tools_count,
            commands::get_os_info,
            // Tool installation commands (Phase 7)
            commands::install_tool,
            commands::install_tool_with_method,
            commands::update_tool,
            commands::uninstall_tool,
            commands::check_tool_installed,
            commands::get_tool_version,
            commands::check_tool_update,
            commands::check_tool_update_legacy,
            commands::check_tool_update_enhanced,
            commands::get_update_checker_telemetry,
            commands::clear_update_checker_telemetry,
            commands::get_tool_installation_info,
            // Package manager commands
            commands::detect_package_managers,
            commands::check_package_manager,
            commands::install_package_manager_pipx,
            commands::install_package_manager_go,
            commands::install_package_manager_winget,
            commands::check_elevation_support,
            commands::check_pipx_path,
            commands::fix_pipx_path,
            commands::cleanup_old_pipx,
            // Scan commands
            commands::list_scans,
            commands::create_scan,
            commands::get_scan,
            commands::update_scan,
            commands::delete_scan,
            commands::get_workflow_artifacts,
            commands::reveal_workflow_artifact,
            commands::reveal_scan_results,
            commands::get_workflow_findings,
            commands::get_system_info,
            commands::get_settings,
            commands::update_settings,
            // Vulnerability commands
            commands::list_vulnerabilities,
            commands::get_scan_vulnerabilities,
            commands::create_vulnerability,
            commands::delete_vulnerability,
            // Report commands
            commands::list_reports,
            commands::get_report,
            commands::reveal_report,
            commands::create_report,
            commands::delete_report,
            commands::get_stats,
            commands::get_system_metrics,
            // Adapter commands - Tool command builders
            commands::build_tool_command,
            commands::build_tool_command_with_defaults,
            commands::get_adapter_info,
            commands::list_adapters,
            commands::get_adapters_by_category,
            commands::get_adapters_by_risk_level,
            commands::has_adapter,
            commands::get_adapter_categories,
            // Local AI client integration. These commands configure STDIO MCP
            // only; they never request or persist model-provider API keys.
            ai_bug_bounty_scanner::integrations::get_mcp_integration_info,
            ai_bug_bounty_scanner::integrations::configure_mcp_client,
            ai_bug_bounty_scanner::integrations::list_engagement_scopes,
            ai_bug_bounty_scanner::integrations::create_engagement_scope,
            ai_bug_bounty_scanner::integrations::revoke_engagement_scope,
            ai_bug_bounty_scanner::integrations::list_mcp_audit_activity,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
