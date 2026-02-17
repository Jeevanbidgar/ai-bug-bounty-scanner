// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;
use log::info;

mod runtime;
mod workflow;
mod tools;
mod adapters;
mod commands;
mod events;

use commands::*;
use events::*;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    env_logger::init();

    info!("Starting AI Bug Bounty Scanner with Tauri Rust core");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_os::init())
        .invoke_handler(tauri::generate_handler![
            // Tool management
            get_tools,
            discover_tools,

            // Workflow management
            get_workflow_templates,
            execute_workflow,

            // Scan management
            get_scans,
            create_scan,
            start_scan,
            stop_scan,
            delete_scan,
            get_scan_details,
            get_workflow_status,

            // Report management
            get_reports,
            generate_report,

            // Health and metrics
            get_health,
            get_metrics
        ])
        .setup(|app| {
            info!("Tauri app setup completed");

            // Initialize tool registry
            let tool_registry = tools::registry::ToolRegistry::new();
            app.manage(tool_registry);

            // Initialize workflow engine
            let workflow_engine = workflow::engine::WorkflowEngine::new();
            app.manage(workflow_engine);

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}