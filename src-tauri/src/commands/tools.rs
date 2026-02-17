use super::types::*;
use crate::{tools::*, workflow::types::*};
use tauri::State;
use anyhow::Result;
use log::{info, warn};
use std::collections::HashMap;

/// Get all available tools
#[tauri::command]
pub async fn get_tools(state: State<'_, ToolRegistry>) -> Result<Vec<Tool>> {
    info!("Getting all tools");
    let tools = state.get_all_tools().await;
    Ok(tools)
}

/// Get available tools only
#[tauri::command]
pub async fn get_available_tools(state: State<'_, ToolRegistry>) -> Result<Vec<Tool>> {
    info!("Getting available tools");
    let tools = state.get_available_tools().await;
    Ok(tools)
}

/// Get tools by category
#[tauri::command]
pub async fn get_tools_by_category(
    category: String,
    state: State<'_, ToolRegistry>,
) -> Result<Vec<Tool>> {
    info!("Getting tools by category: {}", category);

    let category_enum = match category.as_str() {
        "reconnaissance" => ToolCategory::Reconnaissance,
        "scanning" => ToolCategory::Scanning,
        "vulnerability" => ToolCategory::Vulnerability,
        "exploitation" => ToolCategory::Exploitation,
        "utility" => ToolCategory::Utility,
        _ => return Err(anyhow::anyhow!("Invalid category: {}", category)),
    };

    let tools = state.get_tools_by_category(&category_enum).await;
    Ok(tools)
}

/// Discover tools from system
#[tauri::command]
pub async fn discover_tools(state: State<'_, ToolRegistry>) -> Result<usize> {
    info!("Discovering tools from system");

    let mut discovery = ToolDiscovery::new();
    let count = discovery.run_full_discovery().await?;

    info!("Discovered {} new tools", count);
    Ok(count)
}

/// Get tool registry statistics
#[tauri::command]
pub async fn get_tool_stats(state: State<'_, ToolRegistry>) -> Result<ToolRegistryStats> {
    info!("Getting tool registry statistics");
    let stats = state.get_stats().await;
    Ok(stats)
}

/// Check if a specific tool is available
#[tauri::command]
pub async fn check_tool_availability(
    tool_name: String,
    state: State<'_, ToolRegistry>,
) -> Result<bool> {
    info!("Checking availability for tool: {}", tool_name);
    let available = state.is_tool_available(&tool_name).await;
    Ok(available)
}

/// Register a custom tool
#[tauri::command]
pub async fn register_custom_tool(
    name: String,
    path: String,
    description: String,
    category: String,
    state: State<'_, ToolRegistry>,
) -> Result<()> {
    info!("Registering custom tool: {}", name);

    let category_enum = match category.as_str() {
        "reconnaissance" => ToolCategory::Reconnaissance,
        "scanning" => ToolCategory::Scanning,
        "vulnerability" => ToolCategory::Vulnerability,
        "exploitation" => ToolCategory::Exploitation,
        "utility" => ToolCategory::Utility,
        _ => return Err(anyhow::anyhow!("Invalid category: {}", category)),
    };

    let tool = Tool {
        name: name.clone(),
        path,
        version: None,
        description,
        category: category_enum,
        available: false, // Will be checked when refreshed
        last_checked: chrono::Utc::now(),
    };

    state.register_tool(tool).await?;
    info!("Successfully registered custom tool: {}", name);
    Ok(())
}

/// Refresh tool availability and versions
#[tauri::command]
pub async fn refresh_tools(state: State<'_, ToolRegistry>) -> Result<()> {
    info!("Refreshing tool registry");
    state.refresh().await?;
    info!("Tool registry refreshed");
    Ok(())
}