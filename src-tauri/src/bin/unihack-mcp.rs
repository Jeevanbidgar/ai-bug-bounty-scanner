use ai_bug_bounty_scanner::{daemon::DaemonClient, mcp::UniHackMcpServer, service::ServicePaths};
use anyhow::Result;
use rmcp::{transport::stdio, ServiceExt};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let paths = ServicePaths::discover()?;
    let client = Arc::new(DaemonClient::connect_or_start(&paths).await?);
    let server = UniHackMcpServer::new_remote(client);
    let running = server.serve(stdio()).await?;
    running.waiting().await?;
    Ok(())
}
