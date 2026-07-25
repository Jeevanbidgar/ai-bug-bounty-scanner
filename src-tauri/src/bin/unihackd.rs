use ai_bug_bounty_scanner::{daemon::run_daemon, service::ServicePaths};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    run_daemon(ServicePaths::discover()?).await
}
