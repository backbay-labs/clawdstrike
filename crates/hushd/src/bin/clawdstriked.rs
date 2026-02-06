#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hushd::cli::run_bin("clawdstriked").await
}
