#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var("DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("explicit DATABASE_URL required"))?;
    saas_customer_portal_backend::migrate(&url).await
}
