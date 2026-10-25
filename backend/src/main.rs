#[tokio::main]
async fn main() -> anyhow::Result<()> {
    saas_customer_portal_backend::run().await
}
