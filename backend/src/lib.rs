//! Independent customer relying party. Only cookie-bound, exact CUSTOMER
//! selection reaches the self-profile resource; this crate has no platform DB.

mod boundary;
mod config;
mod crypto;
mod error;
mod protocol;
mod resource;
mod routes;
mod selection;
mod store;
mod transport;
mod usecases;

use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct AppState {
    config: Arc<config::Config>,
    pool: sqlx::PgPool,
    transport: Arc<dyn transport::OidcTransport>,
    authority_slots: Arc<tokio::sync::Semaphore>,
}

/// Validate environment, then serve the
/// portal BFF behind the configured same-origin HTTPS reverse proxy.
/// Configuration and startup errors never include credential material.
pub async fn run() -> anyhow::Result<()> {
    let config = config::Config::from_values(&std::env::vars().collect())?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET statement_timeout='3000ms'")
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("SET lock_timeout='1000ms'")
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&config.database_url)
        .await
        .map_err(|_| anyhow::anyhow!("portal database unavailable"))?;
    let bind = config.bind_addr;
    let state = AppState {
        transport: transport::configured(&config),
        config: Arc::new(config),
        pool,
        authority_slots: Arc::new(tokio::sync::Semaphore::new(16)),
    };
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let shutdown_pool = state.pool.clone();
    axum::serve(listener, routes::routes().with_state(state))
        .with_graceful_shutdown(shutdown())
        .await?;
    shutdown_pool.close().await;
    Ok(())
}
async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _=tokio::signal::ctrl_c()=>{}, _=terminate.recv()=>{} }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Apply only this service's migrations to the explicit PostgreSQL URL.
/// Run under a separate migration role before starting the restricted runtime.
/// Connection and migration diagnostics deliberately omit credentials.
pub async fn migrate(database_url: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(database_url)
        .map_err(|_| anyhow::anyhow!("invalid portal database URL"))?;
    anyhow::ensure!(
        matches!(url.scheme(), "postgres" | "postgresql"),
        "PostgreSQL database required"
    );
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .map_err(|_| anyhow::anyhow!("portal database unavailable"))?;
    sqlx::migrate!()
        .run(&pool)
        .await
        .map_err(|_| anyhow::anyhow!("portal migration failed"))?;
    pool.close().await;
    Ok(())
}

#[cfg(test)]
mod tests;
