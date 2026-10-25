use crate::{
    boundary::{self, invalid},
    crypto::CipherKeys,
    error::AppError,
    protocol,
    transport::Chain,
    AppState,
};
use chrono::{DateTime, Utc};
use sqlx::{Executor, Postgres};
use uuid::Uuid;

#[derive(Clone, sqlx::FromRow)]
pub(crate) struct Session {
    pub id: Uuid,
    pub browser_id: Uuid,
    pub user_id: Uuid,
    pub account_version: i64,
    pub global_session_id: Uuid,
    pub oidc_client_id: Uuid,
    pub oidc_grant_id: Uuid,
    pub oidc_client_policy_version: i64,
    pub issuer: String,
    pub auth_time: i64,
    pub nonce_hash: String,
    pub access_ciphertext: String,
    pub refresh_ciphertext: String,
    pub access_expires_at: DateTime<Utc>,
    pub version: i64,
    pub membership_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub identity_version: Option<i64>,
    pub customer_ciphertext: Option<String>,
    pub customer_expires_at: Option<DateTime<Utc>>,
    pub customer_needs_renewal: bool,
    pub refresh_lease_id: Option<Uuid>,
    pub refresh_uncertain: bool,
    pub context_lease_id: Option<Uuid>,
    pub logout_request_id: Option<Uuid>,
    pub logout_scope: Option<String>,
    pub logout_confirmed_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}
#[derive(sqlx::FromRow)]
pub(crate) struct Browser {
    pub id: Uuid,
    pub generation: i64,
    pub current_session_id: Option<Uuid>,
}
#[derive(sqlx::FromRow)]
pub(crate) struct Flow {
    pub id: Uuid,
    pub browser_id: Uuid,
    pub browser_generation: i64,
    pub binder_hash: String,
    pub nonce_hash: String,
    pub verifier_ciphertext: String,
    pub return_path: String,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}
pub(crate) fn keys(state: &AppState) -> Result<&CipherKeys, AppError> {
    state.config.keys.as_deref().ok_or(AppError::Unavailable)
}
pub(crate) fn client(state: &AppState) -> Result<Uuid, AppError> {
    boundary::enabled(state)?;
    Ok(state.config.client_id)
}
pub(crate) fn issuer(state: &AppState) -> Result<&str, AppError> {
    boundary::enabled(state)?;
    Ok(&state.config.issuer)
}
pub(crate) async fn session_id<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    id: Uuid,
    lock: bool,
) -> Result<Option<Session>, AppError> {
    sqlx::query_as(if lock {
        "SELECT * FROM portal_sessions WHERE id=$1 FOR UPDATE"
    } else {
        "SELECT * FROM portal_sessions WHERE id=$1"
    })
    .bind(id)
    .fetch_optional(executor)
    .await
    .map_err(Into::into)
}
pub(crate) async fn session_cookie(state: &AppState, cookie: &str) -> Result<Session, AppError> {
    // Revoked rows remain discoverable solely for idempotent logout receipts.
    sqlx::query_as("SELECT s.* FROM portal_sessions s JOIN portal_browsers b ON b.id=s.browser_id WHERE s.token_hash=$1 AND s.expires_at>clock_timestamp() AND b.expires_at>clock_timestamp()")
        .bind(boundary::digest(cookie)).fetch_optional(&state.pool).await?.ok_or_else(invalid)
}
pub(crate) async fn browser<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    hash: &str,
    lock: bool,
) -> Result<Option<Browser>, AppError> {
    sqlx::query_as(if lock {"SELECT id,generation,current_session_id FROM portal_browsers WHERE token_hash=$1 AND expires_at>clock_timestamp() FOR UPDATE"}else{"SELECT id,generation,current_session_id FROM portal_browsers WHERE token_hash=$1 AND expires_at>clock_timestamp()"})
        .bind(hash).fetch_optional(executor).await.map_err(Into::into)
}
pub(crate) async fn deadline(
    connection: &mut sqlx::PgConnection,
    expires: DateTime<Utc>,
) -> Result<(), AppError> {
    let valid: bool = sqlx::query_scalar("SELECT $1::timestamptz>clock_timestamp()")
        .bind(expires)
        .fetch_one(connection)
        .await?;
    if !valid {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) async fn current(
    connection: &mut sqlx::PgConnection,
    session: &Session,
) -> Result<(), AppError> {
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM portal_sessions s JOIN portal_browsers b ON b.id=s.browser_id AND b.current_session_id=s.id WHERE s.id=$1 AND s.version=$2 AND s.membership_id IS NOT DISTINCT FROM $3::uuid AND s.customer_ciphertext IS NOT DISTINCT FROM $4::text AND s.access_ciphertext=$5 AND s.customer_needs_renewal=$6 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND b.expires_at>clock_timestamp() AND NOT s.refresh_uncertain AND s.refresh_lease_id IS NULL AND s.context_lease_id IS NULL AND s.logout_request_id IS NULL)")
        .bind(session.id).bind(session.version).bind(session.membership_id).bind(&session.customer_ciphertext).bind(&session.access_ciphertext).bind(session.customer_needs_renewal)
        .fetch_one(&mut *connection).await?;
    if !valid {
        return Err(invalid());
    }
    deadline(
        connection,
        session.expires_at.min(session.access_expires_at),
    )
    .await
}
pub(crate) fn access(state: &AppState, session: &Session) -> Result<String, AppError> {
    keys(state)?.open(
        session.id,
        &session.issuer,
        session.oidc_client_id,
        "oidc-access",
        &session.access_ciphertext,
    )
}
pub(crate) fn customer(state: &AppState, session: &Session) -> Result<String, AppError> {
    keys(state)?.open(
        session.id,
        &session.issuer,
        session.oidc_client_id,
        "customer-context",
        session.customer_ciphertext.as_deref().ok_or_else(invalid)?,
    )
}
pub(crate) async fn online(chain: &Chain<'_>, original: Session) -> Result<Session, AppError> {
    let state = chain.state;
    if original.revoked_at.is_some()
        || original.issuer != state.config.issuer
        || original.oidc_client_id != state.config.client_id
        || original.expires_at <= Utc::now()
    {
        return Err(invalid());
    }
    if original.refresh_uncertain
        || original.logout_request_id.is_some()
        || original.context_lease_id.is_some()
    {
        return Err(AppError::Unavailable);
    }
    if original.refresh_lease_id.is_some() {
        sqlx::query("UPDATE portal_sessions SET refresh_uncertain=true WHERE id=$1 AND refresh_lease_id IS NOT NULL AND refresh_started_at<=clock_timestamp()-interval '3 seconds'")
            .bind(original.id).execute(&state.pool).await?;
        return Err(AppError::Unavailable);
    }
    if original.access_expires_at <= Utc::now() + chrono::Duration::seconds(30) {
        let lease = Uuid::now_v7();
        let leased=sqlx::query("UPDATE portal_sessions s SET refresh_lease_id=$2,refresh_started_at=clock_timestamp() WHERE s.id=$1 AND s.version=$3 AND s.access_ciphertext=$4 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND NOT s.refresh_uncertain AND s.logout_request_id IS NULL AND s.refresh_lease_id IS NULL AND s.context_lease_id IS NULL AND EXISTS(SELECT 1 FROM portal_browsers b WHERE b.id=s.browser_id AND b.current_session_id=s.id AND b.expires_at>clock_timestamp())")
            .bind(original.id).bind(lease).bind(original.version).bind(&original.access_ciphertext).execute(&state.pool).await?.rows_affected();
        if leased != 1 {
            return Err(AppError::Unavailable);
        }
        let refresh = keys(state)?.open(
            original.id,
            &original.issuer,
            original.oidc_client_id,
            "oidc-refresh",
            &original.refresh_ciphertext,
        )?;
        let verified = match async {
            // Resource capabilities bind the original access proof, including
            // its expiry. Revoke with that original credential before rotating
            // it; the new proof can never revive or revoke an unrelated source.
            if original.customer_ciphertext.is_some()
                && !original.customer_needs_renewal
                && !(original.access_expires_at <= Utc::now()
                    && original
                        .customer_expires_at
                        .is_some_and(|e| e <= Utc::now()))
            {
                crate::resource::revoke(
                    chain,
                    &access(state, &original)?,
                    &customer(state, &original)?,
                )
                .await?;
            }
            protocol::refresh(chain, &original, &refresh).await
        }
        .await
        {
            Ok(value) => value,
            Err(error) => {
                sqlx::query("UPDATE portal_sessions SET refresh_uncertain=true WHERE id=$1 AND refresh_lease_id=$2").bind(original.id).bind(lease).execute(&state.pool).await?;
                return Err(error);
            }
        };
        return commit_refresh(state, &original, lease, &verified).await;
    }
    let proof = protocol::existing(chain, &original, &access(state, &original)?).await?;
    let mut connection = state.pool.acquire().await?;
    current(&mut connection, &original).await?;
    deadline(&mut connection, proof.expires_at).await?;
    let mut checked = original;
    checked.access_expires_at = checked.access_expires_at.min(proof.expires_at);
    Ok(checked)
}
pub(crate) async fn commit_refresh(
    state: &AppState,
    original: &Session,
    lease: Uuid,
    verified: &protocol::Verified,
) -> Result<Session, AppError> {
    let encrypted_access = keys(state)?.seal(
        original.id,
        &original.issuer,
        original.oidc_client_id,
        "oidc-access",
        &verified.access,
    )?;
    let encrypted_refresh = keys(state)?.seal(
        original.id,
        &original.issuer,
        original.oidc_client_id,
        "oidc-refresh",
        &verified.refresh,
    )?;
    let changed:Option<Session>=sqlx::query_as("UPDATE portal_sessions s SET access_ciphertext=$3,refresh_ciphertext=$4,access_expires_at=$5,customer_needs_renewal=(membership_id IS NOT NULL),refresh_lease_id=NULL,refresh_started_at=NULL WHERE s.id=$1 AND s.refresh_lease_id=$2 AND NOT s.refresh_uncertain AND s.refresh_started_at>clock_timestamp()-interval '3 seconds' AND s.version=$6 AND s.revoked_at IS NULL AND s.logout_request_id IS NULL AND s.expires_at>clock_timestamp() AND $5::timestamptz>clock_timestamp() AND EXISTS(SELECT 1 FROM portal_browsers b WHERE b.id=s.browser_id AND b.current_session_id=s.id AND b.expires_at>clock_timestamp()) RETURNING s.*")
        .bind(original.id).bind(lease).bind(encrypted_access).bind(encrypted_refresh).bind(verified.proof.expires_at).bind(original.version).fetch_optional(&state.pool).await?;
    changed.ok_or_else(invalid)
}
