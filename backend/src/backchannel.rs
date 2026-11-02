//! Signature-authorized logout never asks a revoked access token to prove itself.
use crate::{boundary, error::AppError, protocol, store, transport::Chain, AppState};
use axum::{
    extract::{rejection::FormRejection, Form, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LogoutForm {
    logout_token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    typ: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Events {
    #[serde(rename = "http://schemas.openid.net/event/backchannel-logout")]
    _logout: Empty,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Claims {
    iss: String,
    aud: String,
    sid: String,
    sub: String,
    jti: String,
    iat: i64,
    exp: i64,
    events: Events,
}

fn bad() -> AppError {
    AppError::bad_request("登出通知无效")
}

fn strict_header(token: &str) -> Result<(), AppError> {
    if token.is_empty() || token.len() > 8192 {
        return Err(bad());
    }
    let mut parts = token.split('.');
    let encoded = parts.next().ok_or_else(bad)?;
    if parts.next().is_none() || parts.next().is_none() || parts.next().is_some() {
        return Err(bad());
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| bad())?;
    let header: Header = serde_json::from_slice(&bytes).map_err(|_| bad())?;
    if header.alg != "RS256"
        || header.typ != "logout+jwt"
        || header.kid.is_empty()
        || header.kid.len() > 80
        || !header
            .kid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(bad());
    }
    Ok(())
}

fn validate(
    token: &str,
    key: &DecodingKey,
    issuer: &str,
    client: &str,
    now: i64,
) -> Result<Claims, AppError> {
    strict_header(token)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = 0;
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[client]);
    validation.set_required_spec_claims(&["iss", "aud", "iat", "exp", "jti", "sid", "sub"]);
    let claims = jsonwebtoken::decode::<Claims>(token, key, &validation)
        .map_err(|_| bad())?
        .claims;
    if claims.iss != issuer
        || claims.aud != client
        || !boundary::canonical_secret(&claims.sid)
        || !protocol::opaque(&claims.sub)
        || boundary::id(&claims.jti).is_err()
        || claims.iat <= 0
        || claims.iat > now.saturating_add(5)
        || claims.iat < now.saturating_sub(120)
        || claims.exp != claims.iat.saturating_add(120)
        || claims.exp <= now
    {
        return Err(bad());
    }
    let _ = &claims.events;
    Ok(claims)
}

pub(crate) async fn receive(state: &AppState, token: &str) -> Result<bool, AppError> {
    strict_header(token)?;
    let chain = Chain::new(state)?;
    let key = protocol::signing_key(&chain, token)
        .await
        .map_err(|error| {
            if matches!(error, AppError::Unavailable) {
                error
            } else {
                bad()
            }
        })?;
    let claims = validate(
        token,
        &key,
        store::issuer(state)?,
        &store::client(state)?.to_string(),
        Utc::now().timestamp(),
    )?;
    apply(state, &claims).await
}

async fn apply(state: &AppState, claims: &Claims) -> Result<bool, AppError> {
    let mut tx = state.pool.begin().await?;
    let issued = DateTime::from_timestamp(claims.iat, 0).ok_or_else(bad)?;
    let expires = DateTime::from_timestamp(claims.exp, 0).ok_or_else(bad)?;
    let client = store::client(state)?;
    store::lock_public_source(&mut tx, &claims.iss, client, &claims.sid).await?;
    deadline(&mut tx, expires).await?;
    // A valid signature is necessary but cannot relabel a known RP session.
    let wrong_subject: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM portal_sessions WHERE issuer=$1 AND oidc_client_id=$2 AND oidc_public_sid=$3 AND oidc_public_sub<>$4) OR EXISTS(SELECT 1 FROM portal_backchannel_logout_sources WHERE issuer=$1 AND client_id=$2 AND sid_digest=$5 AND sub_digest<>$6)")
        .bind(&claims.iss).bind(client).bind(&claims.sid).bind(&claims.sub).bind(boundary::digest(&claims.sid)).bind(boundary::digest(&claims.sub)).fetch_one(&mut *tx).await?;
    if wrong_subject {
        return Err(bad());
    }
    let inserted: Option<Uuid>=sqlx::query_scalar("INSERT INTO portal_backchannel_logout_receipts(id,issuer,client_id,jti_digest,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(issuer,client_id,jti_digest) DO NOTHING RETURNING id")
        .bind(Uuid::now_v7()).bind(&claims.iss).bind(client).bind(boundary::digest(&claims.jti)).bind(issued).bind(expires).fetch_optional(&mut *tx).await?;
    if inserted.is_none() {
        return Ok(false);
    }
    sqlx::query("INSERT INTO portal_backchannel_logout_sources(id,issuer,client_id,sid_digest,sub_digest) VALUES($1,$2,$3,$4,$5) ON CONFLICT(issuer,client_id,sid_digest) DO NOTHING")
        .bind(Uuid::now_v7()).bind(&claims.iss).bind(client).bind(boundary::digest(&claims.sid)).bind(boundary::digest(&claims.sub)).execute(&mut *tx).await?;
    // Match normal callback/logout lock order: browser first, then sessions.
    sqlx::query("SELECT b.id FROM portal_browsers b WHERE EXISTS(SELECT 1 FROM portal_sessions s WHERE s.browser_id=b.id AND s.issuer=$1 AND s.oidc_client_id=$2 AND s.oidc_public_sid=$3 AND s.oidc_public_sub=$4) ORDER BY b.id FOR UPDATE")
        .bind(&claims.iss).bind(client).bind(&claims.sid).bind(&claims.sub).fetch_all(&mut *tx).await?;
    sqlx::query("SELECT id FROM portal_sessions WHERE issuer=$1 AND oidc_client_id=$2 AND oidc_public_sid=$3 AND oidc_public_sub=$4 ORDER BY id FOR UPDATE")
        .bind(&claims.iss).bind(client).bind(&claims.sid).bind(&claims.sub).fetch_all(&mut *tx).await?;
    sqlx::query("UPDATE portal_browsers b SET generation=generation+1,current_session_id=NULL WHERE EXISTS(SELECT 1 FROM portal_sessions s WHERE s.id=b.current_session_id AND s.issuer=$1 AND s.oidc_client_id=$2 AND s.oidc_public_sid=$3 AND s.oidc_public_sub=$4)")
        .bind(&claims.iss).bind(client).bind(&claims.sid).bind(&claims.sub).execute(&mut *tx).await?;
    sqlx::query("UPDATE portal_sessions SET revoked_at=COALESCE(revoked_at,clock_timestamp()),refresh_lease_id=NULL,refresh_started_at=NULL,context_lease_id=NULL,context_started_at=NULL,pending_selection_ciphertext=NULL,membership_id=NULL,organization_id=NULL,identity_version=NULL,customer_ciphertext=NULL,customer_expires_at=NULL,customer_needs_renewal=false WHERE issuer=$1 AND oidc_client_id=$2 AND oidc_public_sid=$3 AND oidc_public_sub=$4")
        .bind(&claims.iss).bind(client).bind(&claims.sid).bind(&claims.sub).execute(&mut *tx).await?;
    deadline(&mut tx, expires).await?;
    tx.commit().await?;
    Ok(true)
}

async fn deadline(
    connection: &mut sqlx::PgConnection,
    expiry: DateTime<Utc>,
) -> Result<(), AppError> {
    let live: bool = sqlx::query_scalar("SELECT $1::timestamptz>clock_timestamp()")
        .bind(expiry)
        .fetch_one(connection)
        .await?;
    if live {
        Ok(())
    } else {
        Err(bad())
    }
}

pub(crate) async fn endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    form: Result<Form<LogoutForm>, FormRejection>,
) -> Result<Response, AppError> {
    boundary::host(&state, &headers)?;
    if query.is_some() {
        return Err(bad());
    }
    let Form(form) = form.map_err(|_| bad())?;
    if receive(&state, &form.logout_token).await? {
        Ok(StatusCode::OK.into_response())
    } else {
        Ok((
            StatusCode::CONFLICT,
            Json(json!({"code":"BACKCHANNEL_REPLAY","message":"登出通知已经处理"})),
        )
            .into_response())
    }
}

#[cfg(test)]
pub(crate) mod tests;
