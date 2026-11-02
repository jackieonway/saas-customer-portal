use crate::{
    boundary::{self as b, bad, invalid},
    error::AppError,
    protocol, store,
    transport::Chain,
    usecases, AppState,
};
use axum::{
    extract::{DefaultBodyLimit, RawQuery, Request, State},
    http::{header, HeaderMap, HeaderValue},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/auth/config", get(configuration))
        .route("/auth/session", get(session))
        .route("/auth/login-bootstrap", get(login_bootstrap))
        .route("/auth/login", post(login))
        .route("/auth/callback", get(callback))
        .route("/auth/context", post(context))
        .route("/auth/logout", post(logout))
        .route(
            "/auth/backchannel-logout",
            post(crate::backchannel::endpoint),
        )
        .route("/api/profile", get(profile))
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn(protected_headers))
}
async fn protected_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    for (name, value) in [
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response
        .headers_mut()
        .append(header::VARY, HeaderValue::from_static("Origin, Cookie"));
    response
}
async fn configuration(State(state): State<AppState>) -> Json<Value> {
    Json(json!({"mode":if state.config.enabled {"BFF"} else {"DISABLED"}}))
}
fn no_query(raw: Option<String>) -> Result<(), AppError> {
    if !b::parameters(raw)?.is_empty() {
        return Err(bad());
    }
    Ok(())
}
fn with_cookie(
    mut response: Response,
    name: &str,
    value: &str,
    ttl: i64,
) -> Result<Response, AppError> {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&b::cookie(name, value, ttl)).map_err(|_| AppError::Unavailable)?,
    );
    Ok(response)
}
fn session_cookie(headers: &HeaderMap) -> Result<&str, AppError> {
    b::cookie_value(headers, b::SESSION_COOKIE)?.ok_or_else(invalid)
}
async fn authenticated(state: &AppState, headers: &HeaderMap) -> Result<store::Session, AppError> {
    let cookie = session_cookie(headers)?;
    let s = store::session_cookie(state, cookie).await?;
    let browser = b::cookie_value(headers, b::BROWSER_COOKIE)?.ok_or_else(invalid)?;
    let browser = store::browser(&state.pool, &b::digest(browser), false)
        .await?
        .ok_or_else(invalid)?;
    if browser.id != s.browser_id {
        return Err(invalid());
    }
    // Confirmed logout can be replayed as a receipt, although its browser no
    // longer points at the retired session. Other paths call store::online.
    if browser.current_session_id != Some(s.id)
        && s.logout_confirmed_at.is_none()
        && s.logout_request_id.is_none()
    {
        return Err(invalid());
    }
    Ok(s)
}
async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<Response, AppError> {
    b::origin(&state, &headers, true)?;
    no_query(raw)?;
    if b::cookie_value(&headers, b::SESSION_COOKIE)?.is_some() {
        let original =
            crate::selection::resume(&state, authenticated(&state, &headers).await?).await?;
        if original.logout_request_id.is_some() {
            let scope = original.logout_scope.clone().ok_or(AppError::Unavailable)?;
            let chain = Chain::new(&state)?;
            finish_logout(&chain, original, &scope).await?;
            return Err(invalid());
        }
        let chain = Chain::new(&state)?;
        let checked = store::online(&chain, original).await?;
        return Ok(Json(
            usecases::view(&chain, checked, &b::csrf(session_cookie(&headers)?)).await?,
        )
        .into_response());
    }
    anonymous(&state, &headers).await
}
async fn login_bootstrap(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<Response, AppError> {
    b::origin(&state, &headers, true)?;
    no_query(raw)?;
    // This explicit login bootstrap grants no account or resource access.
    // It remains available when an old session has expired or been revoked.
    anonymous(&state, &headers).await
}
async fn anonymous(state: &AppState, headers: &HeaderMap) -> Result<Response, AppError> {
    let existing = b::cookie_value(headers, b::BROWSER_COOKIE)?;
    let browser_cookie = existing.map(str::to_owned).unwrap_or(b::secret()?);
    let hash = b::digest(&browser_cookie);
    if store::browser(&state.pool, &hash, false).await?.is_none() {
        sqlx::query("INSERT INTO portal_browsers(id,token_hash,generation,created_at,expires_at) VALUES($1,$2,0,clock_timestamp(),clock_timestamp()+interval '1 day') ON CONFLICT(token_hash) DO UPDATE SET generation=portal_browsers.generation+1,current_session_id=NULL,expires_at=clock_timestamp()+interval '1 day'")
            .bind(Uuid::now_v7()).bind(hash).execute(&state.pool).await?;
    }
    let response=Json(json!({"contractVersion":"portal-session/1","version":"0","csrfToken":b::csrf(&browser_cookie),"account":null,"memberships":[],"context":null})).into_response();
    with_cookie(response, b::BROWSER_COOKIE, &browser_cookie, 86400)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Login {
    return_to: String,
    #[serde(default)]
    expected_version: Option<String>,
}
async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
    body: Result<Json<Login>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, AppError> {
    b::origin(&state, &headers, false)?;
    no_query(raw)?;
    let Json(body) = body.map_err(|_| bad())?;
    let path = b::return_path(&body.return_to)?;
    let browser_cookie = b::cookie_value(&headers, b::BROWSER_COOKIE)?.ok_or_else(invalid)?;
    // Explicit reauthentication uses the current session CSRF. Anonymous
    // login uses the preauthentication browser's separately bound CSRF.
    let browser_hash = b::digest(browser_cookie);
    if b::require_csrf(&headers, browser_cookie).is_err() {
        let cookie = b::cookie_value(&headers, b::SESSION_COOKIE)?.ok_or_else(invalid)?;
        let s = authenticated(&state, &headers).await?;
        b::require_csrf(&headers, cookie)?;
        if s.browser_id
            != store::browser(&state.pool, &browser_hash, false)
                .await?
                .ok_or_else(invalid)?
                .id
        {
            return Err(invalid());
        }
    }
    let chain = Chain::new(&state)?;
    let switching = if let Some(expected) = &body.expected_version {
        if !state.config.context_selection_enabled {
            return Err(AppError::conflict("统一选择尚未启用"));
        }
        let original = authenticated(&state, &headers).await?;
        b::require_csrf(&headers, session_cookie(&headers)?)?;
        if original.version.to_string() != *expected {
            return Err(AppError::conflict("原门户会话已变化"));
        }
        Some(store::online(&chain, original).await?)
    } else {
        None
    };
    protocol::discovery(&chain).await?;
    let state_secret = b::secret()?;
    let nonce = b::secret()?;
    let verifier = b::secret()?;
    let binder = b::secret()?;
    let flow_id = Uuid::now_v7();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let context_request = if state.config.context_selection_enabled {
        Some(
            crate::selection::create(
                &chain,
                flow_id,
                &b::digest(&state_secret),
                &b::digest(&nonce),
                &challenge,
                switching.as_ref(),
            )
            .await?,
        )
    } else {
        None
    };
    let encrypted = store::keys(&state)?.seal(
        flow_id,
        &state.config.issuer,
        state.config.client_id,
        "login-verifier",
        &verifier,
    )?;
    let mut tx = state.pool.begin().await?;
    let browser = store::browser(&mut *tx, &browser_hash, true)
        .await?
        .ok_or_else(invalid)?;
    if switching
        .as_ref()
        .is_some_and(|s| s.browser_id != browser.id || browser.current_session_id != Some(s.id))
    {
        return Err(AppError::conflict("原门户浏览器会话已变化"));
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('portal-login-capacity-v1',0))")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM portal_login_flows WHERE id IN (SELECT id FROM portal_login_flows WHERE consumed_at IS NOT NULL OR expires_at<=clock_timestamp() ORDER BY expires_at LIMIT 1024)").execute(&mut *tx).await?;
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM portal_login_flows WHERE consumed_at IS NULL AND expires_at>clock_timestamp()").fetch_one(&mut *tx).await?;
    if count >= 10000 {
        return Err(AppError::Unavailable);
    }
    sqlx::query("INSERT INTO portal_login_flows(id,browser_id,browser_generation,state_hash,binder_hash,nonce_hash,verifier_ciphertext,return_path,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp(),clock_timestamp()+interval '5 minutes')")
        .bind(flow_id).bind(browser.id).bind(browser.generation).bind(b::digest(&state_secret)).bind(b::digest(&binder)).bind(b::digest(&nonce)).bind(encrypted).bind(path).execute(&mut *tx).await?;
    sqlx::query("UPDATE portal_login_flows SET context_selection_required=$2,switch_session_id=$3,switch_version=$4 WHERE id=$1").bind(flow_id).bind(state.config.context_selection_enabled).bind(switching.as_ref().map(|s|s.id)).bind(switching.as_ref().map(|s|s.version)).execute(&mut *tx).await?;
    tx.commit().await?;
    let mut url = reqwest::Url::parse(&format!("{}/oauth/authorize", state.config.issuer))
        .map_err(|_| AppError::Unavailable)?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &state.config.client_id.to_string())
        .append_pair("redirect_uri", &state.config.redirect_uri)
        .append_pair("scope", "openid profile")
        .append_pair("state", &state_secret)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge_method", "S256")
        .append_pair("code_challenge", &challenge);
    if let Some(reference) = context_request {
        url.query_pairs_mut()
            .append_pair("context_request", &reference);
    }
    with_cookie(
        Json(json!({"redirectTo":url.as_str()})).into_response(),
        b::LOGIN_COOKIE,
        &binder,
        300,
    )
}
async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<Response, AppError> {
    b::host(&state, &headers)?;
    let values = b::parameters(raw)?;
    if values.keys().any(|name| {
        !matches!(
            name.as_str(),
            "state" | "iss" | "code" | "error" | "error_description"
        )
    }) {
        return Err(bad());
    }
    let secret = values
        .get("state")
        .filter(|s| b::canonical_secret(s))
        .ok_or_else(bad)?;
    if values.get("iss").map(String::as_str) != Some(state.config.issuer.as_str()) {
        return Err(invalid());
    }
    let error = values.contains_key("error");
    if error == values.contains_key("code") {
        return Err(bad());
    }
    let binder = b::cookie_value(&headers, b::LOGIN_COOKIE)?.ok_or_else(invalid)?;
    let browser_cookie = b::cookie_value(&headers, b::BROWSER_COOKIE)?.ok_or_else(invalid)?;
    let initial: store::Flow =
        sqlx::query_as("SELECT * FROM portal_login_flows WHERE state_hash=$1")
            .bind(b::digest(secret))
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(invalid)?;
    let mut tx = state.pool.begin().await?;
    let browser = store::browser(&mut *tx, &b::digest(browser_cookie), true)
        .await?
        .ok_or_else(invalid)?;
    let flow: store::Flow =
        sqlx::query_as("SELECT * FROM portal_login_flows WHERE id=$1 FOR UPDATE")
            .bind(initial.id)
            .fetch_one(&mut *tx)
            .await?;
    if browser.id != flow.browser_id
        || browser.generation != flow.browser_generation
        || !b::equal(&flow.binder_hash, &b::digest(binder))
        || flow.consumed_at.is_some()
    {
        return Err(invalid());
    }
    store::deadline(&mut tx, flow.expires_at).await?;
    sqlx::query("UPDATE portal_login_flows SET consumed_at=clock_timestamp() WHERE id=$1")
        .bind(flow.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if error {
        return Ok(Redirect::to("/?authenticationError=1").into_response());
    }
    let code = values
        .get("code")
        .filter(|c| !c.is_empty() && c.len() <= 2048)
        .ok_or_else(bad)?;
    let verifier = store::keys(&state)?.open(
        flow.id,
        &state.config.issuer,
        state.config.client_id,
        "login-verifier",
        &flow.verifier_ciphertext,
    )?;
    let chain = Chain::new(&state)?;
    let verified = protocol::exchange(&chain, code, &verifier, &flow.nonce_hash).await?;
    if flow.context_selection_required != state.config.context_selection_enabled
        || flow.context_selection_required != verified.selection.is_some()
    {
        return Err(invalid());
    }
    if let Some(selection) = &verified.selection {
        selection.validate(flow.id)?;
    }
    let cookie = b::secret()?;
    let id = Uuid::now_v7();
    let access = store::keys(&state)?.seal(
        id,
        &state.config.issuer,
        state.config.client_id,
        "oidc-access",
        &verified.access,
    )?;
    let refresh = store::keys(&state)?.seal(
        id,
        &state.config.issuer,
        state.config.client_id,
        "oidc-refresh",
        &verified.refresh,
    )?;
    let mut tx = state.pool.begin().await?;
    store::unrevoked_public_source(
        &mut tx,
        &state.config.issuer,
        state.config.client_id,
        &verified.public_sid,
    )
    .await?;
    let current = store::browser(&mut *tx, &b::digest(browser_cookie), true)
        .await?
        .ok_or_else(invalid)?;
    if current.id != flow.browser_id || current.generation != flow.browser_generation {
        return Err(AppError::conflict("其他登录已完成，本次回调不能覆盖新账号"));
    }
    let old_access = if let Some(old_id) = flow.switch_session_id {
        let old = store::session_id(&mut *tx, old_id, true)
            .await?
            .ok_or_else(invalid)?;
        if current.current_session_id != Some(old_id)
            || Some(old.version) != flow.switch_version
            || old.user_id != verified.proof.user_id
            || old.revoked_at.is_some()
            || old.expires_at <= Utc::now()
            || old.logout_request_id.is_some()
            || old.pending_selection_ciphertext.is_some()
        {
            return Err(AppError::conflict("原门户会话已失效或被其他标签页替换"));
        }
        Some(store::access(&state, &old)?)
    } else {
        None
    };
    let pending = crate::selection::pending_cipher(&state, id, &verified, old_access)?;
    if let Some(previous) = current.current_session_id {
        sqlx::query("UPDATE portal_sessions SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE id=$1").bind(previous).execute(&mut *tx).await?;
    }
    // Browser-row serialization makes versions monotonic across replacement
    // logins as well as selections. A delayed old reply can never share the
    // new session's public version merely because it uses the same account.
    let version: i64 = sqlx::query_scalar(
        "SELECT COALESCE(max(version),0)+1 FROM portal_sessions WHERE browser_id=$1",
    )
    .bind(current.id)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO portal_sessions(id,browser_id,token_hash,user_id,account_version,global_session_id,oidc_client_id,oidc_grant_id,oidc_client_policy_version,issuer,auth_time,nonce_hash,access_ciphertext,refresh_ciphertext,access_expires_at,version,created_at,expires_at,oidc_public_sid,oidc_public_sub) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$17,clock_timestamp(),$16,$18,$19)")
        .bind(id).bind(current.id).bind(b::digest(&cookie)).bind(verified.proof.user_id).bind(verified.proof.account_version).bind(verified.proof.global_session_id).bind(state.config.client_id)
        .bind(verified.proof.grant_id).bind(verified.proof.client_policy_version).bind(&state.config.issuer).bind(verified.proof.auth_time).bind(&flow.nonce_hash).bind(access).bind(refresh).bind(verified.proof.expires_at).bind(verified.absolute_expires_at).bind(version).bind(&verified.public_sid).bind(&verified.proof.subject).execute(&mut *tx).await?;
    sqlx::query("UPDATE portal_sessions SET pending_selection_ciphertext=$2 WHERE id=$1")
        .bind(id)
        .bind(pending)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE portal_browsers SET generation=generation+1,current_session_id=$2,expires_at=GREATEST(expires_at,$3) WHERE id=$1").bind(current.id).bind(id).bind(verified.absolute_expires_at).execute(&mut *tx).await?;
    store::deadline(
        &mut tx,
        verified
            .proof
            .expires_at
            .min(verified.id_expires_at)
            .min(verified.absolute_expires_at)
            .min(flow.expires_at),
    )
    .await?;
    tx.commit().await?;
    if flow.context_selection_required {
        let original = store::session_id(&state.pool, id, false)
            .await?
            .ok_or_else(invalid)?;
        // The new Cookie reaches the browser even if the remote commit or the
        // independent local save is uncertain. GET resumes this exact operation.
        let _ = crate::selection::resume(&state, original).await;
    }
    with_cookie(
        Redirect::to(&flow.return_path).into_response(),
        b::SESSION_COOKIE,
        &cookie,
        (verified.absolute_expires_at - Utc::now()).num_seconds(),
    )
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Selection {
    expected_version: String,
    membership_id: String,
}
async fn context(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
    body: Result<Json<Selection>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, AppError> {
    if state.config.context_selection_enabled {
        return Err(AppError::forbidden("请前往认证中心选择租户和组织"));
    }
    b::origin(&state, &headers, false)?;
    no_query(raw)?;
    let Json(body) = body.map_err(|_| bad())?;
    b::require_csrf(&headers, session_cookie(&headers)?)?;
    let original = authenticated(&state, &headers).await?;
    if original.version != b::version(&body.expected_version, 1)? {
        return Err(AppError::conflict("门户会话版本已变化"));
    }
    let chain = Chain::new(&state)?;
    let checked = store::online(&chain, original).await?;
    Ok(Json(
        usecases::select(
            &chain,
            checked,
            &body.expected_version,
            &body.membership_id,
            &b::csrf(session_cookie(&headers)?),
        )
        .await?,
    ))
}
async fn profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<Json<crate::resource::Profile>, AppError> {
    b::origin(&state, &headers, true)?;
    no_query(raw)?;
    let chain = Chain::new(&state)?;
    let checked = store::online(&chain, authenticated(&state, &headers).await?).await?;
    Ok(Json(usecases::profile(&chain, checked).await?))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Logout {
    expected_version: String,
    scope: String,
}
async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
    body: Result<Json<Logout>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, AppError> {
    b::origin(&state, &headers, false)?;
    no_query(raw)?;
    let Json(body) = body.map_err(|_| bad())?;
    if !matches!(body.scope.as_str(), "PORTAL" | "GLOBAL") {
        return Err(bad());
    }
    b::require_csrf(&headers, session_cookie(&headers)?)?;
    let original = authenticated(&state, &headers).await?;
    if original.version != b::version(&body.expected_version, 1)? {
        return Err(AppError::conflict("门户会话版本已变化"));
    }
    let chain = Chain::new(&state)?;
    let current = if original.logout_request_id.is_some() {
        original
    } else {
        let checked = store::online(&chain, original).await?;
        let request = Uuid::now_v7();
        let changed=sqlx::query("UPDATE portal_sessions s SET logout_request_id=$2,logout_scope=$3 WHERE s.id=$1 AND s.version=$4 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.access_expires_at>clock_timestamp() AND s.logout_request_id IS NULL AND s.refresh_lease_id IS NULL AND s.context_lease_id IS NULL AND NOT s.refresh_uncertain AND EXISTS(SELECT 1 FROM portal_browsers b WHERE b.id=s.browser_id AND b.current_session_id=s.id)")
            .bind(checked.id).bind(request).bind(&body.scope).bind(checked.version).execute(&state.pool).await?.rows_affected();
        if changed != 1 {
            return Err(AppError::conflict("门户注销目标已变化"));
        }
        store::session_id(&state.pool, checked.id, false)
            .await?
            .ok_or_else(invalid)?
    };
    finish_logout(&chain, current, &body.scope).await?;
    // No expiry Set-Cookie: a delayed response cannot erase a newer login.
    Ok(Json(json!({"redirectTo":"/signed-out"})))
}
async fn finish_logout(chain: &Chain<'_>, s: store::Session, scope: &str) -> Result<(), AppError> {
    if s.logout_scope.as_deref() != Some(scope) {
        return Err(AppError::conflict("已有不同范围的注销正在确认"));
    }
    if s.logout_confirmed_at.is_some() {
        let current: Option<Uuid> =
            sqlx::query_scalar("SELECT current_session_id FROM portal_browsers WHERE id=$1")
                .bind(s.browser_id)
                .fetch_one(&chain.state.pool)
                .await?;
        if current.is_some_and(|id| id != s.id) {
            return Err(AppError::conflict("旧注销回执不能覆盖新会话"));
        }
        return Ok(());
    }
    let pending = s.logout_request_id.ok_or(AppError::Unavailable)?;
    let refresh = store::keys(chain.state)?.open(
        s.id,
        &s.issuer,
        s.oidc_client_id,
        "oidc-refresh",
        &s.refresh_ciphertext,
    )?;
    // The OIDC revoke/global command is idempotent for this original RP grant.
    // After it succeeds, every opaque derived from that source is unusable.
    protocol::logout(chain, &s, &refresh, scope, pending).await?;
    let mut tx = chain.state.pool.begin().await?;
    let browser: store::Browser = sqlx::query_as(
        "SELECT id,generation,current_session_id FROM portal_browsers WHERE id=$1 FOR UPDATE",
    )
    .bind(s.browser_id)
    .fetch_one(&mut *tx)
    .await?;
    let current = store::session_id(&mut *tx, s.id, true)
        .await?
        .ok_or_else(invalid)?;
    if current.logout_request_id != Some(pending)
        || current.logout_scope.as_deref() != Some(scope)
        || current.version != s.version
    {
        return Err(invalid());
    }
    sqlx::query("UPDATE portal_sessions SET revoked_at=COALESCE(revoked_at,clock_timestamp()),logout_confirmed_at=clock_timestamp() WHERE id=$1").bind(s.id).execute(&mut *tx).await?;
    if browser.current_session_id == Some(s.id) {
        sqlx::query("UPDATE portal_browsers SET generation=generation+1,current_session_id=NULL WHERE id=$1 AND current_session_id=$2").bind(s.browser_id).bind(s.id).execute(&mut *tx).await?;
    }
    let replaced = browser.current_session_id.is_some_and(|id| id != s.id);
    tx.commit().await?;
    if replaced {
        return Err(AppError::conflict(
            "其他标签页已建立新会话，旧注销不能覆盖其状态",
        ));
    }
    Ok(())
}
