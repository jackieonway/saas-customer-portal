//! Strict relying-party validation. Offline signatures never replace online
//! user, global-session and registered-client authority.

use super::{
    store,
    transport::{Chain, Endpoint, OidcRequest, OidcResponse},
};
use crate::error::AppError;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

pub(crate) struct AccountProof {
    pub subject: String,
    pub user_id: Uuid,
    pub global_session_id: Uuid,
    pub grant_id: Uuid,
    pub account_version: i64,
    pub client_id: Uuid,
    pub client_policy_version: i64,
    pub auth_time: i64,
    pub expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
}
pub(crate) struct Verified {
    pub public_sid: String,
    pub selection: Option<crate::selection::Extension>,
    pub proof: AccountProof,
    pub access: String,
    pub refresh: String,
    pub absolute_expires_at: DateTime<Utc>,
    pub id_expires_at: DateTime<Utc>,
}
struct Identity {
    subject: String,
    public_sid: String,
    auth_time: i64,
    expires_at: DateTime<Utc>,
}

fn invalid() -> AppError {
    AppError::unauthorized("OIDC 认证响应无效，请重新登录")
}
pub(crate) fn opaque(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.bytes().all(|byte| byte.is_ascii_graphic())
}
fn object(value: &Value) -> Result<&serde_json::Map<String, Value>, AppError> {
    value.as_object().ok_or_else(invalid)
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, AppError> {
    value.get(key).and_then(Value::as_str).ok_or_else(invalid)
}
fn number(value: &Value, key: &str) -> Result<i64, AppError> {
    value.get(key).and_then(Value::as_i64).ok_or_else(invalid)
}
fn id(value: &str) -> Result<Uuid, AppError> {
    let id = crate::boundary::id(value).map_err(|_| invalid())?;
    if id.to_string() != value {
        return Err(invalid());
    }
    Ok(id)
}
fn generation(value: &str, min: i64) -> Result<i64, AppError> {
    let number = value.parse::<i64>().map_err(|_| invalid())?;
    if number < min || number.to_string() != value {
        return Err(invalid());
    }
    Ok(number)
}

fn json(response: OidcResponse) -> Result<Value, AppError> {
    if response.body.len() > 65536 {
        return Err(AppError::Unavailable);
    }
    let value: Value = serde_json::from_slice(&response.body).map_err(|_| AppError::Unavailable)?;
    if response.status != 200 {
        if response.status == 401 && value.get("error").is_none() {
            return Err(invalid());
        }
        return Err(match value.get("error").and_then(Value::as_str) {
            Some("invalid_grant" | "invalid_token" | "access_denied") => invalid(),
            _ => AppError::Unavailable,
        });
    }
    object(&value)?;
    Ok(value)
}
fn basic(chain: &Chain<'_>) -> Result<String, AppError> {
    let client = store::client(chain.state)?;
    let secret = chain.state.config.client_secret.as_str();
    Ok(format!(
        "Basic {}",
        STANDARD.encode(format!("{client}:{secret}"))
    ))
}
fn source_basic(chain: &Chain<'_>) -> Result<String, AppError> {
    let config = &chain.state.config;
    if !crate::boundary::canonical_secret(&config.source_service_secret) {
        return Err(AppError::Unavailable);
    }
    Ok(format!(
        "Basic {}",
        STANDARD.encode(format!(
            "{}:{}",
            config.source_service_id, config.source_service_secret
        ))
    ))
}
async fn call(
    chain: &Chain<'_>,
    endpoint: Endpoint,
    authorization: Option<String>,
    form: Vec<(String, String)>,
) -> Result<Value, AppError> {
    json(
        chain
            .send(OidcRequest {
                json: None,
                endpoint,
                authorization,
                form,
            })
            .await?,
    )
}

pub(crate) async fn discovery(chain: &Chain<'_>) -> Result<(), AppError> {
    let issuer = store::issuer(chain.state)?;
    let document = call(chain, Endpoint::Discovery, None, vec![]).await?;
    if text(&document, "issuer")? != issuer {
        return Err(AppError::Unavailable);
    }
    for (name, endpoint) in [
        ("authorization_endpoint", "/oauth/authorize"),
        ("token_endpoint", "/oauth/token"),
        ("jwks_uri", "/oauth/jwks"),
        ("userinfo_endpoint", "/oauth/userinfo"),
        ("introspection_endpoint", "/oauth/introspect"),
        ("revocation_endpoint", "/oauth/revoke"),
    ] {
        if document.get(name).and_then(Value::as_str)
            != Some(format!("{issuer}{endpoint}").as_str())
        {
            return Err(AppError::Unavailable);
        }
    }
    for (name, required) in [
        ("response_types_supported", "code"),
        ("id_token_signing_alg_values_supported", "RS256"),
        (
            "token_endpoint_auth_methods_supported",
            "client_secret_basic",
        ),
        ("code_challenge_methods_supported", "S256"),
    ] {
        if !document
            .get(name)
            .and_then(Value::as_array)
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(required)))
        {
            return Err(AppError::Unavailable);
        }
    }
    Ok(())
}

pub(crate) async fn signing_key(chain: &Chain<'_>, token: &str) -> Result<DecodingKey, AppError> {
    if token.len() > 16384 {
        return Err(invalid());
    }
    let header = jsonwebtoken::decode_header(token).map_err(|_| invalid())?;
    if header.alg != Algorithm::RS256 {
        return Err(invalid());
    }
    let kid = header
        .kid
        .as_deref()
        .filter(|kid| {
            !kid.is_empty()
                && kid.len() <= 80
                && kid
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        })
        .ok_or_else(invalid)?;
    let jwks = call(chain, Endpoint::Jwks, None, vec![]).await?;
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .filter(|keys| !keys.is_empty() && keys.len() <= 32)
        .ok_or_else(invalid)?;
    let mut seen = std::collections::HashSet::new();
    let mut matching = None;
    for key in keys {
        let key_id = text(key, "kid")?;
        if !seen.insert(key_id) {
            return Err(invalid());
        }
        if ["d", "p", "q", "dp", "dq", "qi", "k", "privateKeyPem"]
            .iter()
            .any(|name| key.get(*name).is_some())
        {
            return Err(invalid());
        }
        if key_id == kid {
            matching = Some(key);
        }
    }
    let key = matching.ok_or_else(invalid)?;
    if text(key, "kty")? != "RSA"
        || text(key, "alg")? != "RS256"
        || text(key, "use")? != "sig"
        || text(key, "e")? != "AQAB"
    {
        return Err(invalid());
    }
    let n = text(key, "n")?;
    let modulus = URL_SAFE_NO_PAD.decode(n).map_err(|_| invalid())?;
    let bits = modulus
        .first()
        .map(|first| modulus.len() * 8 - first.leading_zeros() as usize)
        .unwrap_or(0);
    if !(2048..=4096).contains(&bits)
        || modulus.first() == Some(&0)
        || URL_SAFE_NO_PAD.encode(&modulus) != n
    {
        return Err(invalid());
    }
    DecodingKey::from_rsa_components(n, "AQAB").map_err(|_| invalid())
}

async fn identity(chain: &Chain<'_>, token: &str, nonce_hash: &str) -> Result<Identity, AppError> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| invalid())?;
    if header.typ.as_deref() != Some("JWT") {
        return Err(invalid());
    }
    let decoding = signing_key(chain, token).await?;
    let client = store::client(chain.state)?.to_string();
    let issuer = store::issuer(chain.state)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = 60;
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[client.as_str()]);
    validation.set_required_spec_claims(&[
        "iss",
        "sub",
        "sid",
        "aud",
        "exp",
        "iat",
        "nonce",
        "auth_time",
    ]);
    let claims = jsonwebtoken::decode::<Value>(token, &decoding, &validation)
        .map_err(|_| invalid())?
        .claims;
    if text(&claims, "iss")? != issuer
        || text(&claims, "aud")? != client
        || !crate::boundary::equal(
            &crate::boundary::digest(text(&claims, "nonce")?),
            nonce_hash,
        )
        || claims
            .get("azp")
            .is_some_and(|azp| azp.as_str() != Some(client.as_str()))
    {
        return Err(invalid());
    }
    let now = Utc::now().timestamp();
    let iat = number(&claims, "iat")?;
    let exp = number(&claims, "exp")?;
    let auth_time = number(&claims, "auth_time")?;
    if iat <= 0
        || iat > now + 60
        || exp <= iat
        || exp - iat > 660
        || exp <= now
        || auth_time <= 0
        || auth_time > iat + 60
        || auth_time > now + 60
    {
        return Err(invalid());
    }
    let expires_at = DateTime::from_timestamp(exp, 0).ok_or_else(invalid)?;
    let subject = text(&claims, "sub")?;
    let public_sid = text(&claims, "sid")?;
    if !opaque(subject) || !crate::boundary::canonical_secret(public_sid) {
        return Err(invalid());
    }
    Ok(Identity {
        subject: subject.to_owned(),
        public_sid: public_sid.to_owned(),
        auth_time,
        expires_at,
    })
}

async fn inspect(chain: &Chain<'_>, token: &str) -> Result<AccountProof, AppError> {
    if !crate::boundary::canonical_secret(token) {
        return Err(invalid());
    }
    let value = json(
        chain
            .send(OidcRequest {
                endpoint: Endpoint::AccountProof,
                authorization: Some(source_basic(chain)?),
                form: vec![],
                json: Some(
                    serde_json::json!({"contractVersion":"customer-account-proof-request/1",
            "expectedClientId":store::client(chain.state)?,"oidcAccessToken":token}),
                ),
            })
            .await?,
    )?;
    let client = store::client(chain.state)?;
    if text(&value, "contractVersion")? != "customer-account-proof/1"
        || text(&value, "clientId")? != client.to_string()
        || text(&value, "issuer")? != store::issuer(chain.state)?
        || text(&value, "clientPurpose")? != "CUSTOMER_PORTAL"
        || text(&value, "contextMode")? != "PLATFORM_CONTEXT"
        || value.get("allowedMemberTypes") != Some(&serde_json::json!(["CUSTOMER"]))
        || value
            .get("scope")
            .and_then(Value::as_array)
            .is_none_or(|scopes| {
                scopes.len() != 2
                    || !["openid", "profile"]
                        .iter()
                        .all(|required| scopes.iter().any(|scope| scope.as_str() == Some(required)))
            })
    {
        return Err(invalid());
    }
    let subject = text(&value, "sub")?;
    let auth_time = number(&value, "authTime")?;
    let now = Utc::now();
    if subject.is_empty()
        || subject.len() > 256
        || subject.chars().any(char::is_control)
        || auth_time <= 0
        || auth_time > now.timestamp() + 60
    {
        return Err(invalid());
    }
    let expires_at = DateTime::parse_from_rfc3339(text(&value, "expiresAt")?)
        .map(|value| value.with_timezone(&Utc))
        .ok()
        .filter(|expires| *expires > now)
        .ok_or_else(invalid)?;
    let absolute_expires_at = DateTime::parse_from_rfc3339(text(&value, "absoluteExpiresAt")?)
        .map(|value| value.with_timezone(&Utc))
        .ok()
        .filter(|expires| *expires >= expires_at)
        .ok_or_else(invalid)?;
    generation(text(&value, "applicationProjectionVersion")?, 1)?;
    Ok(AccountProof {
        subject: subject.to_owned(),
        user_id: id(text(&value, "userId")?)?,
        global_session_id: id(text(&value, "globalSessionId")?)?,
        grant_id: id(text(&value, "grantId")?)?,
        account_version: generation(text(&value, "accountVersion")?, 1)?,
        client_id: client,
        client_policy_version: generation(text(&value, "clientPolicyVersion")?, 1)?,
        auth_time,
        expires_at,
        absolute_expires_at,
    })
}
fn same(proof: &AccountProof, session: &store::Session) -> Result<(), AppError> {
    if proof.subject != session.oidc_public_sub
        || proof.user_id != session.user_id
        || proof.global_session_id != session.global_session_id
        || proof.grant_id != session.oidc_grant_id
        || proof.account_version != session.account_version
        || proof.client_id != session.oidc_client_id
        || proof.client_policy_version != session.oidc_client_policy_version
        || proof.auth_time != session.auth_time
    {
        return Err(invalid());
    }
    Ok(())
}
async fn userinfo(chain: &Chain<'_>, access: &str, subject: &str) -> Result<(), AppError> {
    let value = call(
        chain,
        Endpoint::UserInfo,
        Some(format!("Bearer {access}")),
        vec![],
    )
    .await?;
    if text(&value, "sub")? != subject {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) async fn existing(
    chain: &Chain<'_>,
    session: &store::Session,
    access: &str,
) -> Result<AccountProof, AppError> {
    let proof = inspect(chain, access).await?;
    same(&proof, session)?;
    userinfo(chain, access, &proof.subject).await?;
    Ok(proof)
}

async fn verified(
    chain: &Chain<'_>,
    response: Value,
    nonce_hash: &str,
    original: Option<&store::Session>,
) -> Result<Verified, AppError> {
    let access = text(&response, "access_token")?.to_owned();
    let refresh = text(&response, "refresh_token")?.to_owned();
    if !crate::boundary::canonical_secret(&access)
        || !crate::boundary::canonical_secret(&refresh)
        || text(&response, "token_type")? != "Bearer"
        || !(1..=600).contains(&number(&response, "expires_in")?)
    {
        return Err(invalid());
    }
    let scopes = text(&response, "scope")?;
    if ["openid", "profile"]
        .iter()
        .any(|required| !scopes.split_whitespace().any(|scope| scope == *required))
        || scopes.split_whitespace().count() != 2
    {
        return Err(invalid());
    }
    let identity = match response.get("id_token") {
        Some(value) => {
            Some(identity(chain, value.as_str().ok_or_else(invalid)?, nonce_hash).await?)
        }
        None => None,
    };
    if original.is_none() && identity.is_none() {
        return Err(invalid());
    }
    let mut proof = inspect(chain, &access).await?;
    if identity.as_ref().is_some_and(|identity| {
        identity.subject != proof.subject || identity.auth_time != proof.auth_time
    }) {
        return Err(invalid());
    }
    if let Some(original) = original {
        same(&proof, original)?;
        if identity.as_ref().is_some_and(|identity| {
            identity.public_sid != original.oidc_public_sid
                || identity.subject != original.oidc_public_sub
        }) {
            return Err(invalid());
        }
    }
    userinfo(chain, &access, &proof.subject).await?;
    let public_sid = identity
        .as_ref()
        .map(|identity| identity.public_sid.clone())
        .or_else(|| original.map(|session| session.oidc_public_sid.clone()))
        .ok_or_else(invalid)?;
    let id_expires_at = identity
        .map(|identity| identity.expires_at)
        .unwrap_or(proof.expires_at);
    proof.expires_at = proof.expires_at.min(id_expires_at);
    let absolute_expires_at = proof.absolute_expires_at;
    Ok(Verified {
        public_sid,
        selection: if original.is_none() {
            response
                .get("context_selection")
                .map(|v| serde_json::from_value(v.clone()).map_err(|_| invalid()))
                .transpose()?
        } else {
            if response.get("context_selection").is_some() {
                return Err(invalid());
            }
            None
        },
        proof,
        access,
        refresh,
        absolute_expires_at,
        id_expires_at,
    })
}

pub(crate) async fn exchange(
    chain: &Chain<'_>,
    code: &str,
    verifier: &str,
    nonce_hash: &str,
) -> Result<Verified, AppError> {
    discovery(chain).await?;
    let redirect = chain.state.config.redirect_uri.as_str();
    let value = call(
        chain,
        Endpoint::Token,
        Some(basic(chain)?),
        vec![
            ("grant_type".into(), "authorization_code".into()),
            ("code".into(), code.into()),
            ("redirect_uri".into(), redirect.into()),
            ("code_verifier".into(), verifier.into()),
        ],
    )
    .await?;
    verified(chain, value, nonce_hash, None).await
}
pub(crate) async fn refresh(
    chain: &Chain<'_>,
    original: &store::Session,
    refresh: &str,
) -> Result<Verified, AppError> {
    // Only the token endpoint consumes a refresh credential. Its atomic family
    // rotation rechecks the original source; private proofs accept access only.
    discovery(chain).await?;
    let value = call(
        chain,
        Endpoint::Token,
        Some(basic(chain)?),
        vec![
            ("grant_type".into(), "refresh_token".into()),
            ("refresh_token".into(), refresh.into()),
        ],
    )
    .await?;
    verified(chain, value, &original.nonce_hash, Some(original)).await
}
pub(crate) async fn logout(
    chain: &Chain<'_>,
    session: &store::Session,
    refresh: &str,
    scope: &str,
    request: Uuid,
) -> Result<(), AppError> {
    if session.issuer != store::issuer(chain.state)?
        || session.oidc_client_id != store::client(chain.state)?
    {
        return Err(invalid());
    }
    let scope = match scope {
        "GLOBAL" => "GLOBAL",
        "PORTAL" => "CURRENT_APP",
        _ => return Err(invalid()),
    };
    if !crate::boundary::canonical_secret(&session.oidc_public_sid)
        || !opaque(&session.oidc_public_sub)
    {
        return Err(invalid());
    }
    let form = vec![
        ("token".into(), refresh.into()),
        ("scope".into(), scope.into()),
        ("operation_id".into(), request.to_string()),
        ("sid".into(), session.oidc_public_sid.clone()),
        ("sub".into(), session.oidc_public_sub.clone()),
    ];
    // The original refresh can already be revoked or expired. Recovery proves
    // the caller's exact original binding without re-authorizing a new grant.
    let recovered = chain
        .send(OidcRequest {
            json: None,
            endpoint: Endpoint::LogoutOperation(request),
            authorization: Some(basic(chain)?),
            form: form.clone(),
        })
        .await?;
    let response = if recovered.status == 404 {
        let missing: Value =
            serde_json::from_slice(&recovered.body).map_err(|_| AppError::Unavailable)?;
        if missing.get("code").and_then(Value::as_str) != Some("NOT_FOUND") {
            return Err(AppError::Unavailable);
        }
        chain
            .send(OidcRequest {
                json: None,
                endpoint: Endpoint::GlobalLogout,
                authorization: Some(basic(chain)?),
                form,
            })
            .await?
    } else {
        recovered
    };
    if response.status != 200 {
        json(response)?;
        return Err(AppError::Unavailable);
    }
    if response.body.len() > 65536 {
        return Err(AppError::Unavailable);
    }
    let completed: LogoutReceipt =
        serde_json::from_slice(&response.body).map_err(|_| AppError::Unavailable)?;
    if completed.operation_id != request.to_string()
        || completed.scope != scope
        || completed.state != "COMPLETED"
        || completed.revoked_grant_count < 0
        || completed.revoked_sso_count < 0
        || completed.notification_count < 0
    {
        return Err(AppError::Unavailable);
    }
    // Keep the original caller-owned identity in this command; never derive a
    // fresh account or sid from the result of its own revocation.
    if session.oidc_client_id != store::client(chain.state)? {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogoutReceipt {
    operation_id: String,
    scope: String,
    state: String,
    revoked_grant_count: i64,
    revoked_sso_count: i64,
    notification_count: i64,
}
