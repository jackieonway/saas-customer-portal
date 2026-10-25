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
use serde_json::Value;
use uuid::Uuid;

pub(crate) struct AccountProof {
    pub user_id: Uuid,
    pub global_session_id: Uuid,
    pub grant_id: Uuid,
    pub account_version: i64,
    pub client_id: Uuid,
    pub client_policy_version: i64,
    pub auth_time: i64,
    pub expires_at: DateTime<Utc>,
}
pub(crate) struct Verified {
    pub proof: AccountProof,
    pub access: String,
    pub refresh: String,
    pub absolute_expires_at: DateTime<Utc>,
    pub id_expires_at: DateTime<Utc>,
}
struct Identity {
    user_id: Uuid,
    sid: Uuid,
    auth_time: i64,
    expires_at: DateTime<Utc>,
}

fn invalid() -> AppError {
    AppError::unauthorized("OIDC 认证响应无效，请重新登录")
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
async fn call(
    chain: &Chain<'_>,
    endpoint: Endpoint,
    authorization: Option<String>,
    form: Vec<(String, String)>,
) -> Result<Value, AppError> {
    json(
        chain
            .send(OidcRequest {
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
        ("authorization_endpoint", "/oidc/authorize"),
        ("token_endpoint", "/oidc/token"),
        ("jwks_uri", "/oidc/jwks"),
        ("userinfo_endpoint", "/oidc/userinfo"),
        ("introspection_endpoint", "/oidc/introspect"),
        ("revocation_endpoint", "/oidc/revoke"),
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

async fn identity(chain: &Chain<'_>, token: &str, nonce_hash: &str) -> Result<Identity, AppError> {
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
    let decoding = DecodingKey::from_rsa_components(n, "AQAB").map_err(|_| invalid())?;
    let client = store::client(chain.state)?.to_string();
    let issuer = store::issuer(chain.state)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = 60;
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[client.as_str()]);
    validation.set_required_spec_claims(&[
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "nonce",
        "auth_time",
        "sid",
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
    Ok(Identity {
        user_id: id(text(&claims, "sub")?)?,
        sid: id(text(&claims, "sid")?)?,
        auth_time,
        expires_at,
    })
}

async fn inspect(chain: &Chain<'_>, token: &str) -> Result<AccountProof, AppError> {
    let value = call(
        chain,
        Endpoint::Introspect,
        Some(basic(chain)?),
        vec![("token".into(), token.into())],
    )
    .await?;
    if value.get("active").and_then(Value::as_bool) != Some(true) {
        return Err(invalid());
    }
    let client = store::client(chain.state)?;
    if text(&value, "client_id")? != client.to_string()
        || text(&value, "aud")? != client.to_string()
        || text(&value, "iss")? != store::issuer(chain.state)?
        || text(&value, "token_type")? != "Bearer"
        || !text(&value, "scope")?
            .split_whitespace()
            .any(|scope| scope == "openid")
    {
        return Err(invalid());
    }
    let projection = value.get("accountProof").ok_or_else(invalid)?;
    if text(projection, "contractVersion")? != "oidc-account-proof/1"
        || text(projection, "clientPurpose")? != "CUSTOMER_PORTAL"
        || projection.get("allowedMemberTypes") != Some(&serde_json::json!(["CUSTOMER"]))
    {
        return Err(invalid());
    }
    let expires_at = DateTime::from_timestamp(number(&value, "exp")?, 0)
        .filter(|expires| *expires > Utc::now())
        .ok_or_else(invalid)?;
    Ok(AccountProof {
        user_id: id(text(&value, "sub")?)?,
        global_session_id: id(text(&value, "sid")?)?,
        grant_id: id(text(projection, "grantId")?)?,
        account_version: generation(text(projection, "accountVersion")?, 0)?,
        client_id: client,
        client_policy_version: generation(text(projection, "clientPolicyVersion")?, 1)?,
        auth_time: number(projection, "authTime")?,
        expires_at,
    })
}
fn same(proof: &AccountProof, session: &store::Session) -> Result<(), AppError> {
    if proof.user_id != session.user_id
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
async fn userinfo(chain: &Chain<'_>, access: &str, user: Uuid) -> Result<(), AppError> {
    let value = call(
        chain,
        Endpoint::UserInfo,
        Some(format!("Bearer {access}")),
        vec![],
    )
    .await?;
    if id(text(&value, "sub")?)? != user {
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
    userinfo(chain, access, session.user_id).await?;
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
    if ["openid", "profile", "offline_access"]
        .iter()
        .any(|required| !scopes.split_whitespace().any(|scope| scope == *required))
    {
        return Err(invalid());
    }
    let identity = identity(chain, text(&response, "id_token")?, nonce_hash).await?;
    let mut proof = inspect(chain, &access).await?;
    let refresh_proof = inspect(chain, &refresh).await?;
    if identity.user_id != proof.user_id
        || identity.sid != proof.global_session_id
        || identity.auth_time != proof.auth_time
        || refresh_proof.user_id != proof.user_id
        || refresh_proof.global_session_id != proof.global_session_id
        || refresh_proof.grant_id != proof.grant_id
        || refresh_proof.account_version != proof.account_version
        || refresh_proof.client_policy_version != proof.client_policy_version
        || refresh_proof.auth_time != proof.auth_time
        || refresh_proof.expires_at < proof.expires_at
    {
        return Err(invalid());
    }
    if let Some(original) = original {
        same(&proof, original)?;
    }
    userinfo(chain, &access, proof.user_id).await?;
    proof.expires_at = proof.expires_at.min(identity.expires_at);
    Ok(Verified {
        proof,
        access,
        refresh,
        absolute_expires_at: refresh_proof.expires_at,
        id_expires_at: identity.expires_at,
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
    // The still-live refresh credential is an online deny-only source proof.
    // An expired access token cannot authorize a request or justify a retry.
    let before = inspect(chain, refresh).await?;
    same(&before, original)?;
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
    let endpoint = if scope == "GLOBAL" {
        Endpoint::GlobalLogout
    } else {
        Endpoint::Revoke
    };
    let mut form = vec![("token".into(), refresh.into())];
    if scope == "GLOBAL" {
        form.push(("request_id".into(), request.to_string()));
    }
    let response = chain
        .send(OidcRequest {
            endpoint,
            authorization: Some(basic(chain)?),
            form,
        })
        .await?;
    if response.status != 200 {
        json(response)?;
        return Err(AppError::Unavailable);
    }
    // Keep the original caller-owned identity in this command; never derive a
    // fresh account or sid from the result of its own revocation.
    if session.oidc_client_id != store::client(chain.state)? {
        return Err(invalid());
    }
    Ok(())
}
