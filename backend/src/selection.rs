//! Durable pending selection. Only backend-encrypted state can resume a result.
use crate::{
    boundary as b,
    error::AppError,
    protocol, resource, store,
    transport::{Chain, Endpoint, OidcRequest},
    AppState,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Extension {
    pub contract_version: String,
    pub transaction_id: String,
    pub credential: String,
}
impl Extension {
    pub fn validate(&self, flow: Uuid) -> Result<(), AppError> {
        if self.contract_version != "context-selection/1"
            || b::id(&self.transaction_id)? != flow
            || !b::canonical_secret(&self.credential)
        {
            return Err(b::invalid());
        }
        Ok(())
    }
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Pending {
    pub extension: Extension,
    pub old_access: Option<String>,
}

pub(crate) async fn create(
    chain: &Chain<'_>,
    flow: Uuid,
    state_hash: &str,
    nonce_hash: &str,
    challenge: &str,
    old: Option<&store::Session>,
) -> Result<String, AppError> {
    let config = &chain.state.config;
    let response=chain.send(OidcRequest{endpoint:Endpoint::ContextInteractions,authorization:Some(format!("Basic {}",STANDARD.encode(format!("{}:{}",config.client_id,config.client_secret)))),form:vec![],
        json:Some(json!({"contractVersion":"context-selection/1","transactionId":flow,"intent":old.map_or(json!({"kind":"LOGIN"}),|s|json!({"kind":"SWITCH","sessionId":s.id,"expectedVersion":s.version.to_string()})),"redirectUri":config.redirect_uri,"stateHash":state_hash,"nonceHash":nonce_hash,"codeChallenge":challenge}))}).await?;
    if response.status != 200 {
        return Err(AppError::Unavailable);
    }
    let value: Value = serde_json::from_slice(&response.body).map_err(|_| AppError::Unavailable)?;
    let expires = value["expiresAt"]
        .as_str()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
        .ok_or(AppError::Unavailable)?;
    if value["contractVersion"] != "context-selection/1" || expires <= chrono::Utc::now() {
        return Err(AppError::Unavailable);
    }
    let reference = value["contextRequest"]
        .as_str()
        .filter(|s| b::canonical_secret(s))
        .ok_or(AppError::Unavailable)?;
    Ok(reference.to_owned())
}

async fn call(
    chain: &Chain<'_>,
    s: &store::Session,
    pending: &Pending,
    endpoint: Endpoint,
) -> Result<Value, AppError> {
    let config = &chain.state.config;
    let response=chain.send(OidcRequest{endpoint,authorization:Some(format!("Basic {}",STANDARD.encode(format!("{}:{}",config.selection_client_id,config.selection_client_secret)))),form:vec![],
        json:Some(json!({"contractVersion":pending.extension.contract_version,"transactionId":pending.extension.transaction_id,"credential":pending.extension.credential,
            "expectedClientId":s.oidc_client_id,"oidcAccessToken":store::access(chain.state,s)?,"bffSessionId":s.id,"version":s.version.to_string(),"oldOidcAccessToken":pending.old_access}))}).await?;
    if response.status != 200 {
        return Err(match response.status {
            401 | 403 | 410 => b::invalid(),
            409 => AppError::conflict("选择结果需要重新检查"),
            _ => AppError::Unavailable,
        });
    }
    serde_json::from_slice(&response.body).map_err(|_| AppError::Unavailable)
}

pub(crate) async fn resume(
    state: &AppState,
    s: store::Session,
) -> Result<store::Session, AppError> {
    let Some(encrypted) = s.pending_selection_ciphertext.as_deref() else {
        return Ok(s);
    };
    if !state.config.context_selection_enabled || s.access_expires_at <= chrono::Utc::now() {
        return Err(b::invalid());
    }
    let raw = store::keys(state)?.open(
        s.id,
        &s.issuer,
        s.oidc_client_id,
        "pending-selection",
        encrypted,
    )?;
    let pending: Pending = serde_json::from_str(&raw).map_err(|_| AppError::Unavailable)?;
    pending
        .extension
        .validate(b::id(&pending.extension.transaction_id)?)?;
    let chain = Chain::new(state)?;
    let mut value = call(&chain, &s, &pending, Endpoint::SelectionResult).await?;
    if value["status"] == "PENDING" {
        value = match call(&chain, &s, &pending, Endpoint::SelectionConsume).await {
            Ok(value) => value,
            Err(AppError::Conflict(_)) => {
                call(&chain, &s, &pending, Endpoint::SelectionResult).await?
            }
            Err(error) => return Err(error),
        };
    }
    if value["status"] != "COMMITTED" {
        return Err(AppError::Unavailable);
    }
    value
        .as_object_mut()
        .ok_or(AppError::Unavailable)?
        .remove("status");
    let mut issued: resource::Issued =
        serde_json::from_value(value).map_err(|_| AppError::Unavailable)?;
    issued.expires_at = issued.expires_at.min(s.access_expires_at);
    let m = resource::Membership {
        membership_id: issued.context.membership_id,
        user_id: s.user_id,
        member_type: "CUSTOMER".into(),
        identity_version: issued.context.identity_version.clone(),
        organization_id: issued.context.organization.id,
        organization_name: issued.context.organization.name.clone(),
        tenant_id: issued.context.tenant.id,
        tenant_name: issued.context.tenant.name.clone(),
    };
    resource::context_matches(&issued.context, &s, &m)?;
    if issued.account.id != s.user_id
        || !issued
            .customer_context
            .strip_prefix("cpc_")
            .is_some_and(b::canonical_secret)
        || issued.expires_at <= chrono::Utc::now()
        || issued.expires_at > s.access_expires_at
    {
        return Err(b::invalid());
    }
    let identity_version = b::version(&m.identity_version, 1)?;
    let context = store::keys(state)?.seal(
        s.id,
        &s.issuer,
        s.oidc_client_id,
        "customer-context",
        &issued.customer_context,
    )?;
    let current:Option<store::Session>=sqlx::query_as("UPDATE portal_sessions s SET membership_id=$4,organization_id=$5,identity_version=$6,customer_ciphertext=$7,customer_expires_at=$8,customer_needs_renewal=false,pending_selection_ciphertext=NULL WHERE s.id=$1 AND s.version=$2 AND s.pending_selection_ciphertext=$3 AND s.access_ciphertext=$9 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.access_expires_at>clock_timestamp() AND $8::timestamptz>clock_timestamp() AND s.logout_request_id IS NULL AND s.refresh_lease_id IS NULL AND NOT s.refresh_uncertain AND EXISTS(SELECT 1 FROM portal_browsers b WHERE b.id=s.browser_id AND b.current_session_id=s.id AND b.expires_at>clock_timestamp()) RETURNING s.*")
        .bind(s.id).bind(s.version).bind(encrypted).bind(m.membership_id).bind(m.organization_id).bind(identity_version).bind(context).bind(issued.expires_at).bind(&s.access_ciphertext).fetch_optional(&state.pool).await?;
    current.ok_or_else(|| AppError::conflict("其他门户操作已完成，请重新检查"))
}

pub(crate) fn pending_cipher(
    state: &AppState,
    id: Uuid,
    verified: &protocol::Verified,
    old_access: Option<String>,
) -> Result<Option<String>, AppError> {
    match &verified.selection {
        Some(extension) => {
            let value = json!({"extension":extension,"oldAccess":old_access});
            Ok(Some(store::keys(state)?.seal(
                id,
                &state.config.issuer,
                state.config.client_id,
                "pending-selection",
                &value.to_string(),
            )?))
        }
        None => Ok(None),
    }
}
