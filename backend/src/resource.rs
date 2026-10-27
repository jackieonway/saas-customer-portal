//! Customer-only resource protocol. Browser input never supplies organization,
//! source account, application, tenant or identity generation.
use crate::{
    boundary::{self, invalid},
    error::AppError,
    store::Session,
    transport::{Chain, Endpoint, OidcRequest},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Account {
    pub id: Uuid,
    pub username: String,
    pub real_name: String,
    pub avatar: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Membership {
    pub membership_id: Uuid,
    pub user_id: Uuid,
    pub member_type: String,
    pub identity_version: String,
    pub organization_id: Uuid,
    pub organization_name: String,
    pub tenant_id: Uuid,
    pub tenant_name: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Source {
    issuer: String,
    client_id: Uuid,
    grant_id: Uuid,
    global_session_id: Uuid,
    user_id: Uuid,
    account_version: String,
    client_policy_version: String,
    auth_time: i64,
    expires_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Memberships {
    contract_version: String,
    pub account: Account,
    pub memberships: Vec<Membership>,
    source: Source,
}
impl Memberships {
    pub(crate) fn deadline(&self) -> DateTime<Utc> {
        self.source.expires_at
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Named {
    pub id: Uuid,
    pub name: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Application {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub entry_path: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub contract_version: String,
    pub purpose: String,
    pub user_id: Uuid,
    pub membership_id: Uuid,
    pub member_type: String,
    pub identity_version: String,
    pub account_version: String,
    pub tenant: Named,
    pub organization: Named,
    pub application: Application,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Profile {
    pub context: Context,
    pub account: Account,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Issued {
    pub customer_context: String,
    pub expires_at: DateTime<Utc>,
    pub context: Context,
    pub account: Account,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revoked {
    revoked: bool,
}

async fn call<T: serde::de::DeserializeOwned>(
    chain: &Chain<'_>,
    endpoint: Endpoint,
    form: Vec<(String, String)>,
) -> Result<T, AppError> {
    let c = &chain.state.config;
    let response = chain
        .send(OidcRequest {
            json: None,
            endpoint,
            authorization: Some(format!(
                "Basic {}",
                STANDARD.encode(format!(
                    "{}:{}",
                    c.resource_client_id, c.resource_client_secret
                ))
            )),
            form,
        })
        .await?;
    if response.status != 200 {
        return Err(match response.status {
            401 | 403 => invalid(),
            400 => AppError::bad_request("客户资料请求无效"),
            409 => AppError::conflict("客户身份已变化"),
            _ => AppError::Unavailable,
        });
    }
    if response.body.len() > 65536 {
        return Err(AppError::Unavailable);
    }
    serde_json::from_slice(&response.body).map_err(|_| AppError::Unavailable)
}
fn uuid(id: Uuid) -> Result<(), AppError> {
    boundary::id(&id.to_string())
        .map(|_| ())
        .map_err(|_| invalid())
}
fn account(account: &Account, s: &Session) -> Result<(), AppError> {
    if account.id != s.user_id
        || account.username.len() > 256
        || account.real_name.len() > 256
        || account.avatar.len() > 4096
    {
        return Err(invalid());
    }
    uuid(account.id)
}
fn source(source: &Source, s: &Session) -> Result<(), AppError> {
    if source.issuer != s.issuer
        || source.client_id != s.oidc_client_id
        || source.grant_id != s.oidc_grant_id
        || source.global_session_id != s.global_session_id
        || source.user_id != s.user_id
        || source.account_version != s.account_version.to_string()
        || source.client_policy_version != s.oidc_client_policy_version.to_string()
        || source.auth_time != s.auth_time
        || source.expires_at <= Utc::now()
    {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) async fn memberships(
    chain: &Chain<'_>,
    s: &Session,
    access: &str,
) -> Result<Memberships, AppError> {
    let result: Memberships = call(
        chain,
        Endpoint::Memberships,
        vec![("oidcAccessToken".into(), access.into())],
    )
    .await?;
    if result.contract_version != "customer-portal-account/1" || result.memberships.len() > 512 {
        return Err(invalid());
    }
    source(&result.source, s)?;
    account(&result.account, s)?;
    let mut seen = std::collections::HashSet::new();
    for m in &result.memberships {
        if m.user_id != s.user_id || m.member_type != "CUSTOMER" || !seen.insert(m.membership_id) {
            return Err(invalid());
        }
        for id in [m.membership_id, m.user_id, m.organization_id, m.tenant_id] {
            uuid(id)?;
        }
        boundary::version(&m.identity_version, 1).map_err(|_| invalid())?;
    }
    Ok(result)
}
pub(crate) fn context_matches(c: &Context, s: &Session, m: &Membership) -> Result<(), AppError> {
    if c.contract_version != "customer-profile/1"
        || c.purpose != "CUSTOMER_PROFILE"
        || c.user_id != s.user_id
        || c.membership_id != m.membership_id
        || c.member_type != "CUSTOMER"
        || c.identity_version != m.identity_version
        || c.account_version != s.account_version.to_string()
        || c.organization.id != m.organization_id
        || c.tenant.id != m.tenant_id
        || c.application.entry_path != "/api/customer/profile"
    {
        return Err(invalid());
    }
    for id in [
        c.user_id,
        c.membership_id,
        c.organization.id,
        c.tenant.id,
        c.application.id,
    ] {
        uuid(id)?;
    }
    Ok(())
}
pub(crate) async fn issue(
    chain: &Chain<'_>,
    s: &Session,
    access: &str,
    m: &Membership,
) -> Result<Issued, AppError> {
    let mut result: Issued = call(
        chain,
        Endpoint::Context,
        vec![
            ("oidcAccessToken".into(), access.into()),
            ("membershipId".into(), m.membership_id.to_string()),
            ("organizationId".into(), m.organization_id.to_string()),
            ("expectedIdentityVersion".into(), m.identity_version.clone()),
        ],
    )
    .await?;
    if !result
        .customer_context
        .strip_prefix("cpc_")
        .is_some_and(boundary::canonical_secret)
        || result.expires_at <= Utc::now()
    {
        return Err(invalid());
    }
    result.expires_at = result.expires_at.min(s.access_expires_at);
    context_matches(&result.context, s, m)?;
    account(&result.account, s)?;
    Ok(result)
}
pub(crate) async fn profile(
    chain: &Chain<'_>,
    s: &Session,
    access: &str,
    context: &str,
    m: &Membership,
) -> Result<Profile, AppError> {
    let result: Profile = call(
        chain,
        Endpoint::Profile,
        vec![
            ("oidcAccessToken".into(), access.into()),
            ("customerContext".into(), context.into()),
        ],
    )
    .await?;
    context_matches(&result.context, s, m)?;
    account(&result.account, s)?;
    Ok(result)
}
pub(crate) async fn revoke(chain: &Chain<'_>, access: &str, context: &str) -> Result<(), AppError> {
    let result: Revoked = call(
        chain,
        Endpoint::ContextRevoke,
        vec![
            ("oidcAccessToken".into(), access.into()),
            ("customerContext".into(), context.into()),
        ],
    )
    .await?;
    if !result.revoked {
        return Err(AppError::Unavailable);
    }
    Ok(())
}
