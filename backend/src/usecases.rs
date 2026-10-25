use crate::{
    boundary::{self, invalid},
    error::AppError,
    resource::{self, Membership, Memberships, Profile},
    store::{self, Session},
    transport::Chain,
};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

fn selected<'a>(s: &Session, available: &'a Memberships) -> Result<&'a Membership, AppError> {
    available
        .memberships
        .iter()
        .find(|m| {
            Some(m.membership_id) == s.membership_id
                && Some(m.organization_id) == s.organization_id
                && m.identity_version.parse::<i64>().ok() == s.identity_version
        })
        .ok_or_else(invalid)
}
pub(crate) async fn final_check(chain: &Chain<'_>, s: &Session) -> Result<(), AppError> {
    let mut connection = chain.state.pool.acquire().await?;
    store::current(&mut connection, s).await?;
    if let Some(expires) = s.customer_expires_at {
        store::deadline(&mut connection, expires).await?;
    }
    Ok(())
}
pub(crate) async fn view(chain: &Chain<'_>, mut s: Session, csrf: &str) -> Result<Value, AppError> {
    let access = store::access(chain.state, &s)?;
    let available = resource::memberships(chain, &s, &access).await?;
    s.access_expires_at = s.access_expires_at.min(available.deadline());
    let context = if s.membership_id.is_some() {
        let m = selected(&s, &available)?;
        s = ensure_context(chain, s, &access, m).await?;
        let profile =
            resource::profile(chain, &s, &access, &store::customer(chain.state, &s)?, m).await?;
        Some(profile.context)
    } else {
        None
    };
    final_check(chain, &s).await?;
    Ok(
        json!({"contractVersion":"portal-session/1","version":s.version.to_string(),"csrfToken":csrf,
        "account":available.account,"memberships":available.memberships,"context":context}),
    )
}
pub(crate) async fn profile(chain: &Chain<'_>, mut s: Session) -> Result<Profile, AppError> {
    let access = store::access(chain.state, &s)?;
    let available = resource::memberships(chain, &s, &access).await?;
    s.access_expires_at = s.access_expires_at.min(available.deadline());
    let m = selected(&s, &available)?;
    let s = ensure_context(chain, s, &access, m).await?;
    let profile =
        resource::profile(chain, &s, &access, &store::customer(chain.state, &s)?, m).await?;
    final_check(chain, &s).await?;
    Ok(profile)
}
async fn claim(chain: &Chain<'_>, s: &Session) -> Result<Uuid, AppError> {
    let lease = Uuid::now_v7();
    let changed=sqlx::query("UPDATE portal_sessions s SET context_lease_id=$2,context_started_at=clock_timestamp() WHERE s.id=$1 AND s.version=$3 AND s.access_ciphertext=$4 AND s.customer_ciphertext IS NOT DISTINCT FROM $5::text AND s.membership_id IS NOT DISTINCT FROM $6::uuid AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.access_expires_at>clock_timestamp() AND s.refresh_lease_id IS NULL AND NOT s.refresh_uncertain AND s.context_lease_id IS NULL AND s.logout_request_id IS NULL AND EXISTS(SELECT 1 FROM portal_browsers b WHERE b.id=s.browser_id AND b.current_session_id=s.id AND b.expires_at>clock_timestamp())")
        .bind(s.id).bind(lease).bind(s.version).bind(&s.access_ciphertext).bind(&s.customer_ciphertext).bind(s.membership_id).execute(&chain.state.pool).await?.rows_affected();
    if changed != 1 {
        return Err(AppError::conflict("门户身份操作已变化"));
    }
    Ok(lease)
}
async fn fail_selection(chain: &Chain<'_>, s: &Session, lease: Uuid) -> Result<(), AppError> {
    // A failed/uncertain switch never puts the old opaque capability back into
    // service. Clearing this original CAS cannot alter a newer browser login.
    sqlx::query("UPDATE portal_sessions SET version=version+1,membership_id=NULL,organization_id=NULL,identity_version=NULL,customer_ciphertext=NULL,customer_expires_at=NULL,context_lease_id=NULL,context_started_at=NULL WHERE id=$1 AND context_lease_id=$2 AND version=$3")
        .bind(s.id).bind(lease).bind(s.version).execute(&chain.state.pool).await?;
    Ok(())
}
async fn replace(
    chain: &Chain<'_>,
    s: Session,
    access: &str,
    m: &Membership,
    explicit: bool,
) -> Result<Session, AppError> {
    let lease = claim(chain, &s).await?;
    let result = async {
        if let Some(cipher) = s
            .customer_ciphertext
            .as_deref()
            .filter(|_| !s.customer_needs_renewal)
        {
            let old = store::keys(chain.state)?.open(
                s.id,
                &s.issuer,
                s.oidc_client_id,
                "customer-context",
                cipher,
            )?;
            resource::revoke(chain, access, &old).await?;
        }
        let issued = resource::issue(chain, &s, access, m).await?;
        let result = commit_context(chain, &s, lease, m, &issued, explicit).await;
        if result.is_err() {
            let _ = resource::revoke(chain, access, &issued.customer_context).await;
        }
        result
    }
    .await;
    if result.is_err() {
        fail_selection(chain, &s, lease).await?;
    }
    result
}
pub(crate) async fn commit_context(
    chain: &Chain<'_>,
    s: &Session,
    lease: Uuid,
    m: &Membership,
    issued: &resource::Issued,
    explicit: bool,
) -> Result<Session, AppError> {
    let encrypted = store::keys(chain.state)?.seal(
        s.id,
        &s.issuer,
        s.oidc_client_id,
        "customer-context",
        &issued.customer_context,
    )?;
    let generation = boundary::version(&m.identity_version, 1)?;
    let changed:Option<Session>=sqlx::query_as("UPDATE portal_sessions s SET membership_id=$4,organization_id=$5,identity_version=$6,customer_ciphertext=$7,customer_expires_at=$8,customer_needs_renewal=false,version=version+$9,context_lease_id=NULL,context_started_at=NULL WHERE s.id=$1 AND s.context_lease_id=$2 AND s.version=$3 AND s.context_started_at>clock_timestamp()-interval '3 seconds' AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.logout_request_id IS NULL AND s.refresh_lease_id IS NULL AND NOT s.refresh_uncertain AND $8::timestamptz>clock_timestamp() AND $10::timestamptz>clock_timestamp() AND EXISTS(SELECT 1 FROM portal_browsers b WHERE b.id=s.browser_id AND b.current_session_id=s.id AND b.expires_at>clock_timestamp()) RETURNING s.*")
        .bind(s.id).bind(lease).bind(s.version).bind(m.membership_id).bind(m.organization_id).bind(generation).bind(encrypted).bind(issued.expires_at).bind(i64::from(explicit)).bind(s.access_expires_at)
        .fetch_optional(&chain.state.pool).await?;
    let mut current = changed.ok_or_else(invalid)?;
    current.access_expires_at = current.access_expires_at.min(s.access_expires_at);
    Ok(current)
}
async fn ensure_context(
    chain: &Chain<'_>,
    s: Session,
    access: &str,
    m: &Membership,
) -> Result<Session, AppError> {
    if !s.customer_needs_renewal
        && s.customer_expires_at
            .is_some_and(|expires| expires > Utc::now() + chrono::Duration::seconds(3))
    {
        return Ok(s);
    }
    replace(chain, s, access, m, false).await
}
pub(crate) async fn select(
    chain: &Chain<'_>,
    mut s: Session,
    expected: &str,
    membership: &str,
    csrf: &str,
) -> Result<Value, AppError> {
    let version = boundary::version(expected, 1)?;
    let membership = boundary::id(membership)?;
    if s.version != version {
        return Err(AppError::conflict("门户会话版本已变化"));
    }
    let access = store::access(chain.state, &s)?;
    let available = resource::memberships(chain, &s, &access).await?;
    s.access_expires_at = s.access_expires_at.min(available.deadline());
    let m = available
        .memberships
        .iter()
        .find(|m| m.membership_id == membership)
        .ok_or_else(|| AppError::forbidden("所选身份不是当前账号的有效客户成员"))?;
    let current = replace(chain, s, &access, m, true).await?;
    view(chain, current, csrf).await
}
