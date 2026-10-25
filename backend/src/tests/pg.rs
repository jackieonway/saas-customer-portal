//! Explicit task-owned PostgreSQL regressions. No ambient DATABASE_URL or
//! default developer database is ever used or modified.
use super::*;
use anyhow::{ensure, Result};

struct Owned {
    admin: sqlx::PgPool,
    pool: sqlx::PgPool,
    name: String,
}
impl Owned {
    async fn new() -> Result<Self> {
        let base = std::env::var("IDENTITY_PHASE11_TEST_DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("explicit IDENTITY_PHASE11_TEST_DATABASE_URL required"))?;
        let mut url =
            reqwest::Url::parse(&base).map_err(|_| anyhow::anyhow!("invalid test database URL"))?;
        ensure!(
            matches!(url.scheme(), "postgres" | "postgresql")
                && matches!(url.host_str(), Some("127.0.0.1" | "localhost")),
            "task-owned loopback PostgreSQL required"
        );
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&base)
            .await
            .map_err(|_| anyhow::anyhow!("test cluster unavailable"))?;
        let cluster: String =
            sqlx::query_scalar("SELECT system_identifier::text FROM pg_control_system()")
                .fetch_one(&admin)
                .await?;
        ensure!(cluster == "7700230159816609830", "wrong test cluster");
        let name = format!("identity_phase11_portal_test_{}", Uuid::now_v7().simple());
        sqlx::query(&format!("CREATE DATABASE \"{name}\""))
            .execute(&admin)
            .await?;
        url.set_path(&format!("/{name}"));
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(url.as_str())
            .await
            .map_err(|_| anyhow::anyhow!("owned test database unavailable"))?;
        sqlx::migrate!().run(&pool).await?;
        Ok(Self { admin, pool, name })
    }
    fn state(&self) -> AppState {
        let mut s = super::state(vec![]);
        s.pool = self.pool.clone();
        s
    }
    async fn finish(self) -> Result<()> {
        self.pool.close().await;
        ensure!(
            self.name.starts_with("identity_phase11_portal_test_")
                && self
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "unsafe cleanup target"
        );
        sqlx::query(&format!("DROP DATABASE \"{}\" WITH (FORCE)", self.name))
            .execute(&self.admin)
            .await?;
        self.admin.close().await;
        Ok(())
    }
}
async fn insert(state: &AppState) -> Result<store::Session> {
    let s = super::session(state);
    sqlx::query("INSERT INTO portal_browsers(id,token_hash,generation,current_session_id,created_at,expires_at) VALUES($1,$2,1,$3,clock_timestamp(),$4)")
        .bind(s.browser_id).bind(b::digest(&"e".repeat(64))).bind(s.id).bind(s.expires_at).execute(&state.pool).await?;
    sqlx::query("INSERT INTO portal_sessions(id,browser_id,token_hash,user_id,account_version,global_session_id,oidc_client_id,oidc_grant_id,oidc_client_policy_version,issuer,auth_time,nonce_hash,access_ciphertext,refresh_ciphertext,access_expires_at,version,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,clock_timestamp(),$17)")
        .bind(s.id).bind(s.browser_id).bind(b::digest(&"f".repeat(64))).bind(s.user_id).bind(s.account_version).bind(s.global_session_id).bind(s.oidc_client_id).bind(s.oidc_grant_id).bind(s.oidc_client_policy_version)
        .bind(&s.issuer).bind(s.auth_time).bind(&s.nonce_hash).bind(&s.access_ciphertext).bind(&s.refresh_ciphertext).bind(s.access_expires_at).bind(s.version).bind(s.expires_at).execute(&state.pool).await?;
    Ok(s)
}
fn verified(s: &store::Session) -> protocol::Verified {
    protocol::Verified {
        proof: protocol::AccountProof {
            user_id: s.user_id,
            global_session_id: s.global_session_id,
            grant_id: s.oidc_grant_id,
            account_version: s.account_version,
            client_id: s.oidc_client_id,
            client_policy_version: s.oidc_client_policy_version,
            auth_time: s.auth_time,
            expires_at: s.access_expires_at,
        },
        access: "9".repeat(64),
        refresh: "8".repeat(64),
        absolute_expires_at: s.expires_at,
        id_expires_at: s.access_expires_at,
    }
}
#[tokio::test]
#[ignore = "requires explicit task-owned phase11 PostgreSQL"]
async fn phase11_pg_every_uuid_has_its_own_v7_guard_and_no_authority_tables() -> Result<()> {
    let db = Owned::new().await?;
    let result=async {
        let columns:i64=sqlx::query_scalar("SELECT count(*) FROM pg_attribute a JOIN pg_class t ON t.oid=a.attrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public' AND t.relkind='r' AND a.attnum>0 AND NOT a.attisdropped AND a.atttypid='uuid'::regtype").fetch_one(&db.pool).await?;
        let guarded:i64=sqlx::query_scalar("SELECT count(*) FROM pg_attribute a JOIN pg_class t ON t.oid=a.attrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public' AND t.relkind='r' AND a.attnum>0 AND NOT a.attisdropped AND a.atttypid='uuid'::regtype AND NOT a.atthasdef AND EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=t.oid AND c.contype='c' AND c.convalidated AND c.conkey=ARRAY[a.attnum]::smallint[] AND pg_get_constraintdef(c.oid) LIKE '%is_uuid_v7%')").fetch_one(&db.pool).await?;
        ensure!(columns==15 && guarded==columns,"UUID guard/default coverage mismatch");
        let tables:Vec<String>=sqlx::query_scalar("SELECT tablename::text FROM pg_tables WHERE schemaname='public' ORDER BY tablename").fetch_all(&db.pool).await?;
        ensure!(tables==["_sqlx_migrations","portal_browsers","portal_login_flows","portal_sessions"],"authority data leaked into portal database");Ok(())
    }.await;
    db.finish().await?;
    result
}
#[tokio::test]
#[ignore = "requires explicit task-owned phase11 PostgreSQL"]
async fn phase11_pg_context_returning_snapshot_does_not_adopt_later_tab_selection() -> Result<()> {
    let db = Owned::new().await?;
    let state = db.state();
    let result=async {
        let s=insert(&state).await?;let m=super::member(&s);let lease=Uuid::now_v7();
        sqlx::query("UPDATE portal_sessions SET context_lease_id=$2,context_started_at=clock_timestamp() WHERE id=$1").bind(s.id).bind(lease).execute(&state.pool).await?;
        let issued=resource::Issued {customer_context:format!("cpc_{}","d".repeat(64)),expires_at:s.access_expires_at,context:super::context(&s,&m),account:serde_json::from_value(super::account(&s))?};
        let chain=Chain::new(&state)?;let returned=usecases::commit_context(&chain,&s,lease,&m,&issued,true).await?;
        // Deterministic scheduling boundary: the exact SQL result has returned;
        // another tab commits before this request performs its final fence.
        let other=Uuid::now_v7();sqlx::query("UPDATE portal_sessions SET version=version+1,membership_id=$2 WHERE id=$1").bind(s.id).bind(other).execute(&state.pool).await?;
        ensure!(returned.version==2 && returned.membership_id==Some(m.membership_id),"context write adopted a later row");
        ensure!(usecases::final_check(&chain,&returned).await.is_err(),"late original response survived selection fence");Ok(())
    }.await;
    drop(state);
    db.finish().await?;
    result
}
#[tokio::test]
#[ignore = "requires explicit task-owned phase11 PostgreSQL"]
async fn phase11_pg_refresh_returning_snapshot_does_not_adopt_later_tab_selection() -> Result<()> {
    let db = Owned::new().await?;
    let state = db.state();
    let result=async {
        let s=insert(&state).await?;let lease=Uuid::now_v7();
        sqlx::query("UPDATE portal_sessions SET refresh_lease_id=$2,refresh_started_at=clock_timestamp() WHERE id=$1").bind(s.id).bind(lease).execute(&state.pool).await?;
        let returned=store::commit_refresh(&state,&s,lease,&verified(&s)).await?;
        let other=super::member(&s);let cipher=store::keys(&state)?.seal(s.id,&s.issuer,s.oidc_client_id,"customer-context",&format!("cpc_{}","3".repeat(64)))?;
        sqlx::query("UPDATE portal_sessions SET version=version+1,membership_id=$2,organization_id=$3,identity_version=1,customer_ciphertext=$4,customer_expires_at=$5 WHERE id=$1")
            .bind(s.id).bind(other.membership_id).bind(other.organization_id).bind(cipher).bind(s.access_expires_at).execute(&state.pool).await?;
        ensure!(returned.version==1 && returned.membership_id.is_none(),"refresh write adopted later member");
        let mut connection=state.pool.acquire().await?;ensure!(store::current(&mut connection,&returned).await.is_err(),"late refresh snapshot survived selection fence");Ok(())
    }.await;
    drop(state);
    db.finish().await?;
    result
}
#[tokio::test]
#[ignore = "requires explicit task-owned phase11 PostgreSQL"]
async fn phase11_pg_expired_refresh_lease_is_uncertain_and_never_replayed() -> Result<()> {
    let db = Owned::new().await?;
    let state = db.state();
    let result=async {
        let s=insert(&state).await?;
        sqlx::query("UPDATE portal_sessions SET refresh_lease_id=$2,refresh_started_at=clock_timestamp()-interval '4 seconds' WHERE id=$1").bind(s.id).bind(Uuid::now_v7()).execute(&state.pool).await?;
        let leased=store::session_id(&state.pool,s.id,false).await?.unwrap();let chain=Chain::new(&state)?;
        ensure!(matches!(store::online(&chain,leased).await,Err(AppError::Unavailable)),"expired refresh lease accepted");
        let current=store::session_id(&state.pool,s.id,false).await?.unwrap();ensure!(current.refresh_uncertain,"unknown outcome not persisted");
        ensure!(matches!(store::online(&chain,current).await,Err(AppError::Unavailable)),"old refresh replay attempted");Ok(())
    }.await;
    drop(state);
    db.finish().await?;
    result
}
#[tokio::test]
#[ignore = "requires explicit task-owned phase11 PostgreSQL"]
async fn phase11_pg_invalid_session_cannot_block_explicit_anonymous_login_bootstrap() -> Result<()>
{
    let db = Owned::new().await?;
    let state = db.state();
    let result = async {
        let app = crate::routes::routes().with_state(state.clone());
        let invalid_cookie = format!("{}={}", b::SESSION_COOKIE, "a".repeat(64));
        let request = |path: &str| {
            Request::builder()
                .uri(path)
                .header("host", "customer.saas.test")
                .header("origin", "https://customer.saas.test")
                .header("cookie", &invalid_cookie)
                .body(Body::empty())
                .unwrap()
        };
        let response = app.clone().oneshot(request("/auth/session")).await?;
        ensure!(
            response.status() == StatusCode::UNAUTHORIZED,
            "invalid session did not fail closed"
        );
        let response = app
            .clone()
            .oneshot(request("/auth/login-bootstrap"))
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "explicit login bootstrap blocked by old cookie"
        );
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()?
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
        ensure!(
            body["version"] == "0"
                && body["account"].is_null()
                && body["context"].is_null()
                && body["memberships"] == json!([]),
            "bootstrap granted identity"
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("host", "customer.saas.test")
                    .header("origin", "https://customer.saas.test")
                    .header("content-type", "application/json")
                    .header("cookie", format!("{cookie}; {invalid_cookie}"))
                    .body(Body::from(r#"{"returnTo":"/"}"#))
                    .unwrap(),
            )
            .await?;
        ensure!(
            response.status() == StatusCode::UNAUTHORIZED
                || response.status() == StatusCode::FORBIDDEN,
            "login without CSRF accepted"
        );
        Ok(())
    }
    .await;
    drop(state);
    db.finish().await?;
    result
}
