//! Explicit task-owned PostgreSQL regressions. No ambient DATABASE_URL or
//! default developer database is ever used or modified.
use super::*;
use anyhow::{ensure, Result};

#[path = "schema_roles.rs"]
mod schema_roles;

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
                && matches!(url.host_str(), Some("127.0.0.1" | "localhost"))
                && url.port().is_some()
                && url.path() == "/postgres"
                && !url.username().is_empty()
                && url.fragment().is_none()
                && url.query_pairs().all(|(key, value)| key == "sslmode"
                    && matches!(value.as_ref(), "disable" | "prefer" | "require")),
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
        let expected = std::env::var("CONTEXT_SELECTION_TEST_CLUSTER_ID").map_err(|_| {
            anyhow::anyhow!("explicit task-owned CONTEXT_SELECTION_TEST_CLUSTER_ID required")
        })?;
        ensure!(cluster == expected, "wrong test cluster");
        let name = format!("identity_phase11_portal_test_{}", Uuid::now_v7().simple());
        sqlx::query(&format!("CREATE DATABASE \"{name}\""))
            .execute(&admin)
            .await?;
        url.set_path(&format!("/{name}"));
        let pool = match sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(url.as_str())
            .await
        {
            Ok(pool) => pool,
            Err(_) => {
                sqlx::query(&format!("DROP DATABASE \"{name}\" WITH (FORCE)"))
                    .execute(&admin)
                    .await?;
                admin.close().await;
                return Err(anyhow::anyhow!("owned test database unavailable"));
            }
        };
        let database = Self { admin, pool, name };
        if let Err(error) = sqlx::migrate!().run(&database.pool).await {
            database.finish().await?;
            return Err(error.into());
        }
        Ok(database)
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
        let removed = sqlx::query(&format!("DROP DATABASE \"{}\" WITH (FORCE)", self.name))
            .execute(&self.admin)
            .await;
        self.admin.close().await;
        eprintln!("portal_owned_cleanup database_removed={}", removed.is_ok());
        removed?;
        Ok(())
    }
}
async fn insert(state: &AppState) -> Result<store::Session> {
    let s = super::session(state);
    insert_bound(state, &s, &"e".repeat(64), &"f".repeat(64)).await?;
    Ok(s)
}
async fn insert_bound(
    state: &AppState,
    s: &store::Session,
    browser_cookie: &str,
    session_cookie: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO portal_browsers(id,token_hash,generation,current_session_id,created_at,expires_at) VALUES($1,$2,1,$3,clock_timestamp(),$4)")
        .bind(s.browser_id).bind(b::digest(browser_cookie)).bind(s.id).bind(s.expires_at).execute(&state.pool).await?;
    sqlx::query("INSERT INTO portal_sessions(id,browser_id,token_hash,user_id,account_version,global_session_id,oidc_client_id,oidc_grant_id,oidc_client_policy_version,issuer,auth_time,nonce_hash,access_ciphertext,refresh_ciphertext,access_expires_at,version,created_at,expires_at,oidc_public_sid,oidc_public_sub) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,clock_timestamp(),$17,$18,$19)")
        .bind(s.id).bind(s.browser_id).bind(b::digest(session_cookie)).bind(s.user_id).bind(s.account_version).bind(s.global_session_id).bind(s.oidc_client_id).bind(s.oidc_grant_id).bind(s.oidc_client_policy_version)
        .bind(&s.issuer).bind(s.auth_time).bind(&s.nonce_hash).bind(&s.access_ciphertext).bind(&s.refresh_ciphertext).bind(s.access_expires_at).bind(s.version).bind(s.expires_at).bind(&s.oidc_public_sid).bind(&s.oidc_public_sub).execute(&state.pool).await?;
    Ok(())
}

fn backchannel_request(token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/auth/backchannel-logout")
        .header("host", "customer.saas.test")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!("logout_token={token}")))
        .unwrap()
}

#[tokio::test]
#[ignore = "requires explicit task-owned PostgreSQL and cluster identifier"]
async fn phase20_pg_signed_logout_is_precise_replay_safe_and_independent_of_access_proof(
) -> Result<()> {
    let db = Owned::new().await?;
    let mut state = db.state();
    let result=async {
        let original=insert(&state).await?;
        let other=super::session(&state);
        insert_bound(&state,&other,&"1".repeat(64),&"2".repeat(64)).await?;
        // Access authority is deliberately unavailable/revoked. Only JWKS is
        // requested; the Script panics if an account/access proof is attempted.
        state.transport=Arc::new(Script(Mutex::new(VecDeque::from(vec![(Endpoint::Jwks,200,crate::backchannel::tests::jwks());6]))));
        let app=crate::routes::routes().with_state(state.clone());
        let mut invalid=crate::backchannel::tests::payload(&original);
        invalid["nonce"]=json!("forbidden");
        ensure!(app.clone().oneshot(backchannel_request(&crate::backchannel::tests::signed(&invalid))).await?.status()==StatusCode::BAD_REQUEST,"borrowed OIDC nonce accepted");
        let mut unknown=crate::backchannel::tests::payload(&original);unknown["sid"]=json!("9".repeat(64));
        ensure!(app.clone().oneshot(backchannel_request(&crate::backchannel::tests::signed(&unknown))).await?.status()==StatusCode::OK,"unknown valid source should acknowledge zero local effect");
        let mut wrong=crate::backchannel::tests::payload(&original);wrong["sub"]=json!("different-opaque-account");
        ensure!(app.clone().oneshot(backchannel_request(&crate::backchannel::tests::signed(&wrong))).await?.status()==StatusCode::BAD_REQUEST,"known sid accepted another subject");
        let value=crate::backchannel::tests::payload(&original);let token=crate::backchannel::tests::signed(&value);
        ensure!(app.clone().oneshot(backchannel_request(&token)).await?.status()==StatusCode::OK,"valid signature did not revoke original source");
        let (old_revoked,other_revoked,pointer):(bool,bool,Option<Uuid>)=sqlx::query_as("SELECT (SELECT revoked_at IS NOT NULL FROM portal_sessions WHERE id=$1),(SELECT revoked_at IS NOT NULL FROM portal_sessions WHERE id=$2),(SELECT current_session_id FROM portal_browsers WHERE id=$3)")
            .bind(original.id).bind(other.id).bind(original.browser_id).fetch_one(&state.pool).await?;
        ensure!(old_revoked&&!other_revoked&&pointer.is_none(),"logout scope touched another RP source/account");
        let replay=app.clone().oneshot(backchannel_request(&token)).await?;
        ensure!(replay.status()==StatusCode::CONFLICT,"replayed jti accepted");
        let body:Value=serde_json::from_slice(&to_bytes(replay.into_body(),4096).await?)?;
        ensure!(body["code"]=="BACKCHANNEL_REPLAY","replay has no stable machine code");
        let again=crate::backchannel::tests::payload(&original);
        ensure!(app.oneshot(backchannel_request(&crate::backchannel::tests::signed(&again))).await?.status()==StatusCode::OK,"new delivery attempt could not acknowledge already closed source");
        let receipts:i64=sqlx::query_scalar("SELECT count(*) FROM portal_backchannel_logout_receipts").fetch_one(&state.pool).await?;
        ensure!(receipts==3,"invalid or replayed notification persisted a receipt");
        Ok(())
    }.await;
    drop(state);
    db.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires explicit task-owned PostgreSQL and cluster identifier"]
async fn phase20_pg_late_notification_and_pending_logout_preserve_new_browser_source() -> Result<()>
{
    let db = Owned::new().await?;
    let mut state = db.state();
    let result=async {
        let original=insert(&state).await?;
        let newer=Uuid::now_v7();let operation=Uuid::now_v7();
        sqlx::query("INSERT INTO portal_sessions(id,browser_id,token_hash,user_id,account_version,global_session_id,oidc_client_id,oidc_grant_id,oidc_client_policy_version,issuer,auth_time,nonce_hash,access_ciphertext,refresh_ciphertext,access_expires_at,version,created_at,expires_at,oidc_public_sid,oidc_public_sub) SELECT $2,browser_id,$3,user_id,account_version,global_session_id,oidc_client_id,$4,oidc_client_policy_version,issuer,auth_time,nonce_hash,access_ciphertext,refresh_ciphertext,access_expires_at,1,created_at,expires_at,$5,oidc_public_sub FROM portal_sessions WHERE id=$1")
            .bind(original.id).bind(newer).bind(b::digest(&"3".repeat(64))).bind(Uuid::now_v7()).bind("7".repeat(64)).execute(&state.pool).await?;
        sqlx::query("UPDATE portal_sessions SET logout_request_id=$2,logout_scope='GLOBAL' WHERE id=$1").bind(original.id).bind(operation).execute(&state.pool).await?;
        sqlx::query("UPDATE portal_browsers SET current_session_id=$2,generation=generation+1 WHERE id=$1").bind(original.browser_id).bind(newer).execute(&state.pool).await?;
        state.transport=Arc::new(Script(Mutex::new(VecDeque::from([(Endpoint::Jwks,200,crate::backchannel::tests::jwks()),
            (Endpoint::LogoutOperation(operation),200,json!({"operationId":operation,"scope":"GLOBAL","state":"COMPLETED","revokedGrantCount":1,"revokedSsoCount":1,"notificationCount":1}))]))));
        let app=crate::routes::routes().with_state(state.clone());
        ensure!(app.clone().oneshot(backchannel_request(&crate::backchannel::tests::signed(&crate::backchannel::tests::payload(&original)))).await?.status()==StatusCode::OK,"late signature rejected");
        let (pointer,revoked):(Option<Uuid>,bool)=sqlx::query_as("SELECT (SELECT current_session_id FROM portal_browsers WHERE id=$1),(SELECT revoked_at IS NOT NULL FROM portal_sessions WHERE id=$2)")
            .bind(original.browser_id).bind(newer).fetch_one(&state.pool).await?;
        ensure!(pointer==Some(newer)&&!revoked,"late old notification erased the new browser source");
        let response=app.oneshot(Request::builder().method("POST").uri("/auth/logout")
            .header("host","customer.saas.test").header("origin","https://customer.saas.test")
            .header("content-type","application/json").header("x-csrf-token",b::csrf(&"f".repeat(64)))
            .header("cookie",format!("{}={}; {}={}",b::BROWSER_COOKIE,"e".repeat(64),b::SESSION_COOKIE,"f".repeat(64)))
            .body(Body::from(r#"{"scope":"GLOBAL","expectedVersion":"1"}"#)).unwrap()).await?;
        ensure!(response.status()==StatusCode::CONFLICT,"original receipt masqueraded as current new login logout");
        let (pointer,confirmed):(Option<Uuid>,bool)=sqlx::query_as("SELECT (SELECT current_session_id FROM portal_browsers WHERE id=$1),(SELECT logout_confirmed_at IS NOT NULL FROM portal_sessions WHERE id=$2)")
            .bind(original.browser_id).bind(original.id).fetch_one(&state.pool).await?;
        ensure!(pointer==Some(newer)&&confirmed,"same original revoked operation could not recover without erasing new source");
        Ok(())
    }.await;
    drop(state);
    db.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires explicit task-owned PostgreSQL and cluster identifier"]
async fn phase20_pg_logout_expiring_while_waiting_rolls_back_replay_and_revocation() -> Result<()> {
    let db = Owned::new().await?;
    let mut state = db.state();
    let result=async {
        let original=insert(&state).await?;
        let mut value=crate::backchannel::tests::payload(&original);
        let end=Utc::now().timestamp()+2;value["iat"]=json!(end-120);value["exp"]=json!(end);
        state.transport=Arc::new(Script(Mutex::new(VecDeque::from([(Endpoint::Jwks,200,crate::backchannel::tests::jwks())]))));
        let mut blocker=state.pool.begin().await?;
        sqlx::query("SELECT id FROM portal_browsers WHERE id=$1 FOR UPDATE").bind(original.browser_id).fetch_one(&mut *blocker).await?;
        let token=crate::backchannel::tests::signed(&value);
        let app=crate::routes::routes().with_state(state.clone());
        let receiving=tokio::spawn(async move {app.oneshot(backchannel_request(&token)).await});
        let waiting=tokio::time::timeout(std::time::Duration::from_secs(2),async {
            loop {
                let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND query LIKE 'SELECT b.id FROM portal_browsers b WHERE EXISTS%' AND cardinality(pg_blocking_pids(pid))>0)").fetch_one(&state.pool).await?;
                if blocked { return Ok::<(),sqlx::Error>(()); }
                tokio::task::yield_now().await;
            }
        }).await;
        // Release the owned lock even if a diagnostic assertion failed.
        let reached=matches!(&waiting,Ok(Ok(())));
        if reached {
            while Utc::now().timestamp()<=end { tokio::time::sleep(std::time::Duration::from_millis(20)).await; }
        }
        blocker.rollback().await?;
        let response=receiving.await??;
        ensure!(reached,"receiver never reached the independently held browser lock");
        ensure!(response.status()==StatusCode::BAD_REQUEST,"expired notification did not return declared 400 after lock wait");
        let (revoked,receipts,sources,pointer):(bool,i64,i64,Option<Uuid>)=sqlx::query_as("SELECT (SELECT revoked_at IS NOT NULL FROM portal_sessions WHERE id=$1),(SELECT count(*) FROM portal_backchannel_logout_receipts),(SELECT count(*) FROM portal_backchannel_logout_sources),(SELECT current_session_id FROM portal_browsers WHERE id=$2)")
            .bind(original.id).bind(original.browser_id).fetch_one(&state.pool).await?;
        ensure!(!revoked&&receipts==0&&sources==0&&pointer==Some(original.id),"expired lock-wait notification left partial revocation/replay state");
        Ok(())
    }.await;
    drop(state);
    db.finish().await?;
    result
}

struct PausedUserInfo {
    script: Mutex<VecDeque<(Endpoint, u16, Value)>>,
    proof_returned: Arc<tokio::sync::Notify>,
    resume: Arc<tokio::sync::Notify>,
}
impl OidcTransport for PausedUserInfo {
    fn send<'a>(&'a self, request: OidcRequest) -> OidcFuture<'a> {
        Box::pin(async move {
            let (endpoint, status, value) = self.script.lock().unwrap().pop_front().unwrap();
            assert_eq!(endpoint.path(), request.endpoint.path());
            if matches!(endpoint, Endpoint::UserInfo) {
                self.proof_returned.notify_one();
                self.resume.notified().await;
            }
            Ok(OidcResponse {
                status,
                body: serde_json::to_vec(&value).unwrap(),
            })
        })
    }
}
async fn login_flow(state: &AppState, session: &store::Session, state_secret: &str) -> Result<()> {
    let id = Uuid::now_v7();
    let verifier = store::keys(state)?.seal(
        id,
        &session.issuer,
        session.oidc_client_id,
        "login-verifier",
        "fixture-verifier",
    )?;
    sqlx::query("INSERT INTO portal_login_flows(id,browser_id,browser_generation,state_hash,binder_hash,nonce_hash,verifier_ciphertext,return_path,created_at,expires_at) VALUES($1,$2,1,$3,$4,$5,$6,'/',clock_timestamp(),$7)")
        .bind(id).bind(session.browser_id).bind(b::digest(state_secret)).bind(b::digest(&"4".repeat(64))).bind(&session.nonce_hash).bind(verifier).bind(session.expires_at).execute(&state.pool).await?;
    Ok(())
}
fn callback_request(state_secret: &str) -> Request<Body> {
    Request::builder().uri(format!("/auth/callback?state={state_secret}&iss=https%3A%2F%2Fauth.saas.test&code=fixture-code"))
        .header("host","customer.saas.test").header("cookie",format!("{}={}; {}={}",b::BROWSER_COOKIE,"e".repeat(64),b::LOGIN_COOKIE,"4".repeat(64)))
        .body(Body::empty()).unwrap()
}
fn exchange_script(session: &store::Session) -> VecDeque<(Endpoint, u16, Value)> {
    let now = Utc::now().timestamp();
    let identity = crate::backchannel::tests::signed_id_token(
        &json!({"iss":session.issuer,"aud":session.oidc_client_id,
        "sub":session.oidc_public_sub,"sid":session.oidc_public_sid,"iat":now,"exp":now+300,
        "auth_time":session.auth_time,"nonce":"fixture-nonce"}),
    );
    VecDeque::from([
        (Endpoint::Discovery, 200, super::discovery()),
        (
            Endpoint::Token,
            200,
            json!({"access_token":"a".repeat(64),"refresh_token":"b".repeat(64),"token_type":"Bearer","scope":"openid profile","expires_in":300,"id_token":identity}),
        ),
        (Endpoint::Jwks, 200, crate::backchannel::tests::jwks()),
        (Endpoint::AccountProof, 200, super::proof(session)),
        (
            Endpoint::UserInfo,
            200,
            json!({"sub":session.oidc_public_sub}),
        ),
    ])
}

#[tokio::test]
#[ignore = "requires explicit task-owned PostgreSQL and cluster identifier"]
async fn phase20_pg_unknown_source_notification_fences_already_verified_callback() -> Result<()> {
    let db = Owned::new().await?;
    let mut state = db.state();
    let result=async {
        let future=super::session(&state);
        sqlx::query("INSERT INTO portal_browsers(id,token_hash,generation,created_at,expires_at) VALUES($1,$2,1,clock_timestamp(),$3)")
            .bind(future.browser_id).bind(b::digest(&"e".repeat(64))).bind(future.expires_at).execute(&state.pool).await?;
        login_flow(&state,&future,&"5".repeat(64)).await?;
        let entered=Arc::new(tokio::sync::Notify::new());let resume=Arc::new(tokio::sync::Notify::new());
        let mut script=exchange_script(&future);script.push_back((Endpoint::Jwks,200,crate::backchannel::tests::jwks()));
        state.transport=Arc::new(PausedUserInfo {script:Mutex::new(script),proof_returned:entered.clone(),resume:resume.clone()});
        let app=crate::routes::routes().with_state(state.clone());
        let callback=tokio::spawn(async move {app.oneshot(callback_request(&"5".repeat(64))).await});
        let barrier=tokio::time::timeout(std::time::Duration::from_secs(2),entered.notified()).await;
        if barrier.is_err() {resume.notify_one();let _=callback.await;return Err(anyhow::anyhow!("callback never returned its original source proof"));}
        let notification=crate::backchannel::receive(&state,&crate::backchannel::tests::signed(&crate::backchannel::tests::payload(&future))).await;
        resume.notify_one();let response=callback.await??;
        ensure!(matches!(notification,Ok(true)),"valid unknown source was not recorded");
        ensure!(response.status()==StatusCode::UNAUTHORIZED,"already verified callback resurrected a revoked unknown source");
        let (sessions,sources,pointer):(i64,i64,Option<Uuid>)=sqlx::query_as("SELECT (SELECT count(*) FROM portal_sessions),(SELECT count(*) FROM portal_backchannel_logout_sources),(SELECT current_session_id FROM portal_browsers WHERE id=$1)")
            .bind(future.browser_id).fetch_one(&state.pool).await?;
        ensure!(sessions==0&&sources==1&&pointer.is_none(),"unknown-source fence left an authorizing local session");
        let mut another=future.clone();another.oidc_public_sid=b::secret()?;another.oidc_grant_id=Uuid::now_v7();
        login_flow(&state,&another,&"6".repeat(64)).await?;
        state.transport=Arc::new(Script(Mutex::new(exchange_script(&another))));
        let response=crate::routes::routes().with_state(state.clone()).oneshot(callback_request(&"6".repeat(64))).await?;
        ensure!(response.status()==StatusCode::SEE_OTHER,"another independently authorized sid was incorrectly fenced");
        let sid:String=sqlx::query_scalar("SELECT oidc_public_sid FROM portal_sessions").fetch_one(&state.pool).await?;
        ensure!(sid==another.oidc_public_sid,"callback changed its independently authorized public source");
        let current:store::Session=sqlx::query_as("SELECT * FROM portal_sessions").fetch_one(&state.pool).await?;
        let lease=Uuid::now_v7();
        sqlx::query("UPDATE portal_sessions SET refresh_lease_id=$2,refresh_started_at=clock_timestamp() WHERE id=$1")
            .bind(current.id).bind(lease).execute(&state.pool).await?;
        let already_verified=verified(&current);
        state.transport=Arc::new(Script(Mutex::new(VecDeque::from([(Endpoint::Jwks,200,crate::backchannel::tests::jwks())]))));
        ensure!(crate::backchannel::receive(&state,&crate::backchannel::tests::signed(&crate::backchannel::tests::payload(&current))).await?,"current source notification failed");
        ensure!(matches!(store::commit_refresh(&state,&current,lease,&already_verified).await,Err(AppError::Unauthorized(_))),"already returned refresh result resurrected the revoked source");
        let closed:store::Session=sqlx::query_as("SELECT * FROM portal_sessions WHERE id=$1").bind(current.id).fetch_one(&state.pool).await?;
        ensure!(closed.revoked_at.is_some()&&closed.access_ciphertext==current.access_ciphertext,"refresh changed the closed source credential");
        Ok(())
    }.await;
    drop(state);
    db.finish().await?;
    result
}
fn verified(s: &store::Session) -> protocol::Verified {
    protocol::Verified {
        public_sid: s.oidc_public_sid.clone(),
        selection: None,
        proof: protocol::AccountProof {
            subject: "pairwise-customer-fixture-no-uuid".into(),
            user_id: s.user_id,
            global_session_id: s.global_session_id,
            grant_id: s.oidc_grant_id,
            account_version: s.account_version,
            client_id: s.oidc_client_id,
            client_policy_version: s.oidc_client_policy_version,
            auth_time: s.auth_time,
            expires_at: s.access_expires_at,
            absolute_expires_at: s.expires_at,
        },
        access: "9".repeat(64),
        refresh: "8".repeat(64),
        absolute_expires_at: s.expires_at,
        id_expires_at: s.access_expires_at,
    }
}

#[tokio::test]
#[ignore = "requires explicit task-owned PostgreSQL and cluster identifier"]
async fn phase14_pg_refresh_preserves_and_shrinks_original_absolute_limit() -> Result<()> {
    let db = Owned::new().await?;
    let state = db.state();
    let result = async {
        let original = insert(&state).await?;
        let lease = Uuid::now_v7();
        sqlx::query("UPDATE portal_sessions SET refresh_lease_id=$2,refresh_started_at=clock_timestamp() WHERE id=$1")
            .bind(original.id).bind(lease).execute(&state.pool).await?;
        let mut response = verified(&original);
        response.absolute_expires_at = chrono::DateTime::from_timestamp(Utc::now().timestamp()+600,0).unwrap();
        let returned = store::commit_refresh(&state,&original,lease,&response).await?;
        ensure!(returned.expires_at == response.absolute_expires_at && returned.expires_at < original.expires_at,
            "refresh did not preserve tighter authority deadline");
        let next_lease = Uuid::now_v7();
        sqlx::query("UPDATE portal_sessions SET refresh_lease_id=$2,refresh_started_at=clock_timestamp() WHERE id=$1")
            .bind(returned.id).bind(next_lease).execute(&state.pool).await?;
        response.absolute_expires_at = original.expires_at+Duration::hours(1);
        let again = store::commit_refresh(&state,&returned,next_lease,&response).await?;
        ensure!(again.expires_at == returned.expires_at,"refresh extended original absolute deadline");
        Ok(())
    }.await;
    drop(state);
    db.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires explicit task-owned PostgreSQL and cluster identifier"]
async fn phase14_pg_pending_recovery_cannot_adopt_later_version_or_reconsume_denial() -> Result<()>
{
    let db = Owned::new().await?;
    let mut state = db.state();
    Arc::get_mut(&mut state.config)
        .unwrap()
        .context_selection_enabled = true;
    let result = async {
        let mut original = insert(&state).await?;
        let pending=crate::selection::Pending {extension:crate::selection::Extension {
            contract_version:"context-selection/1".into(),transaction_id:Uuid::now_v7().to_string(),credential:"c".repeat(64)},old_access:None};
        let encrypted=store::keys(&state)?.seal(original.id,&original.issuer,original.oidc_client_id,
            "pending-selection",&serde_json::to_string(&pending)?)?;
        sqlx::query("UPDATE portal_sessions SET pending_selection_ciphertext=$2 WHERE id=$1")
            .bind(original.id).bind(&encrypted).execute(&state.pool).await?;
        original.pending_selection_ciphertext=Some(encrypted.clone());
        let member=super::member(&original);
        let result=json!({"status":"COMMITTED","customerContext":format!("cpc_{}","d".repeat(64)),
            "expiresAt":original.access_expires_at,"context":super::context(&original,&member),"account":super::account(&original)});
        state.transport=Arc::new(Script(Mutex::new(VecDeque::from([(Endpoint::SelectionResult,200,result)]))));
        sqlx::query("UPDATE portal_sessions SET version=version+1 WHERE id=$1")
            .bind(original.id).execute(&state.pool).await?;
        ensure!(matches!(crate::selection::resume(&state,original.clone()).await,Err(AppError::Conflict(_))),
            "pending recovery adopted a later local session version");
        let current=store::session_id(&state.pool,original.id,false).await?.unwrap();
        ensure!(current.version==2 && current.pending_selection_ciphertext.as_deref()==Some(encrypted.as_str()) && current.membership_id.is_none(),
            "failed original operation replaced later state");
        state.transport=Arc::new(Script(Mutex::new(VecDeque::from([(Endpoint::SelectionResult,401,json!({"code":"UNAUTHORIZED"}))]))));
        ensure!(matches!(crate::selection::resume(&state,current).await,Err(AppError::Unauthorized(_))),
            "denied source was treated as an uncertain result or consumed again");
        Ok(())
    }.await;
    drop(state);
    db.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires explicit task-owned PostgreSQL and cluster identifier"]
async fn centralized_pending_commit_recovers_after_local_save_failure_without_reissuing(
) -> Result<()> {
    let db = Owned::new().await?;
    let mut state = db.state();
    Arc::get_mut(&mut state.config)
        .unwrap()
        .context_selection_enabled = true;
    let result=async {
        let mut s=insert(&state).await?;
        let flow=Uuid::now_v7();
        let pending=crate::selection::Pending {extension:crate::selection::Extension{contract_version:"context-selection/1".into(),transaction_id:flow.to_string(),credential:"c".repeat(64)},old_access:None};
        let encrypted=store::keys(&state)?.seal(s.id,&s.issuer,s.oidc_client_id,"pending-selection",&serde_json::to_string(&pending)?)?;
        sqlx::query("UPDATE portal_sessions SET pending_selection_ciphertext=$2 WHERE id=$1").bind(s.id).bind(&encrypted).execute(&state.pool).await?;
        s.pending_selection_ciphertext=Some(encrypted.clone());
        let m=super::member(&s);
        let response=json!({"status":"COMMITTED","customerContext":format!("cpc_{}","d".repeat(64)),"expiresAt":s.access_expires_at,"context":super::context(&s,&m),"account":super::account(&s)});
        state.transport=Arc::new(Script(Mutex::new(std::collections::VecDeque::from([(Endpoint::SelectionResult,200,response.clone()),(Endpoint::SelectionResult,200,response)]))));
        ensure!(store::online(&Chain::new(&state)?,s.clone()).await.is_err(),"pending operation allowed an ordinary session read");
        sqlx::raw_sql("CREATE FUNCTION suppress_pending_save() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.pending_selection_ciphertext IS NOT NULL AND NEW.pending_selection_ciphertext IS NULL THEN RETURN NULL; END IF; RETURN NEW; END $$; CREATE TRIGGER suppress_pending_save BEFORE UPDATE ON portal_sessions FOR EACH ROW EXECUTE FUNCTION suppress_pending_save();").execute(&state.pool).await?;
        ensure!(crate::selection::resume(&state,s.clone()).await.is_err(),"suppressed local save announced success");
        let saved:Option<String>=sqlx::query_scalar("SELECT pending_selection_ciphertext FROM portal_sessions WHERE id=$1").bind(s.id).fetch_one(&state.pool).await?;
        ensure!(saved.as_deref()==Some(encrypted.as_str()),"failed local save lost its original operation");
        sqlx::raw_sql("DROP TRIGGER suppress_pending_save ON portal_sessions; DROP FUNCTION suppress_pending_save();").execute(&state.pool).await?;
        let restored=crate::selection::resume(&state,s).await?;
        ensure!(restored.pending_selection_ciphertext.is_none() && restored.membership_id==Some(m.membership_id) && restored.version==1,"result recovery changed operation or identity");
        Ok(())
    }.await;
    drop(state);
    db.finish().await?;
    result
}
#[tokio::test]
#[ignore = "requires explicit task-owned phase11 PostgreSQL"]
async fn phase11_pg_every_uuid_has_its_own_v7_guard_and_no_authority_tables() -> Result<()> {
    let db = Owned::new().await?;
    let result=async {
        let columns:i64=sqlx::query_scalar("SELECT count(*) FROM pg_attribute a JOIN pg_class t ON t.oid=a.attrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public' AND t.relkind='r' AND a.attnum>0 AND NOT a.attisdropped AND a.atttypid='uuid'::regtype").fetch_one(&db.pool).await?;
        let guarded:i64=sqlx::query_scalar("SELECT count(*) FROM pg_attribute a JOIN pg_class t ON t.oid=a.attrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public' AND t.relkind='r' AND a.attnum>0 AND NOT a.attisdropped AND a.atttypid='uuid'::regtype AND NOT a.atthasdef AND EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=t.oid AND c.contype='c' AND c.convalidated AND c.conkey=ARRAY[a.attnum]::smallint[] AND pg_get_constraintdef(c.oid) LIKE '%is_uuid_v7%')").fetch_one(&db.pool).await?;
        ensure!(columns==20 && guarded==columns,"UUID guard/default coverage mismatch");
        let tables:Vec<String>=sqlx::query_scalar("SELECT tablename::text FROM pg_tables WHERE schemaname='public' ORDER BY tablename").fetch_all(&db.pool).await?;
        ensure!(tables==["_sqlx_migrations","portal_backchannel_logout_receipts","portal_backchannel_logout_sources","portal_browsers","portal_login_flows","portal_sessions"],"authority data leaked into portal database");Ok(())
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
