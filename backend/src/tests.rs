use crate::{
    boundary as b,
    config::Config,
    crypto::CipherKeys,
    error::AppError,
    protocol, resource, store,
    transport::{Chain, Endpoint, OidcFuture, OidcRequest, OidcResponse, OidcTransport},
    usecases, AppState,
};
use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};
use tower::ServiceExt;
use uuid::Uuid;

struct Script(Mutex<VecDeque<(Endpoint, u16, Value)>>);
impl OidcTransport for Script {
    fn send<'a>(&'a self, request: OidcRequest) -> OidcFuture<'a> {
        Box::pin(async move {
            let (endpoint, status, value) = self
                .0
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected authority request");
            assert_eq!(endpoint.path(), request.endpoint.path());
            Ok(OidcResponse {
                status,
                body: serde_json::to_vec(&value).unwrap(),
            })
        })
    }
}
fn config() -> Config {
    let mut config = Config::from_values(&HashMap::from([(
        "DATABASE_URL".into(),
        "postgres://fixture@127.0.0.1/unused".into(),
    )]))
    .unwrap();
    config.enabled = true;
    config.client_id = Uuid::now_v7();
    config.client_secret = "fixture-only-unusable-client-secret-9A".into();
    config.resource_client_id = "fixture-profile-client".into();
    config.resource_client_secret = "fixture-only-unusable-profile-secret-8B".into();
    config.keys = Some(Arc::new(CipherKeys::fixture()));
    config
}
fn state(script: Vec<(Endpoint, u16, Value)>) -> AppState {
    AppState {
        config: Arc::new(config()),
        pool: sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://fixture@127.0.0.1/unused")
            .unwrap(),
        transport: Arc::new(Script(Mutex::new(script.into()))),
        authority_slots: Arc::new(tokio::sync::Semaphore::new(16)),
    }
}
fn session(state: &AppState) -> store::Session {
    let id = Uuid::now_v7();
    let client = state.config.client_id;
    let issuer = state.config.issuer.clone();
    store::Session {
        id,
        browser_id: Uuid::now_v7(),
        user_id: Uuid::now_v7(),
        account_version: 0,
        global_session_id: Uuid::now_v7(),
        oidc_client_id: client,
        oidc_grant_id: Uuid::now_v7(),
        oidc_client_policy_version: 1,
        issuer: issuer.clone(),
        auth_time: Utc::now().timestamp() - 10,
        nonce_hash: b::digest("fixture-nonce"),
        access_ciphertext: state
            .config
            .keys
            .as_ref()
            .unwrap()
            .seal(id, &issuer, client, "oidc-access", &"a".repeat(64))
            .unwrap(),
        refresh_ciphertext: state
            .config
            .keys
            .as_ref()
            .unwrap()
            .seal(id, &issuer, client, "oidc-refresh", &"b".repeat(64))
            .unwrap(),
        access_expires_at: Utc::now() + Duration::minutes(5),
        version: 1,
        membership_id: None,
        organization_id: None,
        identity_version: None,
        customer_ciphertext: None,
        customer_expires_at: None,
        customer_needs_renewal: false,
        refresh_lease_id: None,
        refresh_uncertain: false,
        context_lease_id: None,
        logout_request_id: None,
        logout_scope: None,
        logout_confirmed_at: None,
        expires_at: Utc::now() + Duration::hours(1),
        revoked_at: None,
    }
}
fn proof(s: &store::Session) -> Value {
    json!({"active":true,"client_id":s.oidc_client_id,"aud":s.oidc_client_id,"iss":s.issuer,"token_type":"Bearer","scope":"openid profile offline_access",
        "sub":s.user_id,"sid":s.global_session_id,"exp":s.access_expires_at.timestamp(),"accountProof":{"contractVersion":"oidc-account-proof/1","clientPurpose":"CUSTOMER_PORTAL","allowedMemberTypes":["CUSTOMER"],
        "grantId":s.oidc_grant_id,"accountVersion":s.account_version.to_string(),"clientPolicyVersion":s.oidc_client_policy_version.to_string(),"authTime":s.auth_time}})
}
fn account(s: &store::Session) -> Value {
    json!({"id":s.user_id,"username":"fixture","realName":"Fixture","avatar":""})
}
fn member(s: &store::Session) -> resource::Membership {
    resource::Membership {
        membership_id: Uuid::now_v7(),
        user_id: s.user_id,
        member_type: "CUSTOMER".into(),
        identity_version: "1".into(),
        organization_id: Uuid::now_v7(),
        organization_name: "Owned organization".into(),
        tenant_id: Uuid::now_v7(),
        tenant_name: "Owned tenant".into(),
    }
}
fn memberships(s: &store::Session, m: &resource::Membership) -> Value {
    json!({"contractVersion":"customer-portal-account/1","account":account(s),"memberships":[m],"source":{"issuer":s.issuer,"clientId":s.oidc_client_id,"grantId":s.oidc_grant_id,"globalSessionId":s.global_session_id,"userId":s.user_id,
        "accountVersion":s.account_version.to_string(),"clientPolicyVersion":s.oidc_client_policy_version.to_string(),"authTime":s.auth_time,"expiresAt":s.access_expires_at}})
}
fn context(s: &store::Session, m: &resource::Membership) -> resource::Context {
    serde_json::from_value(json!({"contractVersion":"customer-profile/1","purpose":"CUSTOMER_PROFILE","userId":s.user_id,"membershipId":m.membership_id,"memberType":"CUSTOMER","identityVersion":m.identity_version,"accountVersion":s.account_version.to_string(),
        "tenant":{"id":m.tenant_id,"name":m.tenant_name},"organization":{"id":m.organization_id,"name":m.organization_name},"application":{"id":Uuid::now_v7(),"code":"owned-profile","name":"Owned profile","entryPath":"/api/customer/profile"}})).unwrap()
}
#[test]
fn canonical_identifiers_and_generations_do_not_normalize_untrusted_input() {
    let id = Uuid::now_v7().to_string();
    assert!(b::id(&id).is_ok());
    assert!(b::id(&id.to_uppercase()).is_err());
    for id in [
        "00000000-0000-4000-8000-000000000000",
        "00000000-0000-7000-c000-000000000000",
        "garbage",
    ] {
        assert!(b::id(id).is_err());
    }
    for value in ["01", "+1", " 1", "-1", "1.0", "9223372036854775808"] {
        assert!(b::version(value, 0).is_err());
    }
    assert_eq!(b::version("0", 0).unwrap(), 0);
    assert!(b::version("0", 1).is_err());
}
#[test]
fn cookies_are_host_only_and_credentials_are_independently_bound() {
    let secret = b::secret().unwrap();
    assert!(b::canonical_secret(&secret));
    assert_ne!(b::csrf(&secret), b::digest(&secret));
    let cookie = b::cookie(b::SESSION_COOKIE, &secret, 300);
    assert!(cookie.contains("Path=/; Secure; HttpOnly; SameSite=Lax"));
    assert!(!cookie.contains("Domain="));
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "{}={secret}; {}={secret}",
            b::SESSION_COOKIE,
            b::SESSION_COOKIE
        ))
        .unwrap(),
    );
    assert!(b::cookie_value(&headers, b::SESSION_COOKIE).is_err());
    headers.clear();
    headers.insert(
        "x-csrf-token",
        HeaderValue::from_str(&b::csrf(&secret)).unwrap(),
    );
    assert!(b::require_csrf(&headers, &secret).is_ok());
    assert!(b::require_csrf(&headers, &"c".repeat(64)).is_err());
}
#[test]
fn redirect_and_callback_parser_reject_duplicates_open_redirects_and_controls() {
    for path in [
        "//evil.test",
        "/%2f%2fevil.test",
        "/\\evil.test",
        "/auth/callback",
        "/%61uth/callback",
        "/x#fragment",
        "/x%0aheader",
    ] {
        assert!(b::return_path(path).is_err(), "accepted unsafe path");
    }
    assert_eq!(
        b::return_path("/profile?tab=account").unwrap(),
        "/profile?tab=account"
    );
    for query in [
        "state=x&state=y",
        "st%61te=x&state=y",
        "x=%G0",
        "x=%00",
        "x=%",
    ] {
        assert!(b::parameters(Some(query.into())).is_err());
    }
}
#[test]
fn disabled_default_never_loads_provisioned_secret_files() {
    let values = HashMap::from([
        (
            "DATABASE_URL".into(),
            "postgres://fixture@127.0.0.1/unused".into(),
        ),
        ("PORTAL_TOKEN_KEY_FILE".into(), "missing-private-key".into()),
    ]);
    let config = Config::from_values(&values).unwrap();
    assert!(!config.enabled);
    assert!(config.keys.is_none());
    for (key, value) in [
        ("PUBLIC_CUSTOMER_URL", "http://customer.saas.test"),
        ("OIDC_ISSUER", "https://auth.saas.test/"),
        ("OIDC_REDIRECT_URI", "https://evil.test/auth/callback"),
        ("CUSTOMER_PORTAL_ENABLED", "yes"),
    ] {
        let mut v = values.clone();
        v.insert(key.into(), value.into());
        assert!(Config::from_values(&v).is_err());
    }
}
#[test]
fn aead_rejects_record_client_issuer_kind_and_ciphertext_substitution() {
    let keys = CipherKeys::fixture();
    let record = Uuid::now_v7();
    let client = Uuid::now_v7();
    let plain = "fixture-not-a-real-token";
    let a = keys
        .seal(
            record,
            "https://auth.saas.test",
            client,
            "oidc-refresh",
            plain,
        )
        .unwrap();
    let b = keys
        .seal(
            record,
            "https://auth.saas.test",
            client,
            "oidc-refresh",
            plain,
        )
        .unwrap();
    assert_ne!(a, b);
    assert!(!a.contains(plain));
    assert_eq!(
        keys.open(record, "https://auth.saas.test", client, "oidc-refresh", &a)
            .unwrap(),
        plain
    );
    for (r, i, c, k) in [
        (
            Uuid::now_v7(),
            "https://auth.saas.test",
            client,
            "oidc-refresh",
        ),
        (record, "https://other.test", client, "oidc-refresh"),
        (
            record,
            "https://auth.saas.test",
            Uuid::now_v7(),
            "oidc-refresh",
        ),
        (record, "https://auth.saas.test", client, "customer-context"),
    ] {
        assert!(keys.open(r, i, c, k, &a).is_err());
    }
}
#[tokio::test]
async fn exact_customer_purpose_is_required_before_userinfo() {
    for (purpose, types, active) in [
        ("PLATFORM_CONSOLE", json!(["EMPLOYEE"]), true),
        ("CUSTOMER_PORTAL", json!(["CUSTOMER", "EMPLOYEE"]), true),
        ("CUSTOMER_PORTAL", json!(["CUSTOMER"]), false),
    ] {
        let mut state = state(vec![]);
        let s = session(&state);
        let mut value = proof(&s);
        value["accountProof"]["clientPurpose"] = json!(purpose);
        value["accountProof"]["allowedMemberTypes"] = types;
        value["active"] = json!(active);
        state.transport = Arc::new(Script(Mutex::new(VecDeque::from([(
            Endpoint::Introspect,
            200,
            value,
        )]))));
        assert!(
            protocol::existing(&Chain::new(&state).unwrap(), &s, &"a".repeat(64))
                .await
                .is_err()
        );
    }
}
#[tokio::test]
async fn source_subject_grant_and_userinfo_cannot_adopt_a_different_account() {
    for field in ["sub", "sid", "grantId", "userinfo"] {
        let mut state = state(vec![]);
        let s = session(&state);
        let mut value = proof(&s);
        let mut subject = s.user_id;
        if field == "userinfo" {
            subject = Uuid::now_v7();
        } else if field == "grantId" {
            value["accountProof"][field] = json!(Uuid::now_v7());
        } else {
            value[field] = json!(Uuid::now_v7());
        }
        let mut script = VecDeque::from([(Endpoint::Introspect, 200, value)]);
        if field == "userinfo" {
            script.push_back((Endpoint::UserInfo, 200, json!({"sub":subject})));
        }
        state.transport = Arc::new(Script(Mutex::new(script)));
        assert!(
            protocol::existing(&Chain::new(&state).unwrap(), &s, &"a".repeat(64))
                .await
                .is_err()
        );
    }
}
#[tokio::test]
async fn resource_rejects_employee_foreign_member_and_source_generation_changes() {
    for field in ["memberType", "userId", "accountVersion", "grantId", "extra"] {
        let mut state = state(vec![]);
        let s = session(&state);
        let m = member(&s);
        let mut value = memberships(&s, &m);
        match field {
            "memberType" => value["memberships"][0][field] = json!("EMPLOYEE"),
            "userId" => value["memberships"][0][field] = json!(Uuid::now_v7()),
            "extra" => value["account"]["permissions"] = json!(["ADMIN"]),
            _ => value["source"][field] = json!("2"),
        }
        state.transport = Arc::new(Script(Mutex::new(VecDeque::from([(
            Endpoint::Memberships,
            200,
            value,
        )]))));
        assert!(
            resource::memberships(&Chain::new(&state).unwrap(), &s, &"a".repeat(64))
                .await
                .is_err()
        );
    }
}
#[tokio::test]
async fn resource_cpc_capability_and_phase6_projection_are_accepted_without_exposing_opaque() {
    let mut state = state(vec![]);
    let s = session(&state);
    let m = member(&s);
    let c = context(&s, &m);
    let opaque = format!("cpc_{}", "d".repeat(64));
    state.transport = Arc::new(Script(Mutex::new(VecDeque::from([
        (
            Endpoint::Context,
            200,
            json!({"customerContext":opaque,"expiresAt":s.access_expires_at,"context":c,"account":account(&s)}),
        ),
        (Endpoint::ContextRevoke, 200, json!({"revoked":true})),
    ]))));
    let chain = Chain::new(&state).unwrap();
    let issued = resource::issue(&chain, &s, &"a".repeat(64), &m)
        .await
        .unwrap();
    assert!(serde_json::to_string(&issued.context)
        .unwrap()
        .contains("customer-profile/1"));
    assert!(!serde_json::to_string(&issued.context)
        .unwrap()
        .contains("cpc_"));
    resource::revoke(&chain, &"a".repeat(64), &issued.customer_context)
        .await
        .unwrap();
}
#[tokio::test]
async fn resource_revocation_requires_an_unambiguous_positive_receipt() {
    for (status, body) in [
        (200, json!({"revoked": false})),
        (200, json!({"error": "temporarily_unavailable"})),
        (200, json!({"revoked": true, "error": "unknown_outcome"})),
        (204, Value::Null),
    ] {
        let state = state(vec![(Endpoint::ContextRevoke, status, body)]);
        let chain = Chain::new(&state).unwrap();
        assert!(matches!(
            resource::revoke(&chain, &"a".repeat(64), &format!("cpc_{}", "d".repeat(64))).await,
            Err(AppError::Unavailable)
        ));
    }
}
#[tokio::test]
async fn backchannel_concurrency_is_bounded_and_does_not_queue_authority_work() {
    let state = state(vec![]);
    let chains: Vec<_> = (0..16).map(|_| Chain::new(&state).unwrap()).collect();
    assert!(matches!(Chain::new(&state), Err(AppError::Unavailable)));
    drop(chains);
    assert!(Chain::new(&state).is_ok());
}
#[tokio::test]
async fn static_routes_are_minimal_and_all_responses_prohibit_storage() {
    let app = crate::routes::routes().with_state(state(vec![]));
    for path in ["/auth/config", "/health"] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert!(body.get("accessToken").is_none());
    }
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/admin/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

mod pg;
