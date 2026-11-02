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
    config.source_service_id = Uuid::now_v7();
    config.source_service_secret = "ab".repeat(32);
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
        pending_selection_ciphertext: None,
        id,
        browser_id: Uuid::now_v7(),
        user_id: Uuid::now_v7(),
        account_version: 1,
        global_session_id: Uuid::now_v7(),
        oidc_client_id: client,
        oidc_grant_id: Uuid::now_v7(),
        oidc_client_policy_version: 1,
        issuer: issuer.clone(),
        oidc_public_sid: b::secret().unwrap(),
        oidc_public_sub: "pairwise-customer-fixture-no-uuid".into(),
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
    json!({"contractVersion":"customer-account-proof/1","clientId":s.oidc_client_id,"issuer":s.issuer,
        "clientPurpose":"CUSTOMER_PORTAL","contextMode":"PLATFORM_CONTEXT","allowedMemberTypes":["CUSTOMER"],"scope":["openid","profile"],
        "sub":"pairwise-customer-fixture-no-uuid","userId":s.user_id,"globalSessionId":s.global_session_id,
        "grantId":s.oidc_grant_id,"accountVersion":s.account_version.to_string(),"clientPolicyVersion":s.oidc_client_policy_version.to_string(),
        "applicationProjectionVersion":"1","authTime":s.auth_time,"expiresAt":s.access_expires_at,"absoluteExpiresAt":s.expires_at})
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
        value["clientPurpose"] = json!(purpose);
        value["allowedMemberTypes"] = types;
        state.transport = Arc::new(Script(Mutex::new(VecDeque::from([(
            Endpoint::AccountProof,
            if active { 200 } else { 401 },
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
    for field in ["userId", "globalSessionId", "grantId", "sub", "userinfo"] {
        let mut state = state(vec![]);
        let s = session(&state);
        let mut value = proof(&s);
        let mut subject = "pairwise-customer-fixture-no-uuid";
        if field == "userinfo" {
            subject = "pairwise-another-customer-account";
        } else if field == "sub" {
            value[field] = json!("pairwise-unrelated-customer-account");
        } else {
            value[field] = json!(Uuid::now_v7());
        }
        let mut script = VecDeque::from([(Endpoint::AccountProof, 200, value)]);
        if matches!(field, "sub" | "userinfo") {
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

fn discovery() -> Value {
    let issuer = "https://auth.saas.test";
    json!({"issuer":issuer,"authorization_endpoint":format!("{issuer}/oauth/authorize"),
        "token_endpoint":format!("{issuer}/oauth/token"),"jwks_uri":format!("{issuer}/oauth/jwks"),
        "userinfo_endpoint":format!("{issuer}/oauth/userinfo"),"introspection_endpoint":format!("{issuer}/oauth/introspect"),
        "revocation_endpoint":format!("{issuer}/oauth/revoke"),"response_types_supported":["code"],
        "id_token_signing_alg_values_supported":["RS256"],"token_endpoint_auth_methods_supported":["client_secret_basic"],
        "code_challenge_methods_supported":["S256"]})
}

#[tokio::test]
async fn canonical_refresh_uses_access_proof_and_accepts_response_without_id_token() {
    let mut state = state(vec![]);
    let original = session(&state);
    let value = proof(&original);
    state.transport = Arc::new(Script(Mutex::new(VecDeque::from([
        (Endpoint::Discovery, 200, discovery()),
        (
            Endpoint::Token,
            200,
            json!({"token_type":"Bearer","access_token":"9".repeat(64),
            "refresh_token":"8".repeat(64),"expires_in":300,"scope":"openid profile"}),
        ),
        (Endpoint::AccountProof, 200, value),
        (
            Endpoint::UserInfo,
            200,
            json!({"sub":"pairwise-customer-fixture-no-uuid"}),
        ),
    ]))));
    let verified = protocol::refresh(&Chain::new(&state).unwrap(), &original, &"b".repeat(64))
        .await
        .unwrap();
    assert_eq!(verified.proof.user_id, original.user_id);
    assert_eq!(verified.proof.subject, "pairwise-customer-fixture-no-uuid");
    assert_eq!(verified.absolute_expires_at, original.expires_at);
    assert!(verified.selection.is_none());
}

#[tokio::test]
async fn canonical_code_exchange_requires_id_token_and_never_accepts_offline_scope() {
    for scope in ["openid profile", "openid profile offline_access"] {
        let state = state(vec![
            (Endpoint::Discovery, 200, discovery()),
            (
                Endpoint::Token,
                200,
                json!({"token_type":"Bearer","access_token":"9".repeat(64),
                "refresh_token":"8".repeat(64),"expires_in":300,"scope":scope}),
            ),
        ]);
        assert!(matches!(
            protocol::exchange(
                &Chain::new(&state).unwrap(),
                "owned-code",
                &"a".repeat(64),
                &b::digest("nonce")
            )
            .await,
            Err(AppError::Unauthorized(_))
        ));
    }
}

#[tokio::test]
async fn invalid_rp_credentials_are_unavailable_infrastructure_not_a_repaired_user_session() {
    let mut state = state(vec![]);
    let original = session(&state);
    state.transport = Arc::new(Script(Mutex::new(VecDeque::from([
        (Endpoint::Discovery, 200, discovery()),
        (Endpoint::Token, 401, json!({"error":"invalid_client"})),
    ]))));
    assert!(matches!(
        protocol::refresh(&Chain::new(&state).unwrap(), &original, &"b".repeat(64)).await,
        Err(AppError::Unavailable)
    ));
}

#[tokio::test]
async fn private_customer_proof_rejects_wrong_client_scope_versions_and_deadlines() {
    for (field, value) in [
        ("contractVersion", json!("platform-account-proof/1")),
        ("clientId", json!(Uuid::now_v7())),
        ("issuer", json!("https://other.saas.test")),
        ("contextMode", json!("ACCOUNT_ONLY")),
        ("scope", json!(["openid"])),
        ("scope", json!(["openid", "profile", "offline_access"])),
        ("sub", json!("")),
        ("sub", json!("unsafe\nsubject")),
        ("accountVersion", json!("0")),
        ("clientPolicyVersion", json!("01")),
        ("applicationProjectionVersion", json!("0")),
        ("authTime", json!(Utc::now().timestamp() + 61)),
        ("expiresAt", json!(Utc::now() - Duration::seconds(1))),
        ("absoluteExpiresAt", json!(Utc::now())),
    ] {
        let mut state = state(vec![]);
        let original = session(&state);
        let mut response = proof(&original);
        response[field] = value;
        state.transport = Arc::new(Script(Mutex::new(VecDeque::from([(
            Endpoint::AccountProof,
            200,
            response,
        )]))));
        assert!(
            protocol::existing(&Chain::new(&state).unwrap(), &original, &"a".repeat(64))
                .await
                .is_err(),
            "accepted {field}"
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

#[tokio::test]
async fn backchannel_rejects_query_duplicate_fields_and_browser_token_substitution() {
    let app = crate::routes::routes().with_state(state(vec![]));
    for (uri, body) in [
        ("/auth/backchannel-logout?token=hidden", "logout_token=x"),
        ("/auth/backchannel-logout", "logout_token=x&logout_token=y"),
        ("/auth/backchannel-logout", "logout_token=x&other=y"),
        ("/auth/backchannel-logout", "token=x"),
    ] {
        let result = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("host", "customer.saas.test")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(result.headers()["cache-control"], "no-store");
    }
}

#[tokio::test]
async fn canonical_logout_recovers_same_original_operation_before_any_revoke_attempt() {
    for scope in ["PORTAL", "GLOBAL"] {
        let mut state = state(vec![]);
        let session = session(&state);
        let op = Uuid::now_v7();
        let wire = if scope == "GLOBAL" {
            "GLOBAL"
        } else {
            "CURRENT_APP"
        };
        let receipt = json!({"operationId":op,"scope":wire,"state":"COMPLETED","revokedGrantCount":1,"revokedSsoCount":0,"notificationCount":1});
        state.transport = Arc::new(Script(Mutex::new(VecDeque::from([
            (
                Endpoint::LogoutOperation(op),
                404,
                json!({"code":"NOT_FOUND"}),
            ),
            (
                Endpoint::GlobalLogout,
                503,
                json!({"error":"temporarily_unavailable"}),
            ),
            (Endpoint::LogoutOperation(op), 200, receipt),
        ]))));
        let chain = Chain::new(&state).unwrap();
        assert!(matches!(
            protocol::logout(&chain, &session, &"b".repeat(64), scope, op).await,
            Err(AppError::Unavailable)
        ));
        protocol::logout(&chain, &session, &"b".repeat(64), scope, op)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn id_token_binds_opaque_public_session_and_refresh_cannot_replace_it() {
    let mut state = state(vec![]);
    let session = session(&state);
    let now = Utc::now().timestamp();
    let claims = json!({"iss":session.issuer,"aud":session.oidc_client_id,"sub":session.oidc_public_sub,
        "sid":session.oidc_public_sid,"iat":now,"exp":now+300,"auth_time":session.auth_time,"nonce":"fixture-nonce"});
    let tokens = |identity: String| json!({"access_token":"a".repeat(64),"refresh_token":"b".repeat(64),"token_type":"Bearer","scope":"openid profile","expires_in":300,"id_token":identity});
    let script = |tokens: Value, with_userinfo: bool| {
        let mut list = VecDeque::from([
            (Endpoint::Discovery, 200, discovery()),
            (Endpoint::Token, 200, tokens),
            (Endpoint::Jwks, 200, crate::backchannel::tests::jwks()),
            (Endpoint::AccountProof, 200, proof(&session)),
        ]);
        if with_userinfo {
            list.push_back((
                Endpoint::UserInfo,
                200,
                json!({"sub":session.oidc_public_sub}),
            ));
        }
        list
    };
    let initial = script(
        tokens(crate::backchannel::tests::signed_id_token(&claims)),
        true,
    );
    state.transport = Arc::new(Script(Mutex::new(initial)));
    let verified = protocol::exchange(
        &Chain::new(&state).unwrap(),
        "code",
        "verifier",
        &session.nonce_hash,
    )
    .await
    .unwrap();
    assert_eq!(verified.public_sid, session.oidc_public_sid);
    let mut changed = claims.clone();
    changed["sid"] = json!("9".repeat(64));
    let retry = VecDeque::from([
        (Endpoint::Discovery, 200, discovery()),
        (
            Endpoint::Token,
            200,
            tokens(crate::backchannel::tests::signed_id_token(&changed)),
        ),
        (Endpoint::Jwks, 200, crate::backchannel::tests::jwks()),
        (Endpoint::AccountProof, 200, proof(&session)),
    ]);
    state.transport = Arc::new(Script(Mutex::new(retry)));
    assert!(matches!(
        protocol::refresh(&Chain::new(&state).unwrap(), &session, &"b".repeat(64)).await,
        Err(AppError::Unauthorized(_))
    ));
    let mut missing = claims;
    missing.as_object_mut().unwrap().remove("sid");
    state.transport = Arc::new(Script(Mutex::new(VecDeque::from([
        (Endpoint::Discovery, 200, discovery()),
        (
            Endpoint::Token,
            200,
            tokens(crate::backchannel::tests::signed_id_token(&missing)),
        ),
        (Endpoint::Jwks, 200, crate::backchannel::tests::jwks()),
    ]))));
    assert!(matches!(
        protocol::exchange(
            &Chain::new(&state).unwrap(),
            "code",
            "verifier",
            &session.nonce_hash
        )
        .await,
        Err(AppError::Unauthorized(_))
    ));
}

mod pg;
