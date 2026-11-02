use super::*;
use jsonwebtoken::{EncodingKey, Header as JwtHeader};
use serde_json::{json, Value};

#[path = "test_key.rs"]
mod test_key;

pub(crate) fn jwks() -> Value {
    json!({"keys":[{"kid":"portal-logout-fixture","kty":"RSA","alg":"RS256","use":"sig","n":test_key::N,"e":"AQAB"}]})
}

pub(crate) fn signed(claims: &Value) -> String {
    let mut header = JwtHeader::new(Algorithm::RS256);
    header.kid = Some("portal-logout-fixture".into());
    header.typ = Some("logout+jwt".into());
    jsonwebtoken::encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(test_key::PEM.as_bytes()).unwrap(),
    )
    .unwrap()
}

pub(crate) fn signed_id_token(claims: &Value) -> String {
    let mut header = JwtHeader::new(Algorithm::RS256);
    header.kid = Some("portal-logout-fixture".into());
    jsonwebtoken::encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(test_key::PEM.as_bytes()).unwrap(),
    )
    .unwrap()
}

pub(crate) fn payload(session: &crate::store::Session) -> Value {
    let now = Utc::now().timestamp();
    json!({"iss":session.issuer,"aud":session.oidc_client_id.to_string(),"sid":session.oidc_public_sid,
        "sub":session.oidc_public_sub,"jti":Uuid::now_v7().to_string(),"iat":now,"exp":now+120,
        "events":{"http://schemas.openid.net/event/backchannel-logout":{}}})
}

#[test]
fn signed_logout_requires_exact_event_subject_audience_and_short_original_time() {
    let issuer = "https://identity.example.test";
    let client = Uuid::now_v7().to_string();
    let now = Utc::now().timestamp();
    let claims = json!({"iss":issuer,"aud":client,"sid":"a".repeat(64),"sub":"opaque-account-without-uuid",
        "jti":Uuid::now_v7().to_string(),"iat":now,"exp":now+120,
        "events":{"http://schemas.openid.net/event/backchannel-logout":{}}});
    let key = DecodingKey::from_rsa_components(test_key::N, "AQAB").unwrap();
    assert!(validate(&signed(&claims), &key, issuer, &client, now).is_ok());
    for (name, value) in [
        ("iss", json!("https://other.example.test")),
        ("aud", json!(Uuid::now_v7())),
        ("aud", json!([client.clone()])),
        ("sid", json!("private-session-uuid")),
        ("sub", json!("")),
        ("jti", json!("00000000-0000-4000-8000-000000000000")),
        ("nonce", json!("forbidden")),
        ("events", json!({})),
        (
            "events",
            json!({"http://schemas.openid.net/event/backchannel-logout":{"x":1}}),
        ),
        (
            "events",
            json!({"http://schemas.openid.net/event/backchannel-logout":{},"other":{}}),
        ),
        ("iat", json!(now + 6)),
        ("iat", json!(now - 121)),
        ("exp", json!(now + 121)),
        ("exp", json!(now)),
    ] {
        let mut wrong = claims.clone();
        wrong[name] = value;
        assert!(
            validate(&signed(&wrong), &key, issuer, &client, now).is_err(),
            "field={name}"
        );
    }
    let token = signed(&claims);
    let mut wrong = token.into_bytes();
    let last = wrong.len() - 5;
    wrong[last] = if wrong[last] == b'A' { b'B' } else { b'A' };
    assert!(validate(
        std::str::from_utf8(&wrong).unwrap(),
        &key,
        issuer,
        &client,
        now
    )
    .is_err());
}

#[test]
fn logout_structs_reject_duplicate_claims_and_borrowed_oidc_token_shapes() {
    let duplicate = r#"{"iss":"a","iss":"b","aud":"x","sid":"a","sub":"x","jti":"x","iat":1,"exp":121,"events":{"http://schemas.openid.net/event/backchannel-logout":{}}}"#;
    assert!(serde_json::from_str::<Claims>(duplicate).is_err());
    assert!(serde_json::from_str::<Events>(r#"{"http://schemas.openid.net/event/backchannel-logout":{},"http://schemas.openid.net/event/backchannel-logout":{}}"#).is_err());
    assert!(serde_json::from_str::<Header>(
        r#"{"alg":"RS256","kid":"x","kid":"y","typ":"logout+jwt"}"#
    )
    .is_err());
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"x","typ":"JWT"}"#);
    assert!(strict_header(&format!("{header}.e30.eA")).is_err());
}
