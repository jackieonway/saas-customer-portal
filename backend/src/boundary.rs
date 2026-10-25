use crate::{error::AppError, AppState};
use axum::http::{header, HeaderMap};
use rand::RngCore;
use sha2::{Digest, Sha256};
use uuid::{Uuid, Variant};

pub(crate) const BROWSER_COOKIE: &str = "__Host-saas_customer_browser";
pub(crate) const LOGIN_COOKIE: &str = "__Host-saas_customer_login";
pub(crate) const SESSION_COOKIE: &str = "__Host-saas_customer";
pub(crate) fn bad() -> AppError {
    AppError::bad_request("门户请求参数无效")
}
pub(crate) fn invalid() -> AppError {
    AppError::unauthorized("门户认证或客户身份已失效，请重新登录")
}
pub(crate) fn id(value: &str) -> Result<Uuid, AppError> {
    let id = Uuid::parse_str(value).map_err(|_| bad())?;
    if id.get_version_num() != 7 || id.get_variant() != Variant::RFC4122 || id.to_string() != value
    {
        return Err(bad());
    }
    Ok(id)
}
pub(crate) fn version(value: &str, min: i64) -> Result<i64, AppError> {
    let n = value.parse::<i64>().map_err(|_| bad())?;
    if n < min || n.to_string() != value {
        return Err(bad());
    }
    Ok(n)
}
pub(crate) fn secret() -> Result<String, AppError> {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AppError::Unavailable)?;
    Ok(hex::encode(bytes))
}
pub(crate) fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
pub(crate) fn csrf(cookie: &str) -> String {
    digest(&format!("customer-portal-csrf/1:{cookie}"))
}
pub(crate) fn equal(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0u8, |v, (l, r)| v | (l ^ r))
            == 0
}
pub(crate) fn canonical_secret(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn enabled(state: &AppState) -> Result<(), AppError> {
    if !state.config.enabled {
        return Err(AppError::Unavailable);
    }
    Ok(())
}
pub(crate) fn unique<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, AppError> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(AppError::forbidden("门户请求头重复"));
    }
    first
        .map(|v| {
            v.to_str()
                .map_err(|_| AppError::forbidden("门户请求头无效"))
        })
        .transpose()
}
pub(crate) fn host(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    enabled(state)?;
    if headers.contains_key(header::AUTHORIZATION)
        || unique(headers, "host")? != state.config.public_origin.strip_prefix("https://")
    {
        return Err(AppError::forbidden("门户主机或认证方式无效"));
    }
    Ok(())
}
pub(crate) fn origin(state: &AppState, headers: &HeaderMap, read: bool) -> Result<(), AppError> {
    host(state, headers)?;
    match unique(headers, "origin")? {
        Some(value) if value == state.config.public_origin => Ok(()),
        None if read && unique(headers, "sec-fetch-site")? == Some("same-origin") => Ok(()),
        _ => Err(AppError::forbidden("门户请求来源无效")),
    }
}
pub(crate) fn cookie_value<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, AppError> {
    let mut found = None;
    for h in headers.get_all(header::COOKIE) {
        for pair in h.to_str().map_err(|_| invalid())?.split(';') {
            let (key, value) = pair.trim().split_once('=').ok_or_else(invalid)?;
            if key == name {
                if found.is_some() || !canonical_secret(value) {
                    return Err(invalid());
                }
                found = Some(value);
            }
        }
    }
    Ok(found)
}
pub(crate) fn cookie(name: &str, value: &str, ttl: i64) -> String {
    format!(
        "{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        ttl.max(0)
    )
}
pub(crate) fn require_csrf(headers: &HeaderMap, cookie: &str) -> Result<(), AppError> {
    let supplied = unique(headers, "x-csrf-token")?
        .ok_or_else(|| AppError::forbidden("缺少门户 CSRF 证明"))?;
    if !canonical_secret(supplied) || !equal(supplied, &csrf(cookie)) {
        return Err(AppError::forbidden("门户 CSRF 证明无效"));
    }
    Ok(())
}
pub(crate) fn parameters(
    raw: Option<String>,
) -> Result<std::collections::BTreeMap<String, String>, AppError> {
    let raw = raw.unwrap_or_default();
    if raw.len() > 16384 {
        return Err(bad());
    }
    let mut values = std::collections::BTreeMap::new();
    for pair in raw.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let decode = |s: &str| -> Result<String, AppError> {
            let bytes = s.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'%' {
                    if i + 2 >= bytes.len()
                        || !bytes[i + 1].is_ascii_hexdigit()
                        || !bytes[i + 2].is_ascii_hexdigit()
                    {
                        return Err(bad());
                    }
                    i += 3;
                } else {
                    i += 1;
                }
            }
            let value = percent_encoding::percent_decode_str(&s.replace('+', " "))
                .decode_utf8()
                .map_err(|_| bad())?
                .into_owned();
            if value.chars().any(char::is_control) {
                return Err(bad());
            }
            Ok(value)
        };
        let k = decode(k)?;
        let v = decode(v)?;
        if k.is_empty()
            || k.len() > 80
            || v.len() > 4096
            || values.len() >= 16
            || values.insert(k, v).is_some()
        {
            return Err(bad());
        }
    }
    Ok(values)
}
pub(crate) fn return_path(raw: &str) -> Result<String, AppError> {
    if raw.is_empty() || raw.len() > 2048 {
        return Err(bad());
    }
    let mut decoded = raw.to_owned();
    for _ in 0..8 {
        if !decoded.starts_with('/')
            || decoded.starts_with("//")
            || decoded.contains('\\')
            || decoded.chars().any(char::is_control)
        {
            return Err(bad());
        }
        let url =
            reqwest::Url::parse(&format!("https://return.invalid{decoded}")).map_err(|_| bad())?;
        if url.host_str() != Some("return.invalid")
            || url.fragment().is_some()
            || url.path() == "/auth"
            || url.path().starts_with("/auth/")
            || url.path() == "/signed-out"
        {
            return Err(bad());
        }
        let next = percent_encoding::percent_decode_str(&decoded)
            .decode_utf8()
            .map_err(|_| bad())?
            .into_owned();
        if next == decoded {
            return Ok(raw.to_owned());
        }
        decoded = next;
    }
    Err(bad())
}
