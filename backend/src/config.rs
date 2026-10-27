use crate::{boundary::id, crypto::CipherKeys};
use std::{collections::HashMap, net::SocketAddr, path::Path, sync::Arc, time::Duration};
use uuid::Uuid;

pub(crate) struct Config {
    pub enabled: bool,
    pub context_selection_enabled: bool,
    pub selection_client_id: String,
    pub selection_client_secret: String,
    pub database_url: String,
    pub bind_addr: SocketAddr,
    pub public_origin: String,
    pub issuer: String,
    pub client_id: Uuid,
    pub client_secret: String,
    pub redirect_uri: String,
    pub resource_origin: String,
    pub resource_client_id: String,
    pub resource_client_secret: String,
    pub keys: Option<Arc<CipherKeys>>,
    pub oidc_http: reqwest::Client,
    pub resource_http: reqwest::Client,
}

fn required<'a>(values: &'a HashMap<String, String>, name: &str) -> anyhow::Result<&'a str> {
    values
        .get(name)
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{name} is required"))
}
fn origin(value: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(value).map_err(|_| anyhow::anyhow!("invalid HTTPS origin"))?;
    anyhow::ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/"
            && url.origin().ascii_serialization() == value,
        "exact HTTPS origin required"
    );
    Ok(())
}
fn secret(value: &str) -> anyhow::Result<()> {
    let unique: std::collections::HashSet<u8> = value.bytes().collect();
    anyhow::ensure!(
        value.len() >= 32
            && value.len() <= 4096
            && unique.len() >= 8
            && !value.chars().any(char::is_control),
        "strong confidential secret required"
    );
    Ok(())
}
fn client(values: &HashMap<String, String>, ca_key: &str) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(3))
        .user_agent("SaaSCustomerPortal-BFF/1");
    if let Some(path) = values.get(ca_key) {
        anyhow::ensure!(Path::new(path).is_absolute(), "CA file must be absolute");
        let bytes = std::fs::read(path).map_err(|_| anyhow::anyhow!("CA file cannot be read"))?;
        anyhow::ensure!(bytes.len() <= 65536, "CA file too large");
        let certs = reqwest::Certificate::from_pem_bundle(&bytes)
            .map_err(|_| anyhow::anyhow!("CA file invalid"))?;
        anyhow::ensure!(!certs.is_empty(), "CA file empty");
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder
        .build()
        .map_err(|_| anyhow::anyhow!("HTTPS client configuration invalid"))
}
impl Config {
    pub(crate) fn from_values(values: &HashMap<String, String>) -> anyhow::Result<Self> {
        let enabled = match values
            .get("CUSTOMER_PORTAL_ENABLED")
            .map(String::as_str)
            .unwrap_or("false")
        {
            "true" => true,
            "false" => false,
            _ => anyhow::bail!("CUSTOMER_PORTAL_ENABLED must be true or false"),
        };
        let database_url = required(values, "DATABASE_URL")?.to_owned();
        let db = reqwest::Url::parse(&database_url)
            .map_err(|_| anyhow::anyhow!("invalid portal database URL"))?;
        anyhow::ensure!(
            matches!(db.scheme(), "postgres" | "postgresql"),
            "PostgreSQL database required"
        );
        let bind_addr = values
            .get("BIND_ADDR")
            .map(String::as_str)
            .unwrap_or("127.0.0.1:8092")
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid BIND_ADDR"))?;
        // Disabled mode starts no authentication and loads no secret files.
        let public_origin = values
            .get("PUBLIC_CUSTOMER_URL")
            .cloned()
            .unwrap_or_else(|| "https://customer.saas.test".into());
        origin(&public_origin)?;
        let issuer = values
            .get("OIDC_ISSUER")
            .cloned()
            .unwrap_or_else(|| "https://auth.saas.test".into());
        origin(&issuer)?;
        let resource_origin = values
            .get("CUSTOMER_RESOURCE_URL")
            .cloned()
            .unwrap_or_else(|| "https://console.saas.test".into());
        origin(&resource_origin)?;
        let redirect_uri = values
            .get("OIDC_REDIRECT_URI")
            .cloned()
            .unwrap_or_else(|| format!("{public_origin}/auth/callback"));
        anyhow::ensure!(
            redirect_uri == format!("{public_origin}/auth/callback"),
            "exact portal callback required"
        );
        anyhow::ensure!(
            reqwest::Url::parse(&public_origin)?.host_str()
                != reqwest::Url::parse(&issuer)?.host_str(),
            "separate portal hostname required"
        );
        let client_id = if enabled {
            id(required(values, "OIDC_CLIENT_ID")?)
                .map_err(|_| anyhow::anyhow!("OIDC_CLIENT_ID must be canonical RFC UUID v7"))?
        } else {
            Uuid::nil()
        };
        let client_secret = values
            .get("OIDC_CLIENT_SECRET")
            .cloned()
            .unwrap_or_default();
        let resource_client_id = values
            .get("CUSTOMER_RESOURCE_CLIENT_ID")
            .cloned()
            .unwrap_or_default();
        let resource_client_secret = values
            .get("CUSTOMER_RESOURCE_CLIENT_SECRET")
            .cloned()
            .unwrap_or_default();
        let keys = if enabled {
            secret(&client_secret)?;
            secret(&resource_client_secret)?;
            anyhow::ensure!(
                !resource_client_id.is_empty()
                    && resource_client_id.len() <= 256
                    && !resource_client_id.contains(':')
                    && !resource_client_id.chars().any(char::is_control),
                "resource client id invalid"
            );
            anyhow::ensure!(
                resource_client_id != client_id.to_string()
                    && client_secret != resource_client_secret,
                "OIDC and resource confidential clients must be independent"
            );
            Some(Arc::new(CipherKeys::load(required(
                values,
                "PORTAL_TOKEN_KEY_FILE",
            )?)?))
        } else {
            None
        };
        let context_selection_enabled = match values
            .get("CONTEXT_SELECTION_ENABLED")
            .map(String::as_str)
            .unwrap_or("false")
        {
            "true" => true,
            "false" => false,
            _ => anyhow::bail!("CONTEXT_SELECTION_ENABLED must be true or false"),
        };
        let selection_client_id = values
            .get("CONTEXT_SELECTION_CONSUMER_ID")
            .cloned()
            .unwrap_or_default();
        let selection_client_secret = values
            .get("CONTEXT_SELECTION_CONSUMER_SECRET")
            .cloned()
            .unwrap_or_default();
        if context_selection_enabled {
            anyhow::ensure!(enabled, "context selection requires enabled portal");
            id(&selection_client_id)
                .map_err(|_| anyhow::anyhow!("selection consumer id must be canonical UUIDv7"))?;
            anyhow::ensure!(
                selection_client_id != client_id.to_string()
                    && selection_client_id != resource_client_id
                    && selection_client_secret != client_secret
                    && selection_client_secret != resource_client_secret
                    && selection_client_secret.len() == 64
                    && selection_client_secret
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "independent selection consumer required"
            );
        } else {
            anyhow::ensure!(
                selection_client_id.is_empty() && selection_client_secret.is_empty(),
                "selection credentials require explicit enablement"
            );
        }
        Ok(Self {
            context_selection_enabled,
            selection_client_id,
            selection_client_secret,
            enabled,
            database_url,
            bind_addr,
            public_origin,
            issuer,
            client_id,
            client_secret,
            redirect_uri,
            resource_origin,
            resource_client_id,
            resource_client_secret,
            keys,
            oidc_http: client(values, "OIDC_CA_FILE")?,
            resource_http: client(values, "CUSTOMER_RESOURCE_CA_FILE")?,
        })
    }
}
