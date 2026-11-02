//! Bounded, fixed-capability HTTP. Neither browsers nor upstream documents can
//! supply a URL; all OIDC and resource calls share one request deadline.
use crate::{config::Config, error::AppError, AppState};
use std::{future::Future, pin::Pin, sync::Arc};

#[derive(Clone, Copy)]
pub(crate) enum Endpoint {
    Discovery,
    Jwks,
    Token,
    UserInfo,
    AccountProof,
    GlobalLogout,
    LogoutOperation(uuid::Uuid),
    Memberships,
    Context,
    Profile,
    ContextRevoke,
    ContextInteractions,
    SelectionConsume,
    SelectionResult,
}
impl Endpoint {
    pub(crate) fn path(self) -> String {
        let path = match self {
            Self::Discovery => "/.well-known/openid-configuration",
            Self::Jwks => "/oauth/jwks",
            Self::Token => "/oauth/token",
            Self::UserInfo => "/oauth/userinfo",
            Self::AccountProof => "/internal/identity/auth/customer-account-proof",
            Self::GlobalLogout => "/oauth/logout",
            Self::LogoutOperation(operation) => {
                return format!("/oauth/logout/operations/{operation}")
            }
            Self::Memberships => "/internal/customer-portal/memberships",
            Self::Context => "/internal/customer-portal/context",
            Self::Profile => "/internal/customer-portal/profile",
            Self::ContextRevoke => "/internal/customer-portal/revoke",
            Self::ContextInteractions => "/internal/identity/auth/context-interactions",
            Self::SelectionConsume => "/internal/platform/context-selection/consume",
            Self::SelectionResult => "/internal/platform/context-selection/result",
        };
        path.to_owned()
    }
    fn resource(self) -> bool {
        matches!(
            self,
            Self::Memberships
                | Self::Context
                | Self::Profile
                | Self::ContextRevoke
                | Self::SelectionConsume
                | Self::SelectionResult
        )
    }
    fn private_identity(self) -> bool {
        matches!(self, Self::AccountProof | Self::ContextInteractions)
    }
    fn post(self) -> bool {
        !matches!(self, Self::Discovery | Self::Jwks | Self::UserInfo)
    }
}
pub(crate) struct OidcRequest {
    pub endpoint: Endpoint,
    pub authorization: Option<String>,
    pub form: Vec<(String, String)>,
    pub json: Option<serde_json::Value>,
}
pub(crate) struct OidcResponse {
    pub status: u16,
    pub body: Vec<u8>,
}
pub(crate) type OidcFuture<'a> =
    Pin<Box<dyn Future<Output = Result<OidcResponse, AppError>> + Send + 'a>>;
pub(crate) trait OidcTransport: Send + Sync {
    fn send<'a>(&'a self, request: OidcRequest) -> OidcFuture<'a>;
}
struct HttpTransport {
    oidc: reqwest::Client,
    resource: reqwest::Client,
    identity: reqwest::Client,
    issuer: String,
    resource_origin: String,
    identity_origin: String,
}
pub(crate) fn configured(config: &Config) -> Arc<dyn OidcTransport> {
    Arc::new(HttpTransport {
        oidc: config.oidc_http.clone(),
        resource: config.resource_http.clone(),
        identity: config.identity_http.clone(),
        issuer: config.issuer.clone(),
        resource_origin: config.resource_origin.clone(),
        identity_origin: config.identity_origin.clone(),
    })
}
pub(crate) fn encode_form(parameters: &[(String, String)]) -> Result<String, AppError> {
    let mut url =
        reqwest::Url::parse("https://form.invalid/").map_err(|_| AppError::Unavailable)?;
    url.query_pairs_mut()
        .extend_pairs(parameters.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    Ok(url.query().unwrap_or("").to_owned())
}
impl OidcTransport for HttpTransport {
    fn send<'a>(&'a self, request: OidcRequest) -> OidcFuture<'a> {
        Box::pin(async move {
            let is_resource = request.endpoint.resource();
            let (client, origin) = if is_resource {
                (&self.resource, &self.resource_origin)
            } else if request.endpoint.private_identity() {
                (&self.identity, &self.identity_origin)
            } else {
                (&self.oidc, &self.issuer)
            };
            let url = format!("{origin}{}", request.endpoint.path());
            let mut outgoing = if request.endpoint.post() {
                client.post(url)
            } else {
                client.get(url)
            };
            if request.endpoint.post() {
                outgoing = if let Some(body) = request.json {
                    outgoing
                        .header("content-type", "application/json")
                        .body(serde_json::to_vec(&body).map_err(|_| AppError::Unavailable)?)
                } else if is_resource {
                    let object: serde_json::Map<String, serde_json::Value> = request
                        .form
                        .into_iter()
                        .map(|(k, v)| (k, serde_json::Value::String(v)))
                        .collect();
                    outgoing
                        .header("content-type", "application/json")
                        .body(serde_json::to_vec(&object).map_err(|_| AppError::Unavailable)?)
                } else {
                    outgoing
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(encode_form(&request.form)?)
                };
            }
            outgoing = outgoing.header("accept", "application/json");
            if let Some(auth) = request.authorization {
                outgoing = outgoing.header("authorization", auth);
            }
            let mut response = outgoing.send().await.map_err(|_| AppError::Unavailable)?;
            if response
                .content_length()
                .is_some_and(|length| length > 65536)
            {
                return Err(AppError::Unavailable);
            }
            let status = response.status().as_u16();
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| AppError::Unavailable)? {
                if body.len() + chunk.len() > 65536 {
                    return Err(AppError::Unavailable);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(OidcResponse { status, body })
        })
    }
}
pub(crate) struct Chain<'a> {
    pub state: &'a AppState,
    deadline: tokio::time::Instant,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl<'a> Chain<'a> {
    pub(crate) fn new(state: &'a AppState) -> Result<Self, AppError> {
        Ok(Self {
            state,
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(3),
            _permit: state
                .authority_slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| AppError::Unavailable)?,
        })
    }
    pub(crate) async fn send(&self, request: OidcRequest) -> Result<OidcResponse, AppError> {
        tokio::time::timeout_at(self.deadline, self.state.transport.send(request))
            .await
            .map_err(|_| AppError::Unavailable)?
    }
}
