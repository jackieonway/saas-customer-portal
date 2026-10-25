use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub(crate) enum AppError {
    #[error("{0}")]
    BadRequest(&'static str),
    #[error("{0}")]
    Unauthorized(&'static str),
    #[error("{0}")]
    Forbidden(&'static str),
    #[error("{0}")]
    Conflict(&'static str),
    #[error("认证服务暂不可用，请稍后重试")]
    Unavailable,
}
impl AppError {
    pub(crate) fn unauthorized(message: &'static str) -> Self {
        Self::Unauthorized(message)
    }
    pub(crate) fn bad_request(message: &'static str) -> Self {
        Self::BadRequest(message)
    }
    pub(crate) fn forbidden(message: &'static str) -> Self {
        Self::Forbidden(message)
    }
    pub(crate) fn conflict(message: &'static str) -> Self {
        Self::Conflict(message)
    }
}
impl From<sqlx::Error> for AppError {
    fn from(_: sqlx::Error) -> Self {
        Self::Unavailable
    }
}
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            Self::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            Self::Forbidden(_) => (StatusCode::FORBIDDEN, "FORBIDDEN"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "UNAVAILABLE"),
        };
        (
            status,
            Json(json!({"code":code,"message":self.to_string()})),
        )
            .into_response()
    }
}
