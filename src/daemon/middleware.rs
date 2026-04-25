use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};

/// Header esperado para autenticação PSK.
pub const PSK_HEADER: &str = "x-erp-token";

/// Newtype para passar o PSK esperado via Axum extensions.
#[derive(Clone)]
pub struct ExpectedPsk(pub String);

/// Middleware Axum 0.7 que valida o header X-ERP-Token contra o PSK configurado.
///
/// O `ExpectedPsk` deve ser injetado como Extension antes desta layer.
/// Retorna 401 se ausente ou inválido.
pub async fn psk_auth(request: Request, next: Next) -> Result<Response, StatusCode> {
    let expected_psk = request
        .extensions()
        .get::<ExpectedPsk>()
        .map(|p| p.0.as_str())
        .unwrap_or("");

    let provided = request
        .headers()
        .get(PSK_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if provided.is_empty() || provided != expected_psk {
        tracing::warn!("PSK authentication failed");
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}
