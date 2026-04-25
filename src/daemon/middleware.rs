//! Autenticação PSK (Pre-Shared Key) via header HTTP.
//!
//! Todas as rotas protegidas do daemon passam por [`psk_auth`], que
//! compara o header `x-erp-token` da request com o PSK configurado em
//! `daemon.psk_token`. A comparação é case-sensitive e byte-a-byte;
//! qualquer divergência (ausente, vazio ou diferente) devolve
//! `401 Unauthorized` sem corpo.
//!
//! O PSK esperado chega até este middleware via `Extension` Axum —
//! [`ExpectedPsk`] é empacotado pelo `server::run` e instalado como
//! layer **antes** do `from_fn(psk_auth)`. Se a ordem das layers for
//! invertida por engano, o middleware lê string vazia e recusa todas
//! as requests (falha fechada — propositalmente).
//!
//! PSK é suficiente para deploy interno em rede confiável; a spec
//! em `docs/tech-spec.md` prevê evolução para mTLS/HMAC.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};

/// Nome do header HTTP onde o cliente envia o PSK.
///
/// Lowercase porque headers HTTP são case-insensitive e o Axum
/// normaliza as chaves para minúsculas — manter o literal em
/// lowercase evita surpresas em comparações diretas.
pub const PSK_HEADER: &str = "x-erp-token";

/// Newtype que embrulha o PSK esperado para trânsito como
/// `Extension` Axum.
///
/// Existe só para evitar colisão de tipos em `request.extensions()` —
/// um `String` "solto" poderia ser confundido com qualquer outro
/// valor. `Clone` é barato porque a String é pequena (token PSK).
#[derive(Clone)]
pub struct ExpectedPsk(pub String);

/// Middleware Axum 0.7 que valida o header `x-erp-token` contra o
/// PSK configurado.
///
/// Fluxo:
///
/// 1. Extrai [`ExpectedPsk`] de `request.extensions()`. Se não
///    estiver lá (layer instalada fora de ordem), usa `""` — o que
///    faz a checagem falhar logo abaixo.
/// 2. Extrai o header [`PSK_HEADER`]. Ausente, vazio ou não-ASCII
///    vira `""`.
/// 3. Se o valor fornecido for vazio **ou** diferente do esperado,
///    emite um `tracing::warn!` (sem logar o valor recebido, para
///    não vazar tokens em log) e retorna
///    [`StatusCode::UNAUTHORIZED`].
///
/// Caso contrário, propaga a request para `next`.
///
/// # Errors
///
/// Retorna [`StatusCode::UNAUTHORIZED`] — convertido pelo Axum em
/// resposta HTTP 401 sem corpo — quando o header está ausente,
/// vazio ou diverge do PSK esperado.
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
