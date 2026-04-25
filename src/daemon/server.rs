//! Servidor HTTP Axum — roteamento, estado compartilhado e handlers.
//!
//! Este módulo é a "cara" do daemon: monta o `Router`, compõe as
//! layers de autenticação, faz o `bind` e delega as quatro rotas
//! expostas aos handlers deste mesmo arquivo.
//!
//! # Rotas
//!
//! | Método | Path              | Autenticação | Handler             |
//! |--------|-------------------|--------------|---------------------|
//! | GET    | `/health`         | nenhuma      | [`handle_health`]   |
//! | POST   | `/api/v1/upload`  | PSK          | [`handle_upload`]   |
//! | PATCH  | `/api/v1/ini`     | PSK          | [`handle_ini_patch`]|
//! | POST   | `/api/v1/restart` | PSK          | [`handle_restart`]  |
//!
//! # Composição de layers
//!
//! O `protected` `Router` leva, na ordem, `layer(from_fn(psk_auth))`
//! e `layer(Extension(psk))`. Em Axum 0.7 as layers executam
//! last-added-first, então `Extension(psk)` roda **antes** de
//! `psk_auth` — que é o que queremos: o middleware precisa ler a
//! extension. Inverter essa ordem quebra a autenticação
//! silenciosamente (middleware lê string vazia e recusa tudo).
//!
//! # Erros e códigos HTTP
//!
//! Cada handler traduz variantes de erro do submódulo correspondente
//! em status HTTP. Os códigos usados:
//!
//! - `400 Bad Request` — entrada malformada (header ausente,
//!   checksum inválido, service_id fora do regex, path inválido).
//! - `401 Unauthorized` — PSK ausente/inválido (emitido pelo
//!   `middleware::psk_auth`, não pelos handlers).
//! - `403 Forbidden` — service_id fora da allowlist.
//! - `404 Not Found` — arquivo `.ini` ou seção inexistente.
//! - `413 Payload Too Large` — upload excede `max_upload_bytes`.
//! - `500 Internal Server Error` — erro inesperado (I/O, lock, etc).
//! - `504 Gateway Timeout` — `systemctl restart` estourou 30s.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    middleware as axum_mw,
    response::Json,
    routing::{get, patch, post},
    Router,
};
use serde_json::{json, Value};
use tokio::net::TcpListener;

use crate::config::AppConfig;
use crate::daemon::ini_patcher::{self, PatchIniRequest};
use crate::daemon::middleware::{psk_auth, ExpectedPsk};
use crate::daemon::restart::{self, RestartRequest};
use crate::daemon::upload;

/// Estado compartilhado injetado em todos os handlers via `State`.
///
/// Só carrega a `AppConfig` atrás de um [`Arc`] para permitir
/// `Clone` barato — o Axum clona o estado por request. A config é
/// imutável durante a vida do processo; mudanças exigem restart.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
}

/// Inicia o servidor Axum e bloqueia até ele terminar.
///
/// Monta o `Router`, faz o `TcpListener::bind` em
/// `config.daemon.listen_addr` e serve requests até o processo
/// receber SIGTERM/SIGINT (tratamento de sinais é delegado ao
/// runtime Tokio).
///
/// Consome `config` por valor e embrulha num [`Arc`] dentro de
/// [`AppState`]; clone-a antes se precisar dela depois.
///
/// # Errors
///
/// Devolve `Box<dyn Error>` em três situações:
///
/// - `bind` falhou (porta em uso, sem permissão para bindar abaixo
///   de 1024, endereço inválido).
/// - `axum::serve` retornou erro não-recuperável durante `accept`.
/// - Qualquer erro que o Axum propague da loop principal.
pub async fn run(config: AppConfig) -> Result<(), Box<dyn std::error::Error>> {
    let listen_addr = config.daemon.listen_addr;
    let psk = ExpectedPsk(config.daemon.psk_token.clone());

    let state = AppState {
        config: Arc::new(config),
    };

    // Rotas protegidas por PSK.
    let protected = Router::new()
        .route("/api/v1/upload", post(handle_upload))
        .route("/api/v1/ini", patch(handle_ini_patch))
        .route("/api/v1/restart", post(handle_restart))
        .layer(axum_mw::from_fn(psk_auth))
        .layer(Extension(psk));

    // Rotas públicas.
    let public = Router::new().route("/health", get(handle_health));

    let app = Router::new()
        .merge(protected)
        .merge(public)
        .with_state(state);

    tracing::info!(%listen_addr, "erp-agent daemon listening");

    let listener = TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// ──────────────────────────────────────────────
// Handlers
// ──────────────────────────────────────────────

/// `GET /health` — Health-check público.
///
/// Rota não autenticada. Usada por load balancers, orquestradores
/// e pelo subcomando `push health` para detectar se o daemon está
/// de pé. Nunca falha: se o processo está atendendo, a rota
/// responde 200.
///
/// Corpo da resposta:
///
/// ```json
/// { "status": "ok", "version": "<CARGO_PKG_VERSION>", "uptime_hint": "..." }
/// ```
async fn handle_health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_hint": "use /api/v1/* for operations"
    }))
}

/// `POST /api/v1/upload` — Upload atômico de arquivo.
///
/// O corpo da request é o conteúdo binário do arquivo; os metadados
/// viajam em headers (não em multipart) para simplificar o parse.
///
/// # Headers
///
/// - `X-Target-Path` — **obrigatório**, caminho relativo de destino
///   dentro de `base_path` (ex: `bin/appserver`). Strings vazias
///   resultam em 400.
/// - `X-SHA256` — checksum SHA-256 esperado em hex lowercase. Se
///   vazio, [`upload::atomic_upload`] pula a verificação (útil para
///   testes; em produção o cliente sempre envia).
///
/// # Códigos de resposta
///
/// - `200 OK` — arquivo gravado com sucesso; corpo contém o path
///   final absoluto.
/// - `400 Bad Request` — `X-Target-Path` ausente, `X-SHA256`
///   divergente do conteúdo recebido, ou path com traversal.
/// - `413 Payload Too Large` — bytes recebidos excedem
///   `daemon.max_upload_bytes`.
/// - `500 Internal Server Error` — qualquer falha de I/O (disco
///   cheio, permissão negada em `tmp_dir`, rename falhou, etc).
async fn handle_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let target_path = headers
        .get("x-target-path")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if target_path.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "missing X-Target-Path header"})),
        ));
    }

    let expected_sha256 = headers
        .get("x-sha256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Verificar tamanho máximo.
    if body.len() as u64 > state.config.daemon.max_upload_bytes {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({
                "error": "payload exceeds max_upload_bytes",
                "max_bytes": state.config.daemon.max_upload_bytes
            })),
        ));
    }

    match upload::atomic_upload(
        &state.config.daemon.base_path,
        &state.config.daemon.tmp_dir,
        &target_path,
        &expected_sha256,
        body,
    )
    .await
    {
        Ok(final_path) => Ok(Json(json!({
            "status": "created",
            "path": final_path.display().to_string()
        }))),
        Err(upload::UploadError::ChecksumMismatch { expected, actual }) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "checksum mismatch",
                "expected": expected,
                "actual": actual
            })),
        )),
        Err(upload::UploadError::InvalidPath(_)) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid target path (possible traversal)"})),
        )),
        Err(e) => {
            tracing::error!(error = %e, "upload failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "upload failed"})),
            ))
        }
    }
}

/// `PATCH /api/v1/ini` — Altera uma chave de um arquivo `.ini`.
///
/// Aceita JSON no formato [`PatchIniRequest`] (section/key/value).
/// Sempre opera sobre `paths.dbaccessini_path` da config — o campo
/// `target_file` do payload é **ignorado** neste endpoint (ver
/// nota em [`ini_patcher::patch_dbaccess_ini_file`]).
///
/// # Códigos de resposta
///
/// - `200 OK` — patch aplicado; corpo inclui `checksum_before`,
///   `checksum_after`, `changed` e `path` (para auditoria).
/// - `400 Bad Request` — path inválido ou com traversal.
/// - `404 Not Found` — arquivo `.ini` não existe **ou** a seção
///   não foi encontrada no arquivo.
/// - `500 Internal Server Error` — falha de I/O, parse quebrado,
///   inconsistência de checksum pós-escrita.
async fn handle_ini_patch(
    State(state): State<AppState>,
    Json(request): Json<PatchIniRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match ini_patcher::patch_dbaccess_ini_file(&state.config, &request) {
        Ok(result) => {
            Ok(Json(json!({
                "changed": result.changed,
                "checksum_before": result.checksum_before,
                "checksum_after": result.checksum_after,
                "path": result.path.display().to_string()
            })))
        }
        Err(ini_patcher::IniPatchError::FileNotFound(p)) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("file not found: {}", p.display())})),
        )),
        Err(ini_patcher::IniPatchError::MissingSection(s)) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("section not found: [{s}]")})),
        )),
        Err(e) => {
            tracing::error!(error = %e, "ini patch failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "ini patch failed"})),
            ))
        }
    }
}

/// `POST /api/v1/restart` — Reinicia um serviço via `systemctl`.
///
/// Aceita JSON no formato [`RestartRequest`] (`service_id`). O
/// `service_id` passa por três filtros antes de chegar ao
/// `systemctl`: regex de formato, allowlist em
/// `daemon.allowed_services` e timeout de 30s na execução.
///
/// # Códigos de resposta
///
/// - `200 OK` — `systemctl restart` retornou sucesso; corpo ecoa
///   `service_id`.
/// - `400 Bad Request` — `service_id` não bate com o regex de
///   caracteres permitidos.
/// - `403 Forbidden` — `service_id` não está em
///   `daemon.allowed_services`.
/// - `500 Internal Server Error` — `systemctl` retornou código de
///   erro, ou falhou ao spawnar.
/// - `504 Gateway Timeout` — `systemctl` excedeu 30s.
async fn handle_restart(
    State(state): State<AppState>,
    Json(request): Json<RestartRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match restart::restart_service(
        &request.service_id,
        &state.config.daemon.allowed_services,
    )
    .await
    {
        Ok(_stdout) => Ok(Json(json!({
            "status": "restarted",
            "service_id": request.service_id
        }))),
        Err(restart::RestartError::ServiceNotAllowed(s)) => Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": format!("service not allowed: {s}")})),
        )),
        Err(restart::RestartError::InvalidServiceId(s)) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid service ID: {s}")})),
        )),
        Err(restart::RestartError::Timeout) => Err((
            StatusCode::GATEWAY_TIMEOUT,
            Json(json!({"error": "systemctl restart timed out (30s)"})),
        )),
        Err(e) => {
            tracing::error!(error = %e, "restart failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "restart failed"})),
            ))
        }
    }
}
