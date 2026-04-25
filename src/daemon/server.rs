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

/// Estado compartilhado do servidor.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
}

/// Inicia o servidor Axum.
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

/// GET /health — Retorna status do daemon (sem autenticação).
async fn handle_health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_hint": "use /api/v1/* for operations"
    }))
}

/// POST /api/v1/upload — Upload atômico de arquivo.
///
/// Headers requeridos:
/// - `X-Target-Path`: caminho relativo de destino (ex: "bin/appserver")
/// - `X-SHA256`: checksum SHA-256 esperado do conteúdo
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

/// PATCH /api/v1/ini — Altera uma chave em um arquivo .ini.
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
        Err(ini_patcher::IniPatchError::InvalidPath(_)) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid path (possible traversal)"})),
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

/// POST /api/v1/restart — Reinicia um serviço via systemctl.
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
