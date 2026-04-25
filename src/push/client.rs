//! Cliente HTTP que fala com um daemon erp-agent remoto.
//!
//! Usado pelo subcomando `push` do binário. Cada método de
//! [`PushClient`] mapeia para um endpoint do daemon:
//!
//! | Método             | Endpoint              |
//! |--------------------|-----------------------|
//! | [`PushClient::upload`]    | `POST /api/v1/upload`  |
//! | [`PushClient::patch_ini`] | `PATCH /api/v1/ini`    |
//! | [`PushClient::restart`]   | `POST /api/v1/restart` |
//! | [`PushClient::health`]    | `GET /health`          |
//!
//! Todas as rotas protegidas incluem automaticamente o header
//! [`PSK_HEADER`] com o token de `PushConfig::psk_token`.

use std::path::Path;

use reqwest::Client;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::config::PushConfig;
use crate::daemon::middleware::PSK_HEADER;

/// Cliente HTTP para enviar comandos a um daemon erp-agent remoto.
///
/// Construído uma vez a partir de [`PushConfig`] e reutilizado
/// para todas as operações. O [`reqwest::Client`] interno mantém
/// pool de conexões, então instanciar uma vez por processo é o
/// padrão recomendado.
pub struct PushClient {
    http: Client,
    base_url: String,
    psk_token: String,
}

/// Falhas possíveis em operações do [`PushClient`].
#[derive(Debug)]
pub enum PushError {
    /// Falha de transporte HTTP (DNS, TCP, TLS, timeout).
    Http(reqwest::Error),
    /// Falha de I/O local — hoje só acontece em
    /// [`PushClient::upload`], ao ler o arquivo do disco.
    Io(std::io::Error),
    /// Daemon respondeu com status ≥ 400. Inclui o body textual
    /// da resposta para diagnóstico.
    ServerError { status: u16, body: String },
}

impl std::fmt::Display for PushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(e) => write!(f, "HTTP error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::ServerError { status, body } => {
                write!(f, "server returned {status}: {body}")
            }
        }
    }
}

impl From<reqwest::Error> for PushError {
    fn from(value: reqwest::Error) -> Self {
        Self::Http(value)
    }
}

impl From<std::io::Error> for PushError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl PushClient {
    /// Constrói um [`PushClient`] a partir de [`PushConfig`].
    ///
    /// Se `config.target_addr` não começar com `http` (ex:
    /// `"192.168.1.100:9876"`), `http://` é prependado
    /// automaticamente — o daemon hoje só serve HTTP plano. Para
    /// falar com um daemon atrás de TLS, inclua `https://`
    /// explicitamente no `target_addr` da config.
    pub fn new(config: &PushConfig) -> Self {
        let base_url = if config.target_addr.starts_with("http") {
            config.target_addr.clone()
        } else {
            format!("http://{}", config.target_addr)
        };

        Self {
            http: Client::new(),
            base_url,
            psk_token: config.psk_token.clone(),
        }
    }

    /// Faz upload de um arquivo local para `POST /api/v1/upload`.
    ///
    /// Lê `local_path` inteiro para memória, calcula SHA-256 e
    /// envia o corpo com os headers `x-target-path` e `x-sha256`
    /// que o daemon espera. A resposta de sucesso (200) é impressa
    /// em stdout; status ≥ 400 vira [`PushError::ServerError`].
    ///
    /// # Errors
    ///
    /// - [`PushError::Io`] se `local_path` não puder ser lido.
    /// - [`PushError::Http`] em falha de transporte.
    /// - [`PushError::ServerError`] se o daemon responder com
    ///   400/401/413/500 (ver handler correspondente).
    pub async fn upload(&self, local_path: &Path, target_relative: &str) -> Result<(), PushError> {
        let file_bytes = tokio::fs::read(local_path).await?;
        let sha256 = sha256_hex(&file_bytes);

        tracing::info!(
            local = %local_path.display(),
            target = target_relative,
            sha256 = %sha256,
            size = file_bytes.len(),
            "pushing file to daemon"
        );

        let resp = self
            .http
            .post(format!("{}/api/v1/upload", self.base_url))
            .header(PSK_HEADER, &self.psk_token)
            .header("x-target-path", target_relative)
            .header("x-sha256", &sha256)
            .body(file_bytes)
            .send()
            .await?;

        self.check_response(resp).await
    }

    /// Altera uma chave `.ini` via `PATCH /api/v1/ini`.
    ///
    /// O campo `target_file` do payload é **hardcoded** em
    /// `"dbaccess.ini"` — o cliente assume que o daemon vai usar
    /// o path configurado em `paths.dbaccessini_path` e ignorar
    /// o `target_file` (ver nota em
    /// [`crate::daemon::ini_patcher::patch_dbaccess_ini_file`]).
    /// Esse hardcode é um débito conhecido registrado em `CLAUDE.md`.
    ///
    /// Log de `tracing::info!` redige o valor — não queremos
    /// senhas em log.
    ///
    /// # Errors
    ///
    /// - [`PushError::Http`] em falha de transporte.
    /// - [`PushError::ServerError`] se o daemon responder com
    ///   400/401/404/500.
    pub async fn patch_ini(
        &self,
        section: &str,
        key: &str,
        value: &str,
    ) -> Result<(), PushError> {
        tracing::info!(section, key, "[REDACTED] pushing ini patch to daemon");

        let resp = self
            .http
            .patch(format!("{}/api/v1/ini", self.base_url))
            .header(PSK_HEADER, &self.psk_token)
            .json(&json!({
                "target_file": "dbaccess.ini",
                "section": section,
                "key": key,
                "new_value": value
            }))
            .send()
            .await?;

        self.check_response(resp).await
    }

    /// Reinicia um serviço via `POST /api/v1/restart`.
    ///
    /// O `service_id` é enviado como está; a validação de formato
    /// e allowlist acontece no lado do daemon. Status ≥ 400 vira
    /// [`PushError::ServerError`] (tipicamente 400 para formato
    /// inválido, 403 fora de allowlist, 504 timeout).
    ///
    /// # Errors
    ///
    /// - [`PushError::Http`] em falha de transporte.
    /// - [`PushError::ServerError`] em qualquer resposta não-2xx
    ///   do daemon (400/401/403/500/504).
    pub async fn restart(&self, service_id: &str) -> Result<(), PushError> {
        tracing::info!(service_id, "pushing restart to daemon");

        let resp = self
            .http
            .post(format!("{}/api/v1/restart", self.base_url))
            .header(PSK_HEADER, &self.psk_token)
            .json(&json!({"service_id": service_id}))
            .send()
            .await?;

        self.check_response(resp).await
    }

    /// Checa saúde do daemon via `GET /health`.
    ///
    /// Rota pública, não envia PSK. Útil como smoke test após
    /// deploy ou para scripts de monitoramento. O corpo da
    /// resposta de sucesso é impresso em stdout.
    ///
    /// # Errors
    ///
    /// - [`PushError::Http`] em falha de transporte (daemon
    ///   ofline, DNS quebrado, etc).
    /// - [`PushError::ServerError`] para qualquer status ≥ 400 —
    ///   improvável nesta rota, mas mantido para consistência.
    pub async fn health(&self) -> Result<(), PushError> {
        let resp = self
            .http
            .get(format!("{}/health", self.base_url))
            .send()
            .await?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            tracing::info!(body = %body, "daemon is healthy");
            println!("{body}");
            Ok(())
        } else {
            Err(PushError::ServerError {
                status: status.as_u16(),
                body,
            })
        }
    }

    async fn check_response(&self, resp: reqwest::Response) -> Result<(), PushError> {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            tracing::info!(status = status.as_u16(), body = %body, "operation succeeded");
            println!("{body}");
            Ok(())
        } else {
            tracing::error!(status = status.as_u16(), body = %body, "operation failed");
            Err(PushError::ServerError {
                status: status.as_u16(),
                body,
            })
        }
    }
}

// SHA-256 em hex lowercase. Duplica helpers privados em
// `daemon::upload` e `daemon::ini_patcher::sha256_hex` —
// consolidação está registrada como débito em `CLAUDE.md`.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
