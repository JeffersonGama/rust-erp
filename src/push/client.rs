use std::path::Path;

use reqwest::Client;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::config::PushConfig;
use crate::daemon::middleware::PSK_HEADER;

/// Cliente HTTP para enviar comandos a um daemon erp-agent remoto.
pub struct PushClient {
    http: Client,
    base_url: String,
    psk_token: String,
}

#[derive(Debug)]
pub enum PushError {
    Http(reqwest::Error),
    Io(std::io::Error),
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

    /// Upload de arquivo para o daemon remoto.
    ///
    /// Lê o arquivo local, calcula SHA-256 e envia via POST /api/v1/upload.
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

    /// Altera uma chave .ini no daemon remoto.
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

    /// Reinicia um serviço no daemon remoto.
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

    /// Verifica saúde do daemon remoto.
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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
