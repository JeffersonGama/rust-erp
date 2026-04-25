//! Restart de serviços via `systemctl`.
//!
//! A única função pública, [`restart_service`], aplica três filtros
//! encadeados antes de executar qualquer binário externo:
//!
//! 1. **Formato** — o `service_id` precisa casar com o regex
//!    [`SERVICE_ID_PATTERN`] (só `[A-Za-z0-9_-]`). Bloqueia
//!    tentativas triviais de command injection (`svc; rm -rf /`).
//! 2. **Allowlist** — o ID precisa estar em `daemon.allowed_services`
//!    da config. É a política central: qualquer serviço que o
//!    daemon pode reiniciar é uma decisão explícita do operador.
//! 3. **Timeout** — 30 segundos no `systemctl restart`; se estourar,
//!    a operação falha como `Timeout` em vez de ficar pendurada.
//!
//! # Assumptions
//!
//! - O processo tem permissão para rodar `systemctl restart` nos
//!   serviços da allowlist. Em Protheus isso normalmente significa
//!   rodar como root, via sudoers ou via polkit. Não há fallback.

use std::time::Duration;

use serde::Deserialize;
use tokio::process::Command;

/// Regex para validar `service_id`: só aceita alfanuméricos, hífen
/// e underscore. É o primeiro anel de defesa contra command
/// injection; a allowlist é o segundo.
const SERVICE_ID_PATTERN: &str = r"^[a-zA-Z0-9_-]+$";

/// Payload JSON aceito por `POST /api/v1/restart`.
#[derive(Debug, Deserialize)]
pub struct RestartRequest {
    /// ID do serviço a reiniciar (ex: `totvs-appserver`).
    pub service_id: String,
}

/// Falhas possíveis em [`restart_service`].
///
/// No handler HTTP cada variante vira um status diferente:
/// `InvalidServiceId`→400, `ServiceNotAllowed`→403, `Timeout`→504,
/// `CommandFailed`/`Io`→500.
#[derive(Debug)]
pub enum RestartError {
    /// `service_id` válido em formato, mas ausente da allowlist.
    ServiceNotAllowed(String),
    /// `service_id` não bate com [`SERVICE_ID_PATTERN`] — a request
    /// é rejeitada antes de chegar ao `systemctl`.
    InvalidServiceId(String),
    /// `systemctl` rodou mas retornou código de erro. Inclui stderr
    /// para auditoria.
    CommandFailed { code: Option<i32>, stderr: String },
    /// `systemctl restart` excedeu 30 segundos.
    Timeout,
    /// Falha ao spawnar o `systemctl` (binário ausente, sem
    /// permissão para `fork`/`exec`, etc).
    Io(std::io::Error),
}

impl std::fmt::Display for RestartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServiceNotAllowed(s) => write!(f, "service not in allowed list: {s}"),
            Self::InvalidServiceId(s) => write!(f, "invalid service ID format: {s}"),
            Self::CommandFailed { code, stderr } => {
                write!(f, "systemctl failed (code={code:?}): {stderr}")
            }
            Self::Timeout => write!(f, "systemctl restart timed out (30s)"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl From<std::io::Error> for RestartError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// Reinicia um serviço via `systemctl restart`.
///
/// Fluxo:
///
/// 1. Valida o formato de `service_id` contra [`SERVICE_ID_PATTERN`].
/// 2. Verifica que `service_id` está em `allowed_services`.
/// 3. Spawna `systemctl restart <service_id>` via [`tokio::process`]
///    e aguarda com timeout de 30s.
/// 4. Interpreta o `ExitStatus`: sucesso devolve `stdout`,
///    falha devolve [`RestartError::CommandFailed`] com stderr.
///
/// A output value retornada em caso de sucesso é o `stdout` capturado
/// (normalmente vazio — `systemctl restart` silencioso quando OK).
///
/// Implementa RF03 e AC02 da tech-spec.
///
/// # Errors
///
/// - [`RestartError::InvalidServiceId`] se o regex de formato falhar.
/// - [`RestartError::ServiceNotAllowed`] se o ID não estiver na
///   allowlist (mesmo que bem-formado).
/// - [`RestartError::Timeout`] se o `systemctl` não retornar em 30s.
/// - [`RestartError::CommandFailed`] se o `systemctl` sair com
///   código diferente de zero.
/// - [`RestartError::Io`] se o spawn do processo falhar.
pub async fn restart_service(
    service_id: &str,
    allowed_services: &[String],
) -> Result<String, RestartError> {
    // Validar formato do ID (anti command injection — AC02).
    let re = regex_lite::Regex::new(SERVICE_ID_PATTERN).unwrap();
    if !re.is_match(service_id) {
        return Err(RestartError::InvalidServiceId(service_id.to_string()));
    }

    // Validar contra whitelist (RF03).
    if !allowed_services.iter().any(|s| s == service_id) {
        return Err(RestartError::ServiceNotAllowed(service_id.to_string()));
    }

    tracing::info!(service_id, "restarting service via systemctl");

    // Executar com timeout (EC03).
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        Command::new("systemctl")
            .arg("restart")
            .arg(service_id)
            .output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();

            if output.status.success() {
                tracing::info!(service_id, "service restarted successfully");
                Ok(stdout)
            } else {
                tracing::error!(service_id, code = ?output.status.code(), %stderr, "systemctl restart failed");
                Err(RestartError::CommandFailed {
                    code: output.status.code(),
                    stderr,
                })
            }
        }
        Ok(Err(io_err)) => {
            tracing::error!(service_id, error = %io_err, "failed to spawn systemctl");
            Err(RestartError::Io(io_err))
        }
        Err(_elapsed) => {
            tracing::error!(service_id, "systemctl restart timed out after 30s");
            Err(RestartError::Timeout)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_service_not_in_whitelist() {
        let allowed = vec!["totvs-appserver".to_string()];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(restart_service("malicious-service", &allowed))
            .unwrap_err();
        assert!(matches!(err, RestartError::ServiceNotAllowed(_)));
    }

    #[test]
    fn rejects_invalid_service_id_format() {
        let allowed = vec!["totvs-appserver".to_string()];
        let rt = tokio::runtime::Runtime::new().unwrap();

        // Command injection attempt
        let err = rt
            .block_on(restart_service("totvs; rm -rf /", &allowed))
            .unwrap_err();
        assert!(matches!(err, RestartError::InvalidServiceId(_)));

        // Path traversal in service name
        let err = rt
            .block_on(restart_service("../etc/passwd", &allowed))
            .unwrap_err();
        assert!(matches!(err, RestartError::InvalidServiceId(_)));
    }

    #[test]
    fn accepts_valid_service_id_format() {
        let re = regex_lite::Regex::new(SERVICE_ID_PATTERN).unwrap();
        assert!(re.is_match("totvs-appserver"));
        assert!(re.is_match("totvs_dbaccess"));
        assert!(re.is_match("my-service-123"));
        assert!(!re.is_match("bad;service"));
        assert!(!re.is_match("../traversal"));
        assert!(!re.is_match("has space"));
    }
}
