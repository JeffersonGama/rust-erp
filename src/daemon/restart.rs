use std::time::Duration;

use serde::Deserialize;
use tokio::process::Command;

/// Regex para validar service IDs: apenas alfanuméricos, hífens e underscores.
const SERVICE_ID_PATTERN: &str = r"^[a-zA-Z0-9_-]+$";

#[derive(Debug, Deserialize)]
pub struct RestartRequest {
    pub service_id: String,
}

#[derive(Debug)]
pub enum RestartError {
    ServiceNotAllowed(String),
    InvalidServiceId(String),
    CommandFailed { code: Option<i32>, stderr: String },
    Timeout,
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

/// Reinicia um serviço via `systemctl restart`, com:
///
/// - Validação de format do service_id (regex estrita).
/// - Whitelist: só aceita IDs presentes em `allowed_services`.
/// - Timeout de 30s para evitar hang.
///
/// Segue RF03 e AC02 da tech-spec.
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
