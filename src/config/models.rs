use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Configuração completa do erp-agent, carregada de config.toml.
#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    /// Configuração do modo daemon (servidor HTTP).
    #[serde(default)]
    pub daemon: DaemonConfig,

    /// Configuração do modo push (cliente).
    #[serde(default)]
    pub push: Option<PushConfig>,

    /// Paths do DBAccess.
    pub paths: PathsConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DaemonConfig {
    /// Endereço de escuta do servidor HTTP.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,

    /// Token PSK para autenticação.
    pub psk_token: String,

    /// Lista de service IDs permitidos para restart.
    #[serde(default)]
    pub allowed_services: Vec<String>,

    /// Diretório base para uploads (destino final).
    pub base_path: PathBuf,

    /// Diretório temporário para uploads em andamento.
    pub tmp_dir: PathBuf,

    /// Tamanho máximo de upload em bytes (default 500MB).
    #[serde(default = "default_max_upload_bytes")]
    pub max_upload_bytes: u64,
}

fn default_listen_addr() -> SocketAddr {
    "0.0.0.0:9876".parse().unwrap()
}

fn default_max_upload_bytes() -> u64 {
    500 * 1024 * 1024 // 500 MB
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            psk_token: String::new(),
            allowed_services: Vec::new(),
            base_path: PathBuf::from("/totvs"),
            tmp_dir: PathBuf::from("/totvs/.tmp_uploads"),
            max_upload_bytes: default_max_upload_bytes(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct PushConfig {
    /// Endereço do daemon remoto (ex: "192.168.1.100:9876").
    pub target_addr: String,

    /// Token PSK compartilhado.
    pub psk_token: String,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct PathsConfig {
    /// Caminho do binário do DBAccess.
    pub dbaccess_path: PathBuf,

    /// Caminho do dbaccess.ini.
    pub dbaccessini_path: PathBuf,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    ParseToml(toml::de::Error),
    MissingDbAccessBinaryPath,
    MissingDbAccessIniPath,
    EmptyPskToken,
    NoAllowedServices,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::ParseToml(e) => write!(f, "TOML parse error: {e}"),
            Self::MissingDbAccessBinaryPath => write!(f, "paths.dbaccess_path is required"),
            Self::MissingDbAccessIniPath => write!(f, "paths.dbaccessini_path is required"),
            Self::EmptyPskToken => write!(f, "daemon.psk_token cannot be empty"),
            Self::NoAllowedServices => write!(f, "daemon.allowed_services cannot be empty"),
        }
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(value: toml::de::Error) -> Self {
        Self::ParseToml(value)
    }
}

impl AppConfig {
    pub fn from_str(contents: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(contents)?;
        Ok(config)
    }

    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path)?;
        Self::from_str(&contents)
    }

    /// Valida configuração para o modo daemon.
    pub fn validate_daemon(&self) -> Result<(), ConfigError> {
        if self.paths.dbaccess_path.as_os_str().is_empty() {
            return Err(ConfigError::MissingDbAccessBinaryPath);
        }
        if self.paths.dbaccessini_path.as_os_str().is_empty() {
            return Err(ConfigError::MissingDbAccessIniPath);
        }
        if self.daemon.psk_token.is_empty() {
            return Err(ConfigError::EmptyPskToken);
        }
        if self.daemon.allowed_services.is_empty() {
            return Err(ConfigError::NoAllowedServices);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL_CONFIG: &str = r#"
[daemon]
listen_addr = "0.0.0.0:9876"
psk_token = "super-secret-token-256bit"
allowed_services = ["totvs-appserver", "totvs-dbaccess", "totvs-license"]
base_path = "/totvs"
tmp_dir = "/totvs/.tmp_uploads"
max_upload_bytes = 524288000

[push]
target_addr = "192.168.1.100:9876"
psk_token = "super-secret-token-256bit"

[paths]
dbaccess_path = "/totvs/bin/dbaccess"
dbaccessini_path = "/totvs/config/dbaccess.ini"
"#;

    #[test]
    fn loads_full_config_from_toml() {
        let config = AppConfig::from_str(FULL_CONFIG).unwrap();

        assert_eq!(
            config.daemon.listen_addr,
            "0.0.0.0:9876".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(config.daemon.psk_token, "super-secret-token-256bit");
        assert_eq!(config.daemon.allowed_services.len(), 3);
        assert_eq!(config.daemon.base_path, PathBuf::from("/totvs"));
        assert_eq!(
            config.paths.dbaccess_path,
            PathBuf::from("/totvs/bin/dbaccess")
        );
        assert_eq!(
            config.paths.dbaccessini_path,
            PathBuf::from("/totvs/config/dbaccess.ini")
        );
    }

    #[test]
    fn loads_push_config() {
        let config = AppConfig::from_str(FULL_CONFIG).unwrap();
        let push = config.push.unwrap();

        assert_eq!(push.target_addr, "192.168.1.100:9876");
        assert_eq!(push.psk_token, "super-secret-token-256bit");
    }

    #[test]
    fn validate_daemon_rejects_empty_psk() {
        let config = AppConfig::from_str(
            r#"
[daemon]
psk_token = ""
allowed_services = ["svc"]
base_path = "/totvs"
tmp_dir = "/tmp"

[paths]
dbaccess_path = "/totvs/bin/dbaccess"
dbaccessini_path = "/totvs/config/dbaccess.ini"
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate_daemon(),
            Err(ConfigError::EmptyPskToken)
        ));
    }

    #[test]
    fn validate_daemon_rejects_no_services() {
        let config = AppConfig::from_str(
            r#"
[daemon]
psk_token = "valid-token"
allowed_services = []
base_path = "/totvs"
tmp_dir = "/tmp"

[paths]
dbaccess_path = "/totvs/bin/dbaccess"
dbaccessini_path = "/totvs/config/dbaccess.ini"
"#,
        )
        .unwrap();

        assert!(matches!(
            config.validate_daemon(),
            Err(ConfigError::NoAllowedServices)
        ));
    }

    #[test]
    fn rejects_missing_paths_section() {
        let err = AppConfig::from_str(
            r#"
[daemon]
psk_token = "token"
"#,
        )
        .unwrap_err();

        assert!(matches!(err, ConfigError::ParseToml(_)));
    }
}
