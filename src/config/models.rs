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

/// Configuração do modo daemon — só é exigida quando o subcomando
/// `daemon` é executado. Em modo `push`, esta seção pode estar
/// ausente ou preenchida com valores default.
///
/// Os campos `psk_token`, `base_path` e `tmp_dir` **não** têm default
/// explícito no TOML: se ausentes, falham no parse. Os demais caem
/// nos defaults definidos em [`Default::default`].
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

/// Configuração do modo push — cliente HTTP que fala com um daemon
/// remoto. Só é consumida pelo subcomando `push`; o modo daemon
/// ignora esta seção.
///
/// Marcada como `Option<PushConfig>` em [`AppConfig`] porque um host
/// que só roda como daemon não precisa preencher — `main.rs` aborta
/// com mensagem clara se `push` for invocado sem `[push]` no TOML.
#[derive(Debug, Deserialize, Clone)]
pub struct PushConfig {
    /// Endereço do daemon remoto (ex: "192.168.1.100:9876").
    pub target_addr: String,

    /// Token PSK compartilhado.
    pub psk_token: String,
}

/// Paths do DBAccess na máquina Protheus. Consumidos principalmente
/// pelo `ini_patcher` (via `dbaccessini_path`); o `dbaccess_path`
/// fica reservado para uso futuro (ex: validação de integridade do
/// binário após upload).
///
/// Pode ser absoluto (recomendado — `/totvs/config/dbaccess.ini`) ou
/// relativo; paths relativos são sanitizados contra traversal antes
/// do uso (ver `daemon::ini_patcher::patch_dbaccess_ini_file`).
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct PathsConfig {
    /// Caminho do binário do DBAccess.
    pub dbaccess_path: PathBuf,

    /// Caminho do dbaccess.ini.
    pub dbaccessini_path: PathBuf,
}

/// Erros possíveis ao carregar ou validar um [`AppConfig`].
///
/// As variantes `Io` e `ParseToml` podem surgir em qualquer modo;
/// as demais (`MissingDbAccessBinaryPath`, `MissingDbAccessIniPath`,
/// `EmptyPskToken`, `NoAllowedServices`) só são produzidas por
/// [`AppConfig::validate_daemon`] e, portanto, só afetam o modo daemon.
#[derive(Debug)]
pub enum ConfigError {
    /// Falha lendo o arquivo de configuração (não existe, sem
    /// permissão, etc). Encapsula o [`std::io::Error`] original.
    Io(std::io::Error),
    /// `config.toml` malformado — sintaxe inválida, seção obrigatória
    /// ausente (ex: `[paths]`) ou tipo de campo incompatível.
    ParseToml(toml::de::Error),
    /// `paths.dbaccess_path` está vazio — disparado por
    /// [`AppConfig::validate_daemon`].
    MissingDbAccessBinaryPath,
    /// `paths.dbaccessini_path` está vazio — disparado por
    /// [`AppConfig::validate_daemon`].
    MissingDbAccessIniPath,
    /// `daemon.psk_token` está vazio — autenticação PSK não pode
    /// funcionar sem token, então o daemon se recusa a iniciar.
    EmptyPskToken,
    /// `daemon.allowed_services` está vazio — nenhum serviço poderia
    /// ser reiniciado via `/api/v1/restart`, então o daemon trata
    /// como misconfig.
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
    /// Desserializa uma string TOML em um `AppConfig`.
    ///
    /// Não valida conteúdo — apenas forma. Use
    /// [`AppConfig::validate_daemon`] antes de iniciar o modo daemon.
    ///
    /// # Errors
    ///
    /// Retorna [`ConfigError::ParseToml`] se o TOML for inválido
    /// ou se seções obrigatórias (como `[paths]`) estiverem ausentes.
    pub fn from_str(contents: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(contents)?;
        Ok(config)
    }

    /// Carrega e desserializa um `config.toml` do disco.
    ///
    /// # Errors
    ///
    /// - [`ConfigError::Io`] se o arquivo não existir ou não for legível.
    /// - [`ConfigError::ParseToml`] se o conteúdo não for TOML válido.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path)?;
        Self::from_str(&contents)
    }

    /// Valida a configuração para execução em modo daemon.
    ///
    /// Aplica as seguintes checagens, retornando na primeira falha:
    ///
    /// 1. `paths.dbaccess_path` não vazio.
    /// 2. `paths.dbaccessini_path` não vazio.
    /// 3. `daemon.psk_token` não vazio (autenticação obrigatória).
    /// 4. `daemon.allowed_services` não vazio (senão o endpoint
    ///    `/api/v1/restart` seria inútil).
    ///
    /// O modo `push` **não** exige essa validação — só lê a seção
    /// `[push]`, que é opcional.
    ///
    /// # Errors
    ///
    /// Retorna a variante de [`ConfigError`] correspondente ao
    /// primeiro campo ausente/vazio. Não acumula todas as falhas.
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
