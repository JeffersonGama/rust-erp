use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct AppConfig {
    pub dbaccess_path: PathBuf,
    pub dbaccessini_path: PathBuf,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    ParseToml(toml::de::Error),
    MissingDbAccessBinaryPath,
    MissingDbAccessIniPath,
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
        config.validate()?;
        Ok(config)
    }

    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path)?;
        Self::from_str(&contents)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.dbaccess_path.as_os_str().is_empty() {
            return Err(ConfigError::MissingDbAccessBinaryPath);
        }

        if self.dbaccessini_path.as_os_str().is_empty() {
            return Err(ConfigError::MissingDbAccessIniPath);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_dbaccess_paths_from_toml() {
        let config = AppConfig::from_str(
            r#"
            dbaccess_path = "/totvs/bin/dbaccess"
            dbaccessini_path = "/totvs/config/dbaccess.ini"
            "#,
        )
        .unwrap();

        assert_eq!(config.dbaccess_path, PathBuf::from("/totvs/bin/dbaccess"));
        assert_eq!(
            config.dbaccessini_path,
            PathBuf::from("/totvs/config/dbaccess.ini")
        );
    }

    #[test]
    fn rejects_missing_dbaccess_path() {
        let err = AppConfig::from_str(
            r#"
            dbaccessini_path = "/totvs/config/dbaccess.ini"
            "#,
        )
        .unwrap_err();

        assert!(matches!(err, ConfigError::ParseToml(_)));
    }
}
