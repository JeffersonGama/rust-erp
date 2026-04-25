//! Configuração do erp-agent, carregada de `config.toml`.
//!
//! Reexporta os tipos públicos do submódulo [`models`]:
//! [`AppConfig`] (root), [`ConfigError`] (falhas de I/O, parse ou
//! validação), [`PathsConfig`] e [`PushConfig`].
//!
//! A seção `[daemon]` é acessada via `AppConfig::daemon` e o tipo
//! `DaemonConfig` não é reexportado — só o binário consome diretamente.

pub mod models;

pub use models::{AppConfig, ConfigError, PathsConfig, PushConfig};
