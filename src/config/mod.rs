//! Configuração do erp-agent, carregada de `config.toml`.
//!
//! Reexporta os tipos do submódulo [`models`] consumidos fora do
//! módulo: [`AppConfig`] (root) e [`PushConfig`]. `DaemonConfig` é
//! acessado via `AppConfig::daemon` e `PathsConfig` via
//! `AppConfig::paths`; a forma canônica de construí-los, quando
//! necessário (testes, fixtures), é por
//! `crate::config::models::PathsConfig`.

pub mod models;

pub use models::{AppConfig, PushConfig};
