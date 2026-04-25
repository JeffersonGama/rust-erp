//! Inicialização do subscriber global de `tracing`.
//!
//! Uma única função pública, [`init_tracing`], instala o subscriber
//! com output JSONL (uma linha por evento) na saída padrão. É
//! chamada uma vez por `main.rs`, antes de parsear a config — assim
//! erros de carregamento da config já saem como eventos estruturados.

use tracing_subscriber::{fmt, EnvFilter};

/// Inicializa o `tracing` global com output JSONL estruturado.
///
/// Instala um subscriber `fmt` com filtro baseado na variável de
/// ambiente `RUST_LOG`; se ausente, cai no default
/// `erp_agent=info,tower_http=info`. Cada evento vira uma linha JSON
/// na stdout — formato pensado para ser consumido por agregadores
/// (journald, Loki, etc).
///
/// # Panics
///
/// Entra em pânico se chamada mais de uma vez no mesmo processo —
/// `init` do tracing-subscriber falha se já houver subscriber global
/// instalado. O binário só chama uma vez, em `main`.
pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("erp_agent=info,tower_http=info"));

    fmt()
        .with_env_filter(filter)
        .json()
        .with_target(true)
        .with_current_span(false)
        .flatten_event(true)
        .init();
}
