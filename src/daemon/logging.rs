use tracing_subscriber::{fmt, EnvFilter};

/// Inicializa tracing com output JSONL estruturado.
///
/// Controlado pela variável `RUST_LOG` (default: `info`).
/// Exemplo: `RUST_LOG=erp_agent=debug,tower_http=info`
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
