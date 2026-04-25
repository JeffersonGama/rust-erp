//! Implementação do modo `daemon` do erp-agent.
//!
//! Cada submódulo tem uma responsabilidade isolada:
//!
//! - `server` — servidor Axum, roteamento, handlers HTTP e `AppState`.
//! - `middleware` — autenticação PSK via header `x-erp-token`.
//! - `upload` — upload atômico (tmp → SHA-256 → rename).
//! - `ini_patcher` — edição estrutural de `.ini` com double-checksum e lock exclusivo.
//! - `restart` — restart de serviços via `systemctl` com allowlist e timeout de 30s.
//! - `security` — sanitização de paths (defesa contra traversal).
//! - `logging` — inicialização do `tracing` com output JSONL.
//!
//! O ponto de entrada é `server::run`, invocado por `main.rs` quando
//! o subcomando `daemon` é selecionado.

pub mod ini_patcher;
pub mod logging;
pub mod middleware;
pub mod restart;
pub mod security;
pub mod server;
pub mod upload;
