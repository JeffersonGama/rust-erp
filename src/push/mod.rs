//! Implementação do modo `push` do erp-agent.
//!
//! Expõe [`client::PushClient`], o cliente HTTP que envia comandos
//! autenticados por PSK (header `x-erp-token`) para um daemon
//! erp-agent remoto. Usado por `main.rs` quando o subcomando `push`
//! é selecionado.

pub mod client;
