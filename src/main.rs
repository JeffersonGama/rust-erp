//! # erp-agent
//!
//! Orquestrador CLI/daemon para administração remota de servidores
//! Totvs Protheus on-premise. Não é um ERP nem um parser SQL: é um
//! agente que roda nas máquinas Protheus para permitir operações
//! automatizadas e auditáveis disparadas de um host central.
//!
//! ## Modos de operação
//!
//! O binário expõe dois subcomandos mutuamente exclusivos via Clap:
//!
//! - `daemon` — sobe um servidor HTTP Axum na máquina Protheus e
//!   aceita comandos autenticados por PSK (ver módulo `daemon::server`).
//! - `push` — cliente CLI que envia comandos a um daemon remoto:
//!   `upload`, `ini`, `restart`, `health` (ver módulo `push::client`).
//!
//! Ambos os modos compartilham o mesmo `config.toml`. O modo daemon
//! ainda exige `AppConfig::validate_daemon` no bootstrap — PSK vazio
//! ou allowlist de serviços vazia abortam o start.
//!
//! ## Uso
//!
//! ```bash
//! erp-agent --config config.toml daemon
//! erp-agent --config config.toml push health
//! erp-agent --config config.toml push upload --file ./bin/appserver --target bin/appserver
//! erp-agent --config config.toml push ini --section Postgres --key Thread --value 40
//! erp-agent --config config.toml push restart --service totvs-appserver
//! ```
//!
//! Consulte `docs/tech-spec.md` para o desenho técnico completo.

mod config;
mod daemon;
mod push;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use config::AppConfig;

/// erp-agent — Orquestrador Totvs On-Premise
#[derive(Parser)]
#[command(name = "erp-agent", version, about)]
struct Cli {
    /// Caminho do config.toml
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inicia o daemon HTTP (modo servidor)
    Daemon,

    /// Envia comandos para um daemon remoto (modo cliente)
    Push {
        #[command(subcommand)]
        action: PushAction,
    },
}

#[derive(Subcommand)]
enum PushAction {
    /// Upload de arquivo para o daemon remoto
    Upload {
        /// Caminho local do arquivo a enviar
        #[arg(short, long)]
        file: PathBuf,

        /// Caminho relativo de destino no servidor (ex: "bin/appserver")
        #[arg(short, long)]
        target: String,
    },

    /// Altera uma chave em um arquivo .ini no daemon remoto
    Ini {
        /// Seção do .ini (ex: "Postgres")
        #[arg(short, long)]
        section: String,

        /// Chave a alterar (ex: "Thread")
        #[arg(short, long)]
        key: String,

        /// Novo valor (ex: "40")
        #[arg(short, long)]
        value: String,
    },

    /// Reinicia um serviço no daemon remoto
    Restart {
        /// ID do serviço (ex: "totvs-appserver")
        #[arg(short, long)]
        service: String,
    },

    /// Verifica saúde do daemon remoto
    Health,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Setup tracing
    daemon::logging::init_tracing();

    let config = match AppConfig::from_file(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, path = %cli.config.display(), "failed to load config");
            std::process::exit(1);
        }
    };

    match cli.command {
        Commands::Daemon => {
            if let Err(e) = config.validate_daemon() {
                tracing::error!(error = %e, "invalid daemon config");
                std::process::exit(1);
            }
            tracing::info!(
                addr = %config.daemon.listen_addr,
                services = ?config.daemon.allowed_services,
                "starting erp-agent daemon"
            );
            if let Err(e) = daemon::server::run(config).await {
                tracing::error!(error = %e, "daemon exited with error");
                std::process::exit(1);
            }
        }
        Commands::Push { action } => {
            let push_config = match &config.push {
                Some(p) => p.clone(),
                None => {
                    tracing::error!("missing [push] section in config.toml");
                    std::process::exit(1);
                }
            };
            let client = push::client::PushClient::new(&push_config);
            let result = match action {
                PushAction::Upload { file, target } => {
                    client.upload(&file, &target).await
                }
                PushAction::Ini {
                    section,
                    key,
                    value,
                } => client.patch_ini(&section, &key, &value).await,
                PushAction::Restart { service } => {
                    client.restart(&service).await
                }
                PushAction::Health => client.health().await,
            };
            if let Err(e) = result {
                tracing::error!(error = %e, "push command failed");
                std::process::exit(1);
            }
        }
    }
}
