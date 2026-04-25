# erp-agent — Project Memory

> Memória do projeto para sessões com Claude.
> Ler no início de cada sessão para contexto completo.
> Pasta do repo: `rust-erp/`. Crate: `erp-agent`.

## O que é este projeto

**erp-agent** — Orquestrador para administração remota de servidores **Totvs Protheus on-premise**. Não é um ERP nem um parser SQL: é um agente CLI/daemon que roda nas máquinas Protheus para permitir operações automatizadas e auditáveis a partir de um host central (deploy de binários, ajuste de `.ini`, restart de serviços via systemd).

Dois modos de operação no mesmo binário (subcomandos Clap):

- **`erp-agent daemon`** — sobe um servidor HTTP Axum nas máquinas Protheus que aceita comandos autenticados por PSK.
- **`erp-agent push <ação>`** — cliente CLI (Reqwest) que envia comandos a um daemon remoto: `upload`, `ini`, `restart`, `health`.

A spec técnica completa vive em `docs/tech-spec.md`.

## Tech Stack

Rust 2021. Tokio + Axum 0.7 (servidor), Reqwest 0.12 (cliente), Clap 4 (CLI), Serde + toml (config), tracing + tracing-subscriber + tracing-appender (observabilidade), sha2 (checksum de uploads), fs3 (file locking), rust-ini (parsing de `.ini`), regex-lite (validação), tower-http (middlewares HTTP).

## Arquitetura

```
src/
├── main.rs              CLI: subcommands Daemon | Push (Upload/Ini/Restart/Health)
├── config/
│   ├── mod.rs
│   └── models.rs        AppConfig, DaemonConfig, PushConfig, PathsConfig + validate_daemon
├── daemon/
│   ├── mod.rs
│   ├── server.rs        Axum app — rotas + handlers
│   ├── middleware.rs    psk_auth (header X-PSK-Token)
│   ├── upload.rs        atomic_upload — tmp_dir → SHA-256 check → rename atômico
│   ├── ini_patcher.rs   patch_dbaccess_ini_file — edição segura de .ini com checksum
│   ├── restart.rs       restart_service — systemctl restart com allowlist e timeout 30s
│   ├── security.rs      sanitização de paths, defesa contra traversal
│   └── logging.rs       init_tracing
└── push/
    ├── mod.rs
    └── client.rs        PushClient: upload / patch_ini / restart / health

docs/tech-spec.md        Spec técnica hardenizada
examples/config.toml     Exemplo de configuração
```

Endpoints HTTP expostos pelo daemon:

- `GET  /health` — público, retorna versão e status.
- `POST /api/v1/upload` — protegido. Headers: `X-Target-Path`, `X-SHA256`. Corpo: bytes do arquivo. Limite `max_upload_bytes` (default 500 MB).
- `PATCH /api/v1/ini` — protegido. JSON `PatchIniRequest` (section/key/value). Retorna `checksum_before`/`checksum_after`.
- `POST /api/v1/restart` — protegido. JSON `RestartRequest` (`service_id`). Falha com 403 se o serviço não estiver na allowlist.

## Configuração

`Cargo.toml`:
```toml
[package]
name = "erp-agent"
version = "0.1.0"
edition = "2021"
authors = ["Dev Solo <sysadmin@empresa.com>"]
```

`config.toml` (ver `examples/config.toml`) tem três seções:

- `[daemon]` — `listen_addr` (default `0.0.0.0:9876`), `psk_token`, `allowed_services[]`, `base_path`, `tmp_dir`, `max_upload_bytes`.
- `[push]` — `target_addr`, `psk_token` (opcional, só usado em modo cliente).
- `[paths]` — `dbaccess_path`, `dbaccessini_path`.

`AppConfig::validate_daemon` rejeita: PSK vazio, `allowed_services` vazio, `dbaccess_path`/`dbaccessini_path` vazios.

## Histórico (commits relevantes em `main`)

```
103a9e7  Merge PR #4 — atualizar branch main
00532ed  chore: add Cargo.lock on main
9351f0b  Merge PR #3 — verify implementation against spec
290df46  Add configurable dbaccess paths
14c47b9  Merge PR #2 — atomic file validation module
144f041  Add hardened erp-agent technical spec
13a6a2c  Merge PR #1 — security & ini_patcher modules
feea17a  Add secure INI patcher scaffolding
5cdfea3  Initialize repository
```

## Estado atual da working tree (sessão de 2026-04-24)

Branch `main`, sincronizada com `origin/main`, mas com **trabalho substancial não commitado**:

Modificados (≈+422/−37 linhas, 9 arquivos): `Cargo.toml`, `Cargo.lock`, `examples/config.toml`, `src/main.rs` (+131), `src/config/models.rs` (+193 — refactor grande de `AppConfig`), `src/daemon/ini_patcher.rs`, `src/daemon/mod.rs`, `src/push/mod.rs`.

Novos arquivos não rastreados: `src/daemon/{logging,middleware,restart,server,upload}.rs`, `src/push/client.rs`, `CLAUDE.md`.

Em outras palavras, todo o esqueleto do daemon HTTP (rotas, upload atômico, restart, middleware PSK, logging) e o cliente push estão escritos mas ainda não foram commitados.

Total de código Rust: ~1.594 linhas em 13 arquivos.

## Decisões de design (ADRs)

- **Atomicidade de upload:** o arquivo é gravado primeiro em `tmp_dir`, validado por SHA-256 contra o header `X-SHA256` enviado pelo cliente, e só então renomeado para o destino final em `base_path`. Em caso de mismatch, o tmp é descartado e a operação falha com 400.
- **Allowlist de serviços:** `restart_service` só executa `systemctl restart` para IDs explicitamente listados em `daemon.allowed_services`. Tentativas fora dela retornam 403, mesmo com PSK válido.
- **Auth simples por PSK:** middleware Axum compara `X-PSK-Token` com `daemon.psk_token`. Suficiente para deploy interno; a spec considera mTLS/HMAC como evolução futura.
- **Patch de `.ini` com double-checksum:** `ini_patcher` retorna `checksum_before` e `checksum_after` para auditoria, e usa edição estrutural (`rust-ini`) em vez de regex para preservar comentários e formatação.
- **Defesa contra path traversal:** `upload.rs` valida que `target_path` resolvido não escapa de `base_path`; `ini_patcher.rs` faz a mesma checagem para o caminho do `.ini`.

## Problemas conhecidos

- O texto antigo deste arquivo descrevia o projeto como "parser SQL" — corrigido nesta atualização. Se houver outros docs com a mesma descrição errada, vale conferir.
- Mudanças não commitadas há tempo: risco de perder contexto. Vale agrupar em commits lógicos (server skeleton, upload atomic, push client, config refactor, etc.) e abrir PR.
- Nenhum CI configurado no repo até onde a árvore mostra (não há `.github/workflows/` visível).
- Sem `cargo` disponível no sandbox da sessão, então `cargo check`/`cargo test` precisam rodar localmente para confirmar que o estado atual compila.

## Próximos passos sugeridos

Quebrar o WIP em commits coerentes e abrir PR. Rodar `cargo check && cargo clippy --all-targets && cargo test` localmente. Adicionar workflow de CI mínimo (fmt + clippy + test). Cobrir `upload.rs`, `ini_patcher.rs` e `restart.rs` com testes de integração (incluindo casos de traversal e mismatch). Avaliar evolução do PSK para mTLS/HMAC conforme spec.

## Build & Test

```bash
cargo build
cargo test
cargo run -- daemon --config examples/config.toml
cargo run -- push --config examples/config.toml health
cargo run -- push --config examples/config.toml upload --file ./bin/appserver --target bin/appserver
cargo run -- push --config examples/config.toml ini --section Postgres --key Thread --value 40
cargo run -- push --config examples/config.toml restart --service totvs-appserver
```

## Links úteis

- [Spec técnica](./docs/tech-spec.md)
- [Exemplo de config](./examples/config.toml)
- [Cargo Docs](https://doc.rust-lang.org/cargo/)
- [Axum](https://docs.rs/axum/)

---

Last updated: 2026-04-24
