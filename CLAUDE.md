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
│   ├── middleware.rs    psk_auth (header x-erp-token)
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

Commits da sessão de 2026-04-24/25 (WIP consolidado + docs):

```
cff7154  docs(step 7/8): rustdoc for push::client
deb05f1  docs(step 6/8): rustdoc for ini_patcher
f778aa0  docs(step 5/8): rustdoc for restart_service
17caeb3  docs(step 4/8): rustdoc for atomic_upload
ab8e58d  docs(step 3/8): rustdoc for the HTTP server layer
201c9cc  docs(step 2/8): rustdoc for security primitives and middleware
bab0124  docs(step 1/8): rustdoc foundation — crate, mod and config types
83525a0  chore: add CLAUDE.md project memory
00b7892  feat(cli): subcommands Daemon / Push (Upload/Ini/Restart/Health)
9e13a10  feat(push): HTTP client for remote daemon
ea371ab  feat(daemon): HTTP server skeleton + upload/ini/restart/middleware/logging
35b278a  feat(config): DaemonConfig + PushConfig + validate_daemon
4587bb8  chore: add .gitignore
```

Commits anteriores em `main` seguem abaixo:

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

## Estado atual da working tree (sessão de 2026-04-25)

Branch `main`, **à frente de `origin/main` em 13 commits** (5 commits de WIP consolidado + 7 commits de docs + 1 commit de .gitignore). Working tree limpa.

Total de código Rust: ~1.728 linhas em 13 arquivos. A fase de documentação cobriu 100% dos itens públicos do crate com rustdoc; build e testes precisam ser validados localmente (sandbox da sessão não tem `cargo`).

## Fase de documentação (sessão de 2026-04-24/25)

Oito passos rustdoc encadeados (sem mudança de comportamento):

1. Fundação — crate-level, módulos, tipos de config.
2. `security`, `middleware`, `logging`.
3. `server` — tabela de rotas + contratos por handler.
4. `upload` — `atomic_upload`, premissas e erros.
5. `restart` — três camadas de defesa, permissão `systemctl`.
6. `ini_patcher` — nota sobre `target_file` ignorado, lock sem timeout.
7. `push::client` — mapa método→endpoint, hardcode `target_file`.
8. Este update em `CLAUDE.md`.

Convenção aplicada: prosa em PT-BR, seções rustdoc em inglês (`# Errors`, `# Panics`, `# Assumptions`) para compatibilidade com `rustdoc` e ferramentas.

## Decisões de design (ADRs)

- **Atomicidade de upload:** o arquivo é gravado primeiro em `tmp_dir`, validado por SHA-256 contra o header `X-SHA256` enviado pelo cliente, e só então renomeado para o destino final em `base_path`. Em caso de mismatch, o tmp é descartado e a operação falha com 400.
- **Allowlist de serviços:** `restart_service` só executa `systemctl restart` para IDs explicitamente listados em `daemon.allowed_services`. Tentativas fora dela retornam 403, mesmo com PSK válido.
- **Auth simples por PSK:** middleware Axum compara o header `x-erp-token` com `daemon.psk_token`. Suficiente para deploy interno; a spec considera mTLS/HMAC como evolução futura.
- **Patch de `.ini` com double-checksum:** `ini_patcher` retorna `checksum_before` e `checksum_after` para auditoria, e usa edição estrutural (`rust-ini`) em vez de regex para preservar comentários e formatação.
- **Defesa contra path traversal:** `upload.rs` valida que `target_path` resolvido não escapa de `base_path`; `ini_patcher.rs` faz a mesma checagem para o caminho do `.ini`.

## Problemas conhecidos / Débitos técnicos

Registrados durante a fase de docs (não corrigidos — apenas anotados):

- **`sha256_hex` duplicado em três arquivos** (`daemon::upload`, `daemon::ini_patcher::sha256_hex` (público), `push::client`). Consolidar em um helper compartilhado em `daemon::security` ou criar um módulo `util` é a evolução natural.
- **`PatchIniRequest::target_file` ignorado por `patch_dbaccess_ini_file`.** O endpoint HTTP `PATCH /api/v1/ini` sempre opera sobre `paths.dbaccessini_path` da config; o cliente `push::client::patch_ini` envia `target_file: "dbaccess.ini"` hardcoded. Trap conhecida — a decisão é manter o comportamento e revisar o protocolo depois (campo redundante hoje, ou virar de fato dispatch por arquivo).
- **Atomicidade de `fs::rename` depende de mesmo filesystem.** `tmp_dir` e `base_path` precisam estar no mesmo FS para o rename ser atômico no POSIX. A premissa não é validada em runtime; é responsabilidade da config.
- **Header PSK é `x-erp-token`, não `X-PSK-Token`.** Versões antigas deste arquivo diziam `X-PSK-Token` — corrigido. Quem ler a spec ou docs externos deve confirmar a string contra `daemon::middleware::PSK_HEADER`.
- **Lock de `.ini` não tem timeout.** `fs3::FileExt::lock_exclusive` bloqueia indefinidamente se outro processo segurar o arquivo. Improvável em operação normal, mas vale conhecer.
- **CI ausente.** Sem `.github/workflows/` no repo — fmt/clippy/test rodam só local até existir um workflow.
- **`cargo` indisponível na sessão.** A fase de docs foi puro rustdoc, sem mudança de comportamento, mas `cargo check && cargo clippy --all-targets && cargo test` precisa rodar localmente antes de push para validar que tudo compila.

## Próximos passos sugeridos

1. Rodar `cargo check && cargo clippy --all-targets && cargo test` localmente para confirmar que o estado documentado compila e os testes existentes passam.
2. Push de `main` (13 commits à frente de `origin/main`) ou abrir PR consolidando os commits.
3. Adicionar workflow de CI mínimo (fmt + clippy + test).
4. Fase 2 da sessão: revisão de segurança via `security-orchestrator` skill.
5. Fase 3: testes de integração via `teste`/`plano-teste-orquestrador` (cobrindo upload, ini_patcher, restart com casos de traversal, mismatch e command injection).
6. Avaliar evolução do PSK para mTLS/HMAC conforme spec.

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

Last updated: 2026-04-25
