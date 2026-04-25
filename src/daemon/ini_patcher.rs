//! Patch estrutural de arquivos `.ini` com lock exclusivo e
//! auditoria por double-checksum.
//!
//! Entrada pública: [`patch_dbaccess_ini_file`] — usada pelo
//! handler HTTP. Lê o path do `.ini` direto de
//! `config.paths.dbaccessini_path` e **ignora** o campo
//! `target_file` do payload (ver `NOTE` no item).
//!
//! Internamente: (1) adquire lock exclusivo via
//! `fs3::FileExt::lock_exclusive`, (2) lê o conteúdo e calcula
//! `checksum_before`, (3) edita a estrutura com `rust-ini`
//! (preserva comentários e ordem), (4) calcula `checksum_after` a
//! partir do buffer renderizado, (5) regrava o arquivo truncando
//! primeiro, (6) libera o lock. O par de checksums serve como
//! evidência em log de auditoria: o cliente pode armazenar antes/
//! depois e reconciliar caso o arquivo seja editado fora do daemon.
//!
//! # Assumptions
//!
//! - O lock exclusivo não tem timeout. Se outro processo segurar
//!   o arquivo, a chamada bloqueia indefinidamente. Na prática só
//!   o daemon toca nesse arquivo durante operação normal, mas é
//!   bom saber caso alguém mantenha o `.ini` aberto em editor
//!   com advisory lock.
//! - Edição estrutural com `rust-ini` preserva comentários e
//!   formatação, mas a ordem interna das chaves dentro de uma
//!   seção pode ser normalizada pelo parser — isso é aceitável
//!   para o DBAccess.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fs3::FileExt;
use ini::Ini;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::AppConfig;
use crate::daemon::security::{sanitize_relative_path, PathSecurityError};

/// Payload JSON aceito por `PATCH /api/v1/ini`.
///
/// O campo `target_file` vem do protocolo mas é **ignorado** pelo
/// endpoint HTTP — ver nota em [`patch_dbaccess_ini_file`].
#[derive(Debug, Deserialize)]
pub struct PatchIniRequest {
    // Mantido para compatibilidade do contrato HTTP — ignorado pelo
    // server, que sempre usa `paths.dbaccessini_path` da config.
    #[allow(dead_code)]
    pub target_file: String,
    /// Nome da seção (sem os colchetes) — ex: `"Postgres"`.
    pub section: String,
    /// Nome da chave a alterar — ex: `"Thread"`.
    pub key: String,
    /// Novo valor para a chave — ex: `"40"`.
    pub new_value: String,
}

/// Resultado de um patch bem-sucedido.
///
/// Os dois checksums viabilizam auditoria: o cliente pode registrar
/// o par `(checksum_before, checksum_after)` e detectar edições
/// externas ao daemon comparando com snapshots posteriores. Se
/// `changed` for `false`, os dois checksums são iguais e o arquivo
/// no disco não foi tocado.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PatchIniResult {
    /// Caminho absoluto que foi efetivamente editado.
    pub path: PathBuf,
    /// `false` quando a chave já tinha exatamente `new_value` — a
    /// operação é idempotente.
    pub changed: bool,
    /// SHA-256 (hex, lowercase) do conteúdo antes do patch.
    pub checksum_before: String,
    /// SHA-256 (hex, lowercase) do buffer renderizado que foi
    /// gravado. Idêntico a `checksum_before` quando `changed` é
    /// `false`.
    pub checksum_after: String,
}

/// Falhas possíveis em [`patch_dbaccess_ini_file`].
#[derive(Debug)]
pub enum IniPatchError {
    /// Arquivo alvo não existe ou não é um arquivo regular.
    FileNotFound(PathBuf),
    /// Falha de I/O (abertura, leitura, lock, write, truncate).
    Io(std::io::Error),
    /// Conteúdo do `.ini` é sintaticamente inválido para o
    /// `rust-ini` parser.
    Parse(ini::ParseError),
    /// Seção informada não existe no arquivo.
    MissingSection(String),
    /// `paths.dbaccessini_path` da config é relativo **e** falhou
    /// em [`sanitize_relative_path`] (ex: `../foo.ini`).
    InvalidConfiguredPath(PathSecurityError),
}

impl std::fmt::Display for IniPatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileNotFound(p) => write!(f, "file not found: {}", p.display()),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Parse(e) => write!(f, "INI parse error: {e}"),
            Self::MissingSection(s) => write!(f, "section not found: [{s}]"),
            Self::InvalidConfiguredPath(e) => write!(f, "invalid configured path: {e:?}"),
        }
    }
}

impl From<std::io::Error> for IniPatchError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ini::ParseError> for IniPatchError {
    fn from(value: ini::ParseError) -> Self {
        Self::Parse(value)
    }
}

/// Aplica `request` ao `.ini` configurado em
/// `config.paths.dbaccessini_path`.
///
/// Path absoluto é usado como está; path relativo passa por
/// [`sanitize_relative_path`] (bloqueia `..`, componentes vazios,
/// não-UTF-8). Depois o arquivo é aberto em modo RW, recebe lock
/// exclusivo e é patchado — o lock é liberado antes do retorno,
/// mesmo em caso de erro.
///
/// # NOTE
///
/// **`request.target_file` é ignorado por esta função.** O path é
/// determinado exclusivamente pela config — é o comportamento que
/// o handler HTTP expõe hoje. O campo segue no contrato HTTP por
/// decisão registrada em `CLAUDE.md` (revisão futura do protocolo).
///
/// # Errors
///
/// - [`IniPatchError::InvalidConfiguredPath`] se
///   `dbaccessini_path` for relativo e falhar na sanitização.
/// - [`IniPatchError::FileNotFound`] se o path resolvido não
///   apontar para um arquivo regular.
/// - [`IniPatchError::Io`] em falha de open/lock/read/write.
/// - [`IniPatchError::Parse`] se o `.ini` estiver malformado.
/// - [`IniPatchError::MissingSection`] se `request.section` não
///   existir no arquivo.
pub fn patch_dbaccess_ini_file(
    config: &AppConfig,
    request: &PatchIniRequest,
) -> Result<PatchIniResult, IniPatchError> {
    let target_path = configured_dbaccess_ini_path(config)?;
    patch_ini_at_path(&target_path, request)
}

fn configured_dbaccess_ini_path(config: &AppConfig) -> Result<PathBuf, IniPatchError> {
    let configured_path = &config.paths.dbaccessini_path;

    if configured_path.is_absolute() {
        return Ok(configured_path.clone());
    }

    sanitize_relative_path(configured_path.to_string_lossy().as_ref())
        .map_err(IniPatchError::InvalidConfiguredPath)
}

fn patch_ini_at_path(
    target_path: &Path,
    request: &PatchIniRequest,
) -> Result<PatchIniResult, IniPatchError> {
    if !target_path.is_file() {
        return Err(IniPatchError::FileNotFound(target_path.to_path_buf()));
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(target_path)?;
    file.lock_exclusive()?;

    let patch_result = patch_locked_file(&mut file, target_path, request);
    let unlock_result = file.unlock();

    match (patch_result, unlock_result) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(err), Ok(())) => Err(err),
        (Ok(_), Err(err)) => Err(IniPatchError::Io(err)),
        (Err(original_err), Err(_unlock_err)) => Err(original_err),
    }
}

fn patch_locked_file(
    file: &mut File,
    target_path: &Path,
    request: &PatchIniRequest,
) -> Result<PatchIniResult, IniPatchError> {
    file.seek(SeekFrom::Start(0))?;

    let mut original_content = String::new();
    file.read_to_string(&mut original_content)?;

    let checksum_before = sha256_hex(original_content.as_bytes());
    let mut ini = Ini::load_from_str(&original_content)?;

    let section_name = Some(request.section.as_str());
    let Some(section) = ini.section_mut(section_name) else {
        return Err(IniPatchError::MissingSection(request.section.clone()));
    };

    let changed = section.get(&request.key) != Some(request.new_value.as_str());

    if !changed {
        return Ok(PatchIniResult {
            path: target_path.to_path_buf(),
            changed: false,
            checksum_before: checksum_before.clone(),
            checksum_after: checksum_before,
        });
    }

    section.insert(request.key.clone(), request.new_value.clone());

    let mut rendered = Vec::new();
    ini.write_to(&mut rendered)?;
    let checksum_after = sha256_hex(&rendered);

    persist_locked_file(file, &rendered)?;

    Ok(PatchIniResult {
        path: target_path.to_path_buf(),
        changed: true,
        checksum_before,
        checksum_after,
    })
}

fn persist_locked_file(file: &mut File, rendered: &[u8]) -> Result<(), IniPatchError> {
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    file.write_all(rendered)?;
    file.sync_all()?;

    Ok(())
}

/// SHA-256 em hex lowercase — utilitário público por ora
/// duplicado em `daemon::upload` e `push::client`. Ver débitos
/// registrados em `CLAUDE.md`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("erp-agent-test-{unique}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn config_for(ini_path: &Path) -> AppConfig {
        AppConfig {
            daemon: Default::default(),
            push: None,
            paths: crate::config::models::PathsConfig {
                dbaccess_path: ini_path
                    .parent()
                    .unwrap_or_else(|| Path::new("/"))
                    .join("bin/dbaccess"),
                dbaccessini_path: ini_path.to_path_buf(),
            },
        }
    }

    #[test]
    fn patch_is_idempotent_when_value_is_already_set() {
        let base = temp_dir();
        let ini_path = base.join("dbaccess.ini");
        fs::write(&ini_path, "[Postgres]\nThread=40\nPassword=secret\n").unwrap();

        let config = config_for(&ini_path);
        let request = PatchIniRequest {
            target_file: "dbaccess.ini".into(),
            section: "Postgres".into(),
            key: "Thread".into(),
            new_value: "40".into(),
        };

        let before = fs::read_to_string(&ini_path).unwrap();
        let result = patch_dbaccess_ini_file(&config, &request).unwrap();
        let after = fs::read_to_string(&ini_path).unwrap();

        assert!(!result.changed);
        assert_eq!(before, after);
    }

    #[test]
    fn patch_updates_only_requested_key() {
        let base = temp_dir();
        let ini_path = base.join("dbaccess.ini");
        fs::write(&ini_path, "[Postgres]\nThread=10\nPassword=encrypted\n").unwrap();

        let config = config_for(&ini_path);
        let request = PatchIniRequest {
            target_file: "dbaccess.ini".into(),
            section: "Postgres".into(),
            key: "Thread".into(),
            new_value: "40".into(),
        };

        let result = patch_dbaccess_ini_file(&config, &request).unwrap();
        let after = fs::read_to_string(&ini_path).unwrap();

        assert!(result.changed);
        assert!(after.contains("Thread=40"));
        assert!(after.contains("Password=encrypted"));
    }

    #[test]
    fn patch_uses_dbaccess_ini_path_from_config() {
        let base = temp_dir();
        let ini_path = base.join("custom/dbaccess.ini");
        fs::create_dir_all(ini_path.parent().unwrap()).unwrap();
        fs::write(
            &ini_path,
            "[Postgres]\nThread=10\nPassword=encrypted\n",
        )
        .unwrap();

        let config = AppConfig {
            daemon: Default::default(),
            push: None,
            paths: crate::config::models::PathsConfig {
                dbaccess_path: base.join("bin/dbaccess"),
                dbaccessini_path: ini_path.clone(),
            },
        };

        let request = PatchIniRequest {
            target_file: "ignored-by-config.ini".into(),
            section: "Postgres".into(),
            key: "Thread".into(),
            new_value: "40".into(),
        };

        let result = patch_dbaccess_ini_file(&config, &request).unwrap();
        let after = fs::read_to_string(&ini_path).unwrap();

        assert!(result.changed);
        assert_eq!(result.path, ini_path);
        assert!(after.contains("Thread=40"));
    }

    #[test]
    fn patch_rejects_invalid_relative_path_from_config() {
        let config = AppConfig {
            daemon: Default::default(),
            push: None,
            paths: crate::config::models::PathsConfig {
                dbaccess_path: PathBuf::from("/totvs/bin/dbaccess"),
                dbaccessini_path: PathBuf::from("../dbaccess.ini"),
            },
        };

        let request = PatchIniRequest {
            target_file: "dbaccess.ini".into(),
            section: "Postgres".into(),
            key: "Thread".into(),
            new_value: "40".into(),
        };

        let err = patch_dbaccess_ini_file(&config, &request).unwrap_err();
        assert!(matches!(
            err,
            IniPatchError::InvalidConfiguredPath(PathSecurityError::ParentTraversalForbidden)
        ));
    }
}
