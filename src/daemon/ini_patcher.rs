use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fs3::FileExt;
use ini::Ini;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::AppConfig;
use crate::daemon::security::{sanitize_relative_path, secure_join, PathSecurityError};

#[derive(Debug, Deserialize)]
pub struct PatchIniRequest {
    pub target_file: String,
    pub section: String,
    pub key: String,
    pub new_value: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PatchIniResult {
    pub path: PathBuf,
    pub changed: bool,
    pub checksum_before: String,
    pub checksum_after: String,
}

#[derive(Debug)]
pub enum IniPatchError {
    InvalidPath(PathSecurityError),
    FileNotFound(PathBuf),
    Io(std::io::Error),
    Parse(ini::Error),
    MissingSection(String),
    InvalidConfiguredPath(PathSecurityError),
}

impl From<std::io::Error> for IniPatchError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ini::Error> for IniPatchError {
    fn from(value: ini::Error) -> Self {
        Self::Parse(value)
    }
}

pub fn patch_dbaccess_ini_file(
    config: &AppConfig,
    request: &PatchIniRequest,
) -> Result<PatchIniResult, IniPatchError> {
    let target_path = configured_dbaccess_ini_path(config)?;
    patch_ini_at_path(&target_path, request)
}

fn configured_dbaccess_ini_path(config: &AppConfig) -> Result<PathBuf, IniPatchError> {
    let configured_path = &config.dbaccessini_path;

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

pub fn patch_ini_file(
    base_path: &Path,
    request: &PatchIniRequest,
) -> Result<PatchIniResult, IniPatchError> {
    let target_path =
        secure_join(base_path, &request.target_file).map_err(IniPatchError::InvalidPath)?;
    patch_ini_at_path(&target_path, request)
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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn patch_is_idempotent_when_value_is_already_set() {
        let base = temp_dir();
        let ini_path = base.join("dbaccess.ini");
        fs::write(&ini_path, "[Postgres]\nThread=40\nPassword=secret\n").unwrap();

        let request = PatchIniRequest {
            target_file: "dbaccess.ini".into(),
            section: "Postgres".into(),
            key: "Thread".into(),
            new_value: "40".into(),
        };

        let before = fs::read_to_string(&ini_path).unwrap();
        let result = patch_ini_file(&base, &request).unwrap();
        let after = fs::read_to_string(&ini_path).unwrap();

        assert!(!result.changed);
        assert_eq!(before, after);
    }

    #[test]
    fn patch_updates_only_requested_key() {
        let base = temp_dir();
        let ini_path = base.join("dbaccess.ini");
        fs::write(&ini_path, "[Postgres]\nThread=10\nPassword=encrypted\n").unwrap();

        let request = PatchIniRequest {
            target_file: "dbaccess.ini".into(),
            section: "Postgres".into(),
            key: "Thread".into(),
            new_value: "40".into(),
        };

        let result = patch_ini_file(&base, &request).unwrap();
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
            "[Postgres]
Thread=10
Password=encrypted
",
        )
        .unwrap();

        let config = AppConfig {
            dbaccess_path: base.join("bin/dbaccess"),
            dbaccessini_path: ini_path.clone(),
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
            dbaccess_path: PathBuf::from("/totvs/bin/dbaccess"),
            dbaccessini_path: PathBuf::from("../dbaccess.ini"),
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
