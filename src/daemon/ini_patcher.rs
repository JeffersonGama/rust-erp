use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fs3::FileExt;
use ini::Ini;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::daemon::security::{secure_join, PathSecurityError};

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

pub fn patch_ini_file(
    base_path: &Path,
    request: &PatchIniRequest,
) -> Result<PatchIniResult, IniPatchError> {
    let target_path =
        secure_join(base_path, &request.target_file).map_err(IniPatchError::InvalidPath)?;

    if !target_path.is_file() {
        return Err(IniPatchError::FileNotFound(target_path));
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&target_path)?;
    file.lock_exclusive()?;

    let patch_result = patch_locked_file(&mut file, &target_path, request);
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
}
