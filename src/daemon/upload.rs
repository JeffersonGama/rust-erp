//! Upload atômico: tmp → SHA-256 → rename.
//!
//! Uma única função pública — [`atomic_upload`] — implementa o RF01
//! da tech-spec: receber bytes da rede, gravar num arquivo temporário
//! separado do destino, validar o conteúdo contra um checksum
//! fornecido pelo cliente e só então mover para o local definitivo
//! via `fs::rename`. O destino nunca enxerga um arquivo parcial ou
//! corrompido: o `rename` é atômico no POSIX desde que tmp e destino
//! vivam no mesmo filesystem.

use std::path::{Path, PathBuf};

use axum::body::Bytes;
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::daemon::security::{secure_join, PathSecurityError};

/// Falhas possíveis durante um upload atômico.
///
/// `InvalidPath` e `ChecksumMismatch` indicam problema na request
/// (cliente vira 400). `Io` é erro infraestrutural (vira 500 no handler).
#[derive(Debug)]
pub enum UploadError {
    /// `target_relative` violou as regras de [`secure_join`]
    /// (traversal, path absoluto, prefixo, etc).
    InvalidPath(PathSecurityError),
    /// O SHA-256 calculado sobre os bytes gravados não bateu com
    /// o valor declarado no header `X-SHA256`. O arquivo temporário
    /// foi removido antes do retorno.
    ChecksumMismatch { expected: String, actual: String },
    /// Qualquer falha de I/O durante a escrita/leitura/rename.
    Io(std::io::Error),
}

impl std::fmt::Display for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath(e) => write!(f, "invalid target path: {e:?}"),
            Self::ChecksumMismatch { expected, actual } => {
                write!(f, "SHA-256 mismatch: expected={expected}, actual={actual}")
            }
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl From<std::io::Error> for UploadError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// Grava `body` em `base_path / target_relative` com garantias
/// atômicas.
///
/// Fluxo:
///
/// 1. `target_relative` é sanitizado e resolvido contra `base_path`
///    via [`secure_join`] — qualquer traversal é rejeitado aqui.
/// 2. `tmp_dir` é criado se ainda não existir
///    (`create_dir_all`). O nome do arquivo temporário usa
///    nanossegundos desde `UNIX_EPOCH`, suficiente para evitar
///    colisão em uso single-process.
/// 3. `body` é gravado integralmente no tmp e sincronizado com
///    `sync_all` (fsync) antes de fechar.
/// 4. O conteúdo é re-lido e passado pelo SHA-256. Se
///    `expected_sha256` **não for vazio**, compara em lowercase.
///    Divergência: remove o tmp e devolve
///    [`UploadError::ChecksumMismatch`].
/// 5. `final_path.parent()` é garantido (`create_dir_all`) e o
///    rename atômico move o tmp para o destino.
/// 6. Log estruturado emitido com path final, checksum e tamanho.
///
/// # Assumptions
///
/// - `tmp_dir` e `base_path` devem viver no **mesmo filesystem** —
///   o `fs::rename` só é atômico sob essa condição. Essa premissa
///   não é validada em runtime; é responsabilidade da configuração.
/// - Nome de arquivo temporário não é cryptographically unique.
///   Seguro para um daemon single-writer; se múltiplos processos
///   compartilharem o tmp_dir, colisões ficam teoricamente possíveis.
/// - `expected_sha256` vazio **pula a verificação** — útil em testes
///   e uploads internos, mas em produção o cliente sempre envia.
///
/// # Errors
///
/// - [`UploadError::InvalidPath`] se `target_relative` falhar em
///   [`secure_join`] (traversal, absoluto, etc).
/// - [`UploadError::ChecksumMismatch`] se `expected_sha256` não
///   estiver vazio e não bater com o conteúdo gravado.
/// - [`UploadError::Io`] para qualquer falha de
///   `create_dir_all`/`File::create`/`write_all`/`rename`, etc.
pub async fn atomic_upload(
    base_path: &Path,
    tmp_dir: &Path,
    target_relative: &str,
    expected_sha256: &str,
    body: Bytes,
) -> Result<PathBuf, UploadError> {
    // Validar path de destino (anti-traversal).
    let final_path =
        secure_join(base_path, target_relative).map_err(UploadError::InvalidPath)?;

    // Garantir que tmp_dir existe.
    if !tmp_dir.exists() {
        fs::create_dir_all(tmp_dir).await?;
    }

    // Gerar nome temporário único.
    let tmp_filename = format!(
        "upload-{}.tmp",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let tmp_path = tmp_dir.join(&tmp_filename);

    // Escrever body no arquivo temporário.
    let mut tmp_file = fs::File::create(&tmp_path).await?;
    tmp_file.write_all(&body).await?;
    tmp_file.sync_all().await?;
    drop(tmp_file);

    // Calcular SHA-256 do arquivo escrito.
    let written_bytes = fs::read(&tmp_path).await?;
    let actual_sha256 = sha256_hex(&written_bytes);

    // Validar checksum.
    if !expected_sha256.is_empty() && actual_sha256 != expected_sha256.to_lowercase() {
        // Limpar arquivo temporário em caso de mismatch.
        let _ = fs::remove_file(&tmp_path).await;
        return Err(UploadError::ChecksumMismatch {
            expected: expected_sha256.to_lowercase(),
            actual: actual_sha256,
        });
    }

    // Garantir que o diretório pai do destino existe.
    if let Some(parent) = final_path.parent() {
        fs::create_dir_all(parent).await?;
    }

    // Rename atômico: tmp → destino final.
    fs::rename(&tmp_path, &final_path).await?;

    tracing::info!(
        target_path = %final_path.display(),
        sha256 = %actual_sha256,
        size_bytes = written_bytes.len(),
        "upload completed atomically"
    );

    Ok(final_path)
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

    fn test_dirs() -> (PathBuf, PathBuf) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("erp-upload-test-{unique}"));
        let tmp = base.join(".tmp");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::create_dir_all(&tmp).unwrap();
        (base, tmp)
    }

    #[tokio::test]
    async fn upload_succeeds_with_valid_checksum() {
        let (base, tmp) = test_dirs();
        let content = b"hello erp-agent";
        let sha = sha256_hex(content);

        let result = atomic_upload(
            &base,
            &tmp,
            "bin/test-file.bin",
            &sha,
            Bytes::from_static(content),
        )
        .await
        .unwrap();

        assert!(result.exists());
        assert_eq!(std::fs::read(&result).unwrap(), content);
    }

    #[tokio::test]
    async fn upload_fails_on_checksum_mismatch() {
        let (base, tmp) = test_dirs();
        let content = b"hello erp-agent";

        let err = atomic_upload(
            &base,
            &tmp,
            "bin/test-file.bin",
            "0000000000000000000000000000000000000000000000000000000000000000",
            Bytes::from_static(content),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, UploadError::ChecksumMismatch { .. }));
        // Arquivo temporário deve ter sido limpo.
        assert!(std::fs::read_dir(&tmp).unwrap().count() == 0);
    }

    #[tokio::test]
    async fn upload_rejects_path_traversal() {
        let (base, tmp) = test_dirs();

        let err = atomic_upload(
            &base,
            &tmp,
            "../etc/passwd",
            "",
            Bytes::from_static(b"evil"),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, UploadError::InvalidPath(_)));
    }

    #[tokio::test]
    async fn upload_skips_checksum_when_empty() {
        let (base, tmp) = test_dirs();
        let content = b"no checksum required";

        let result = atomic_upload(
            &base,
            &tmp,
            "bin/loose.bin",
            "",
            Bytes::from_static(content),
        )
        .await
        .unwrap();

        assert!(result.exists());
    }
}
