//! Sanitização de paths e defesa contra traversal.
//!
//! Duas primitivas são expostas:
//!
//! - [`sanitize_relative_path`] — valida um path recebido como string
//!   (ex: header `X-Target-Path` num upload) e devolve um [`PathBuf`]
//!   normalizado, já livre de `..`, raiz absoluta, prefixos Windows e
//!   componentes não-UTF-8.
//! - [`secure_join`] — junta esse path sanitizado a uma `base_path`
//!   confiável (o `base_path` da config) e verifica que o resultado
//!   ainda fica dentro da base, protegendo contra qualquer truque que
//!   escape do escopo.
//!
//! Ambas são usadas pelo `daemon::upload` e `daemon::ini_patcher` como
//! guarda de entrada — qualquer path vindo da rede passa por aqui
//! antes de tocar o disco.

use std::path::{Component, Path, PathBuf};

/// Falhas possíveis na sanitização de um path relativo.
///
/// Cada variante corresponde a uma classe de ataque ou entrada
/// inválida. Em todos os casos a operação chamadora deve ser
/// **rejeitada** — nunca "corrigida" silenciosamente, já que isso
/// poderia mascarar tentativas de traversal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSecurityError {
    /// String vazia (ou só com whitespace) — não há o que validar.
    EmptyPath,
    /// Path começa com `/` (ou equivalente na plataforma). Só
    /// aceitamos paths relativos; a base vem da config.
    AbsolutePathForbidden,
    /// Path contém `..` — tentativa clássica de traversal.
    ParentTraversalForbidden,
    /// Path contém um prefixo de plataforma (ex: `C:` no Windows).
    /// Rejeitado para manter comportamento determinístico entre OSes.
    PrefixForbidden,
    /// Componente do path não é UTF-8 válido — impossível de
    /// converter para `&str` com segurança.
    NonUtf8ComponentForbidden,
    /// Componente normal veio vazio após parsing (caso degenerado,
    /// improvável mas possível com entrada adversarial).
    InvalidComponent,
    /// Resultado de [`secure_join`] escapou de `base_path`. Só pode
    /// acontecer se [`sanitize_relative_path`] tiver sido burlado —
    /// é o "cinto-e-suspensório" final.
    OutsideBasePath,
}

/// Sanitiza uma string recebida como path relativo.
///
/// Aceita entradas como `"bin/appserver"` ou `"./config/dbaccess.ini"`
/// e devolve o `PathBuf` equivalente sem componentes `.` redundantes.
/// Qualquer tentativa de `..`, path absoluto, prefixo de plataforma,
/// componente não-UTF-8 ou string vazia resulta em erro.
///
/// # Errors
///
/// Retorna a variante de [`PathSecurityError`] correspondente à
/// primeira violação encontrada — não acumula falhas:
///
/// - [`EmptyPath`](PathSecurityError::EmptyPath) se `input` for vazio
///   ou só whitespace (também após remoção de `./` redundantes).
/// - [`AbsolutePathForbidden`](PathSecurityError::AbsolutePathForbidden)
///   se `input` começar com `/` (ou equivalente).
/// - [`ParentTraversalForbidden`](PathSecurityError::ParentTraversalForbidden)
///   se qualquer componente for `..`.
/// - [`PrefixForbidden`](PathSecurityError::PrefixForbidden) para
///   prefixos Windows (`C:\`, `\\server\`, etc).
/// - [`NonUtf8ComponentForbidden`](PathSecurityError::NonUtf8ComponentForbidden)
///   se algum componente não for UTF-8 válido.
/// - [`InvalidComponent`](PathSecurityError::InvalidComponent) para
///   componentes normais vazios após parsing.
///
/// # Examples
///
/// ```ignore
/// use erp_agent::daemon::security::{sanitize_relative_path, PathSecurityError};
///
/// let ok = sanitize_relative_path("bin/appserver").unwrap();
/// assert_eq!(ok.to_str(), Some("bin/appserver"));
///
/// let err = sanitize_relative_path("../etc/passwd").unwrap_err();
/// assert_eq!(err, PathSecurityError::ParentTraversalForbidden);
/// ```
pub fn sanitize_relative_path(input: &str) -> Result<PathBuf, PathSecurityError> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Err(PathSecurityError::EmptyPath);
    }

    let candidate = Path::new(trimmed);

    if candidate.is_absolute() {
        return Err(PathSecurityError::AbsolutePathForbidden);
    }

    let mut sanitized = PathBuf::new();

    for component in candidate.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => {
                let value = part
                    .to_str()
                    .ok_or(PathSecurityError::NonUtf8ComponentForbidden)?;

                if value.is_empty() {
                    return Err(PathSecurityError::InvalidComponent);
                }

                sanitized.push(value);
            }
            Component::ParentDir => return Err(PathSecurityError::ParentTraversalForbidden),
            Component::RootDir => return Err(PathSecurityError::AbsolutePathForbidden),
            Component::Prefix(_) => return Err(PathSecurityError::PrefixForbidden),
        }
    }

    if sanitized.as_os_str().is_empty() {
        return Err(PathSecurityError::EmptyPath);
    }

    Ok(sanitized)
}

/// Junta `relative_path` (não confiável) a `base_path` (confiável) e
/// garante que o resultado permanece dentro da base.
///
/// É a função que upload e ini_patcher chamam para transformar um
/// path vindo da rede num caminho absoluto seguro antes de qualquer
/// I/O. Primeiro sanitiza via [`sanitize_relative_path`], depois faz
/// o `join` e finalmente confere via `Path::starts_with` que não
/// escapou da base (defesa em profundidade).
///
/// # Errors
///
/// - Todas as variantes que [`sanitize_relative_path`] pode retornar,
///   se `relative_path` violar as regras de sanitização.
/// - [`OutsideBasePath`](PathSecurityError::OutsideBasePath) se o
///   caminho resultante não começar com `base_path`. Só pode ocorrer
///   se a sanitização falhar em algo sutil — serve de rede de
///   segurança.
pub fn secure_join(base_path: &Path, relative_path: &str) -> Result<PathBuf, PathSecurityError> {
    let sanitized_relative = sanitize_relative_path(relative_path)?;
    let joined = base_path.join(sanitized_relative);

    if !joined.starts_with(base_path) {
        return Err(PathSecurityError::OutsideBasePath);
    }

    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_safe_relative_path() {
        let path = sanitize_relative_path("bin/appserver/appserver.ini").unwrap();
        assert_eq!(path, PathBuf::from("bin/appserver/appserver.ini"));
    }

    #[test]
    fn rejects_parent_traversal() {
        let err = sanitize_relative_path("../etc/passwd").unwrap_err();
        assert_eq!(err, PathSecurityError::ParentTraversalForbidden);
    }

    #[test]
    fn rejects_absolute_paths() {
        let err = sanitize_relative_path("/totvs/dbaccess.ini").unwrap_err();
        assert_eq!(err, PathSecurityError::AbsolutePathForbidden);
    }

    #[test]
    fn secure_join_keeps_result_inside_base() {
        let joined = secure_join(Path::new("/totvs"), "bin/dbaccess.ini").unwrap();
        assert_eq!(joined, PathBuf::from("/totvs/bin/dbaccess.ini"));
    }
}
