use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSecurityError {
    EmptyPath,
    AbsolutePathForbidden,
    ParentTraversalForbidden,
    PrefixForbidden,
    NonUtf8ComponentForbidden,
    InvalidComponent,
    OutsideBasePath,
}

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
