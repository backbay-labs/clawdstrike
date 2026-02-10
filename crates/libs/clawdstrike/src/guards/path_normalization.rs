//! Shared path normalization for policy path matching.

use std::path::Path;

/// Normalize a path for policy glob matching.
///
/// Rules:
/// - Convert `\` to `/`
/// - Collapse repeated separators
/// - Remove `.` segments
/// - Resolve `..` segments lexically (without filesystem access)
pub fn normalize_path_for_policy(path: &str) -> String {
    let path = path.replace('\\', "/");
    let is_absolute = path.starts_with('/');

    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }

        if segment == ".." {
            if let Some(last) = segments.last().copied() {
                if last != ".." {
                    segments.pop();
                    continue;
                }
            }
            if !is_absolute {
                segments.push(segment);
            }
            continue;
        }

        segments.push(segment);
    }

    if is_absolute {
        if segments.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", segments.join("/"))
        }
    } else if segments.is_empty() {
        ".".to_string()
    } else {
        segments.join("/")
    }
}

/// Normalize a path for policy matching, preferring filesystem-resolved targets when possible.
///
/// - For existing paths, this resolves symlinks via `canonicalize`.
/// - For non-existing write targets, this resolves the parent directory and rejoins the filename.
/// - Falls back to lexical normalization when resolution is not possible.
pub fn normalize_path_for_policy_with_fs(path: &str) -> String {
    resolve_path_for_policy(path).unwrap_or_else(|| normalize_path_for_policy(path))
}

fn resolve_path_for_policy(path: &str) -> Option<String> {
    let raw = Path::new(path);
    if let Ok(canonical) = std::fs::canonicalize(raw) {
        return Some(normalize_path_for_policy(&canonical.to_string_lossy()));
    }

    let parent = raw.parent()?;
    let canonical_parent = std::fs::canonicalize(parent).ok()?;
    let candidate = match raw.file_name() {
        Some(name) => canonical_parent.join(name),
        None => canonical_parent,
    };
    Some(normalize_path_for_policy(&candidate.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use super::{normalize_path_for_policy, normalize_path_for_policy_with_fs};

    #[test]
    fn normalizes_separators_and_dots() {
        assert_eq!(
            normalize_path_for_policy(r"C:\repo\src\.\main.rs"),
            "C:/repo/src/main.rs"
        );
        assert_eq!(normalize_path_for_policy("/tmp///foo//bar"), "/tmp/foo/bar");
    }

    #[test]
    fn resolves_parent_segments_lexically() {
        assert_eq!(
            normalize_path_for_policy("/workspace/a/b/../c/./file.txt"),
            "/workspace/a/c/file.txt"
        );
        assert_eq!(normalize_path_for_policy("a/b/../../c"), "c");
        assert_eq!(normalize_path_for_policy("../a/../b"), "../b");
    }

    #[test]
    fn fs_aware_normalization_uses_canonical_parent_for_new_file() {
        let root =
            std::env::temp_dir().join(format!("path-normalization-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create root");
        let candidate = root.join("new_file.txt");
        let normalized = normalize_path_for_policy_with_fs(candidate.to_str().expect("utf-8 path"));
        assert!(
            normalized.ends_with("/new_file.txt"),
            "normalized path should preserve file name, got {normalized}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
