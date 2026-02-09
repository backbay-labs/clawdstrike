//! Shared path normalization for policy path matching.

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

#[cfg(test)]
mod tests {
    use super::normalize_path_for_policy;

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
}
