use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

const TUI_DIR_ENV: &str = "CLAWDSTRIKE_TUI_DIR";
const TUI_RUNTIME_SOURCE_ENV: &str = "CLAWDSTRIKE_TUI_RUNTIME_SOURCE";
const TUI_RUNTIME_SCRIPT_ENV: &str = "CLAWDSTRIKE_TUI_RUNTIME_SCRIPT";
const TUI_HUNT_BINARY_ENV: &str = "CLAWDSTRIKE_TUI_HUNT_BINARY";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TuiScriptSource {
    Override,
    InstalledBundle,
    RepoSource,
}

impl TuiScriptSource {
    fn as_env_value(self) -> &'static str {
        match self {
            Self::Override => "override",
            Self::InstalledBundle => "installed-bundle",
            Self::RepoSource => "repo-source",
        }
    }
}

#[derive(Clone, Debug)]
struct ResolvedTuiScript {
    path: PathBuf,
    source: TuiScriptSource,
}

pub(crate) fn cmd_tui(args: Vec<String>, no_color: bool, stderr: &mut dyn Write) -> i32 {
    let script = match resolve_tui_script() {
        Some(path) => path,
        None => {
            let _ = writeln!(
                stderr,
                "Error: could not locate the TUI runtime. Set {} to the TUI bundle or apps/terminal directory.",
                TUI_DIR_ENV
            );
            return 4;
        }
    };
    let tui_dir = match resolve_tui_dir(&script.path) {
        Some(path) => path,
        None => {
            let _ = writeln!(
                stderr,
                "Error: failed to resolve the TUI runtime directory."
            );
            return 4;
        }
    };

    let cwd = match env::current_dir() {
        Ok(path) => path,
        Err(err) => {
            let _ = writeln!(stderr, "Error: failed to resolve current directory: {err}");
            return 4;
        }
    };

    let has_cwd = args
        .iter()
        .any(|arg| arg == "--cwd" || arg.starts_with("--cwd="));
    let has_no_color = args.iter().any(|arg| arg == "--no-color");
    let normalized_args = normalize_explicit_cwd_args(args, &cwd);

    let mut child_args = vec![
        "run".to_string(),
        script.path.to_string_lossy().into_owned(),
        "--".to_string(),
    ];
    if !has_cwd {
        child_args.push("--cwd".to_string());
        child_args.push(cwd.to_string_lossy().into_owned());
    }
    if no_color && !has_no_color {
        child_args.push("--no-color".to_string());
    }
    child_args.extend(normalized_args);

    let mut command = Command::new("bun");
    command
        .args(&child_args)
        .env(TUI_RUNTIME_SOURCE_ENV, script.source.as_env_value())
        .env(TUI_RUNTIME_SCRIPT_ENV, &script.path)
        .current_dir(&tui_dir);

    if let Ok(exe) = env::current_exe() {
        command.env(TUI_HUNT_BINARY_ENV, exe);
    }

    match command.status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(err) => {
            let hint = if err.kind() == std::io::ErrorKind::NotFound {
                " Is Bun installed and on PATH?"
            } else {
                ""
            };
            let _ = writeln!(stderr, "Error: failed to launch TUI via bun: {err}.{hint}");
            4
        }
    }
}

fn normalize_explicit_cwd_args(args: Vec<String>, base_cwd: &Path) -> Vec<String> {
    let mut normalized = Vec::with_capacity(args.len());
    let mut iter = args.into_iter();

    while let Some(arg) = iter.next() {
        if arg == "--cwd" {
            normalized.push(arg);
            if let Some(value) = iter.next() {
                normalized.push(resolve_cwd_arg(&value, base_cwd));
            }
            continue;
        }

        if let Some(value) = arg.strip_prefix("--cwd=") {
            normalized.push(format!("--cwd={}", resolve_cwd_arg(value, base_cwd)));
            continue;
        }

        normalized.push(arg);
    }

    normalized
}

fn resolve_cwd_arg(value: &str, base_cwd: &Path) -> String {
    let path = Path::new(value);
    if path.is_absolute() {
        return value.to_string();
    }

    base_cwd.join(path).to_string_lossy().into_owned()
}

fn resolve_tui_script() -> Option<ResolvedTuiScript> {
    if let Some(dir) = env::var_os(TUI_DIR_ENV) {
        let path = resolve_override_tui_dir(&dir);
        let script = normalize_tui_path(&path);
        if script.is_file() {
            return Some(ResolvedTuiScript {
                path: script,
                source: TuiScriptSource::Override,
            });
        }
    }

    if let Ok(exe) = env::current_exe() {
        if let Some(script) = resolve_installed_tui_bundle(&exe) {
            return Some(ResolvedTuiScript {
                path: script,
                source: TuiScriptSource::InstalledBundle,
            });
        }
    }

    if let Ok(current_dir) = env::current_dir() {
        if let Some(script) = find_tui_repo_script(&current_dir) {
            return Some(ResolvedTuiScript {
                path: script,
                source: TuiScriptSource::RepoSource,
            });
        }
    }

    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            if let Some(script) = find_tui_repo_script(parent) {
                return Some(ResolvedTuiScript {
                    path: script,
                    source: TuiScriptSource::RepoSource,
                });
            }
        }
    }

    let manifest_fallback =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../apps/terminal/src/cli/index.ts");
    if manifest_fallback.is_file() {
        return Some(ResolvedTuiScript {
            path: manifest_fallback,
            source: TuiScriptSource::RepoSource,
        });
    }
    None
}

fn resolve_override_tui_dir(path: &std::ffi::OsStr) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        return path;
    }

    match env::current_dir() {
        Ok(current_dir) => current_dir.join(path),
        Err(_) => path,
    }
}

fn normalize_tui_path(path: &Path) -> PathBuf {
    if path
        .file_name()
        .is_some_and(|name| name == "index.ts" || name == "cli.js")
    {
        return path.to_path_buf();
    }

    let bundle = path.join("cli.js");
    if bundle.is_file() {
        return bundle;
    }

    path.join("src/cli/index.ts")
}

fn resolve_installed_tui_bundle(exe: &Path) -> Option<PathBuf> {
    let bin_dir = exe.parent()?;
    let candidate = bin_dir
        .join("..")
        .join("share")
        .join("clawdstrike")
        .join("tui")
        .join("cli.js");
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

fn find_tui_repo_script(start: &Path) -> Option<PathBuf> {
    for ancestor in start.ancestors() {
        let candidate = ancestor.join("apps/terminal/src/cli/index.ts");
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

fn resolve_tui_dir(script: &Path) -> Option<PathBuf> {
    if script.file_name().is_some_and(|name| name == "index.ts")
        && script
            .parent()?
            .file_name()
            .is_some_and(|name| name == "cli")
    {
        return Some(script.parent()?.parent()?.parent()?.to_path_buf());
    }

    Some(script.parent()?.to_path_buf())
}

#[cfg(all(test, unix))]
mod tests {
    use super::{cmd_tui, resolve_installed_tui_bundle, resolve_tui_script, TUI_DIR_ENV};
    use std::env;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};
    use tempfile::tempdir;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn write_executable(path: &Path, content: &str) {
        fs::write(path, content).expect("write executable");
        let mut perms = fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("set permissions");
    }

    #[test]
    fn cmd_tui_invokes_bun_with_injected_cwd_and_no_color() {
        let _guard = env_lock().lock().expect("env lock");
        let temp = tempdir().expect("tempdir");
        let tui_dir = temp.path().join("apps/terminal");
        let script_path = tui_dir.join("src/cli/index.ts");
        fs::create_dir_all(script_path.parent().expect("script parent")).expect("create tui dir");
        fs::write(&script_path, "// stub").expect("write script");

        let bin_dir = temp.path().join("bin");
        fs::create_dir_all(&bin_dir).expect("create bin");
        let args_file = temp.path().join("bun-args.log");
        let cwd_file = temp.path().join("bun-cwd.log");
        let env_file = temp.path().join("bun-env.log");
        let bun_path = bin_dir.join("bun");
        write_executable(
            &bun_path,
            &format!(
                "#!/bin/sh\nprintf '%s\n' \"$PWD\" > \"{}\"\nprintf '%s\n' \"$@\" > \"{}\"\nprintf '%s\n%s\n%s\n' \"$CLAWDSTRIKE_TUI_RUNTIME_SOURCE\" \"$CLAWDSTRIKE_TUI_RUNTIME_SCRIPT\" \"$CLAWDSTRIKE_TUI_HUNT_BINARY\" > \"{}\"\nexit 0\n",
                cwd_file.display(),
                args_file.display(),
                env_file.display()
            ),
        );

        let old_path = env::var_os("PATH");
        let current_dir = env::current_dir().expect("current dir");
        unsafe {
            env::set_var(TUI_DIR_ENV, &tui_dir);
            env::set_var(
                "PATH",
                format!(
                    "{}:{}",
                    bin_dir.display(),
                    old_path.as_deref().unwrap_or_default().to_string_lossy()
                ),
            );
        }

        let mut stderr = Vec::new();
        let exit = cmd_tui(vec!["doctor".into(), "--json".into()], true, &mut stderr);

        let args = fs::read_to_string(&args_file).expect("read args");
        let cwd = fs::read_to_string(&cwd_file).expect("read cwd");
        let env_text = fs::read_to_string(&env_file).expect("read env");
        let logged_cwd = fs::canonicalize(cwd.trim()).expect("canonicalize logged cwd");
        let expected_cwd = fs::canonicalize(&tui_dir).expect("canonicalize expected cwd");

        assert_eq!(exit, 0);
        assert!(stderr.is_empty());
        assert_eq!(logged_cwd, expected_cwd);
        assert!(args.contains("run"));
        assert!(args.contains("src/cli/index.ts"));
        assert!(args.contains("--cwd"));
        assert!(args.contains(current_dir.to_string_lossy().as_ref()));
        assert!(args.contains("--no-color"));
        assert!(args.contains("doctor"));
        assert!(args.contains("--json"));
        assert!(env_text.contains("override"));
        assert!(env_text.contains("src/cli/index.ts"));
        assert!(env_text.contains("clawdstrike") || env_text.contains("hush"));

        unsafe {
            env::remove_var(TUI_DIR_ENV);
            if let Some(path) = old_path {
                env::set_var("PATH", path);
            } else {
                env::remove_var("PATH");
            }
        }
    }

    #[test]
    fn cmd_tui_respects_explicit_cwd_and_existing_no_color() {
        let _guard = env_lock().lock().expect("env lock");
        let temp = tempdir().expect("tempdir");
        let tui_dir = temp.path().join("apps/terminal");
        let script_path = tui_dir.join("src/cli/index.ts");
        fs::create_dir_all(script_path.parent().expect("script parent")).expect("create tui dir");
        fs::write(&script_path, "// stub").expect("write script");

        let bin_dir = temp.path().join("bin");
        fs::create_dir_all(&bin_dir).expect("create bin");
        let args_file = temp.path().join("bun-args.log");
        let bun_path = bin_dir.join("bun");
        write_executable(
            &bun_path,
            &format!(
                "#!/bin/sh\nprintf '%s\n' \"$@\" > \"{}\"\nexit 0\n",
                args_file.display()
            ),
        );

        let old_path = env::var_os("PATH");
        let explicit_cwd = temp.path().join("custom-cwd");
        unsafe {
            env::set_var(TUI_DIR_ENV, &tui_dir);
            env::set_var(
                "PATH",
                format!(
                    "{}:{}",
                    bin_dir.display(),
                    old_path.as_deref().unwrap_or_default().to_string_lossy()
                ),
            );
        }

        let mut stderr = Vec::new();
        let exit = cmd_tui(
            vec![
                "doctor".into(),
                "--cwd".into(),
                explicit_cwd.display().to_string(),
                "--no-color".into(),
            ],
            true,
            &mut stderr,
        );

        let args = fs::read_to_string(&args_file).expect("read args");

        assert_eq!(exit, 0);
        assert!(stderr.is_empty());
        assert_eq!(args.matches("--cwd").count(), 1);
        assert_eq!(args.matches("--no-color").count(), 1);
        assert!(args.contains(explicit_cwd.to_string_lossy().as_ref()));

        unsafe {
            env::remove_var(TUI_DIR_ENV);
            if let Some(path) = old_path {
                env::set_var("PATH", path);
            } else {
                env::remove_var("PATH");
            }
        }
    }

    #[test]
    fn cmd_tui_resolves_relative_explicit_cwd_against_caller_directory() {
        let _guard = env_lock().lock().expect("env lock");
        let temp = tempdir().expect("tempdir");
        let tui_dir = temp.path().join("apps/terminal");
        let script_path = tui_dir.join("src/cli/index.ts");
        fs::create_dir_all(script_path.parent().expect("script parent")).expect("create tui dir");
        fs::write(&script_path, "// stub").expect("write script");

        let bin_dir = temp.path().join("bin");
        fs::create_dir_all(&bin_dir).expect("create bin");
        let args_file = temp.path().join("bun-args.log");
        let bun_path = bin_dir.join("bun");
        write_executable(
            &bun_path,
            &format!(
                "#!/bin/sh\nprintf '%s\n' \"$@\" > \"{}\"\nexit 0\n",
                args_file.display()
            ),
        );

        let old_path = env::var_os("PATH");
        let old_cwd = env::current_dir().expect("current dir");
        env::set_current_dir(temp.path()).expect("set current dir");
        unsafe {
            env::set_var(TUI_DIR_ENV, &tui_dir);
            env::set_var(
                "PATH",
                format!(
                    "{}:{}",
                    bin_dir.display(),
                    old_path.as_deref().unwrap_or_default().to_string_lossy()
                ),
            );
        }

        let mut stderr = Vec::new();
        let exit = cmd_tui(
            vec!["doctor".into(), "--cwd".into(), "apps/terminal".into()],
            false,
            &mut stderr,
        );

        let args = fs::read_to_string(&args_file).expect("read args");
        let expected_cwd = temp.path().join("apps/terminal");

        assert_eq!(exit, 0);
        assert!(stderr.is_empty());
        assert!(args.contains(expected_cwd.to_string_lossy().as_ref()));

        env::set_current_dir(old_cwd).expect("restore current dir");
        unsafe {
            env::remove_var(TUI_DIR_ENV);
            if let Some(path) = old_path {
                env::set_var("PATH", path);
            } else {
                env::remove_var("PATH");
            }
        }
    }

    #[test]
    fn resolve_installed_bundle_uses_bin_relative_share_dir() {
        let temp = tempdir().expect("tempdir");
        let exe = temp.path().join("bin").join("clawdstrike");
        fs::create_dir_all(exe.parent().expect("exe parent")).expect("create bin dir");
        let bundle = temp
            .path()
            .join("share")
            .join("clawdstrike")
            .join("tui")
            .join("cli.js");
        fs::create_dir_all(bundle.parent().expect("bundle parent")).expect("create share dir");
        fs::write(&bundle, "console.log('bundle')").expect("write bundle");

        let resolved = resolve_installed_tui_bundle(&exe).expect("resolve installed bundle");
        assert_eq!(
            fs::canonicalize(resolved).unwrap(),
            fs::canonicalize(bundle).unwrap()
        );
    }

    #[test]
    fn resolve_override_tui_dir_uses_caller_directory_for_relative_paths() {
        let _guard = env_lock().lock().expect("env lock");
        let temp = tempdir().expect("tempdir");
        let tui_dir = temp.path().join("apps/terminal");
        let script_path = tui_dir.join("src/cli/index.ts");
        fs::create_dir_all(script_path.parent().expect("script parent")).expect("create tui dir");
        fs::write(&script_path, "// stub").expect("write script");

        let old_cwd = env::current_dir().expect("current dir");
        env::set_current_dir(temp.path()).expect("set current dir");
        unsafe {
            env::set_var(TUI_DIR_ENV, "apps/terminal");
        }

        let resolved = resolve_tui_script().expect("resolve override");
        assert_eq!(
            fs::canonicalize(resolved.path).unwrap(),
            fs::canonicalize(script_path).unwrap()
        );

        env::set_current_dir(old_cwd).expect("restore current dir");
        unsafe {
            env::remove_var(TUI_DIR_ENV);
        }
    }
}
