//! `pkg init` — scaffold a new package in the current directory.

use std::io::Write;

use super::scaffold::scaffold_package;
use super::CliPkgType;
use crate::ExitCode;

pub(super) fn cmd_pkg_init(
    pkg_type: &CliPkgType,
    name: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot determine current directory: {e}");
            return ExitCode::RuntimeError;
        }
    };

    // Generate scaffold based on type
    let core_type = pkg_type.to_pkg_type();
    if let Err(e) = scaffold_package(&cwd, &core_type, name) {
        let _ = writeln!(stderr, "Error: {e}");
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(
        stdout,
        "Initialized {} package '{}' in {}",
        pkg_type.label(),
        name,
        cwd.display()
    );
    ExitCode::Ok
}
