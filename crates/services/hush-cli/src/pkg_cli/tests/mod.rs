use super::*;

fn run_cmd(cmd: PkgCommands) -> (String, String, ExitCode) {
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let code = cmd_pkg(cmd, &mut stdout_buf, &mut stderr_buf);
    (
        String::from_utf8_lossy(&stdout_buf).to_string(),
        String::from_utf8_lossy(&stderr_buf).to_string(),
        code,
    )
}

include!("scaffold_and_pack.rs");
include!("commands.rs");
include!("validation.rs");
include!("registry.rs");
