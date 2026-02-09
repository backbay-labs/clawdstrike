use std::path::PathBuf;
use std::process::{Command, ExitStatus};

fn main() {
    eprintln!("clawdstrike is deprecated; use `hush` instead.");

    let mut args = std::env::args_os();
    // Skip argv[0]
    let _ = args.next();

    let status = match find_hush_exe() {
        Some(hush) => Command::new(hush).args(args).status(),
        None => Command::new("hush").args(args).status(),
    };

    match status {
        Ok(status) => exit_with_status(status),
        Err(e) => {
            eprintln!("Failed to execute hush: {e}");
            std::process::exit(1);
        }
    }
}

fn find_hush_exe() -> Option<PathBuf> {
    let mut exe = std::env::current_exe().ok()?;
    exe.set_file_name(exe_name("hush"));
    if exe.exists() {
        return Some(exe);
    }
    None
}

fn exe_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

fn exit_with_status(status: ExitStatus) -> ! {
    match status.code() {
        Some(code) => std::process::exit(code),
        None => std::process::exit(1),
    }
}
