use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(has_nono_signal_mode)");

    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR").map(PathBuf::from) else {
        return;
    };
    let is_packaged_verify_build = manifest_dir
        .components()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|window| {
            matches!(window, [target, package]
            if target.as_os_str() == "target" && package.as_os_str() == "package")
        });

    let capability_path = manifest_dir.join("../../../infra/vendor/nono/src/capability.rs");

    let has_signal_mode = !is_packaged_verify_build
        && fs::read_to_string(capability_path)
            .map(|source| {
                source.contains("pub enum SignalMode") && source.contains("fn signal_mode")
            })
            .unwrap_or(false);

    if has_signal_mode {
        println!("cargo:rustc-cfg=has_nono_signal_mode");
    }
}
