use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut includes = vec![PathBuf::from("proto")];

    if let Ok(include_path) = std::env::var("PROTOC_INCLUDE") {
        includes.push(PathBuf::from(include_path));
    }

    // Debian protobuf-compiler installs well-known protos under /usr/include.
    if Path::new("/usr/include/google/protobuf").exists() {
        includes.push(PathBuf::from("/usr/include"));
    }

    tonic_build::configure()
        .build_server(false)
        .compile_protos(&["proto/flow.proto", "proto/observer.proto"], &includes)?;
    Ok(())
}
