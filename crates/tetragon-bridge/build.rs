fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .compile_protos(&["proto/tetragon.proto"], &["proto"])?;
    Ok(())
}
