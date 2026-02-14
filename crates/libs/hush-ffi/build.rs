#![allow(clippy::unwrap_used, clippy::expect_used)]

fn main() {
    #[cfg(feature = "cbindgen")]
    {
        use std::env;
        use std::path::PathBuf;

        let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let out_dir = PathBuf::from(&crate_dir);

        let config = cbindgen::Config::from_file("cbindgen.toml")
            .unwrap_or_else(|_| cbindgen::Config::default());

        if let Ok(bindings) = cbindgen::Builder::new()
            .with_crate(&crate_dir)
            .with_config(config)
            .generate()
        {
            bindings.write_to_file(out_dir.join("hush.h"));
        }
    }
}
