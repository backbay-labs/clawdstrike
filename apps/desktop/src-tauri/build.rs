fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|e| panic!("CARGO_MANIFEST_DIR is not set: {e}"));

    // `tauri::generate_context!()` requires the configured `frontendDist` to exist at build time.
    // In unit tests we don't necessarily have the Vite build output, so create a minimal stub.
    let dist_dir = manifest_dir.join("../dist");
    if dist_dir.exists() && !dist_dir.is_dir() {
        panic!(
            "Tauri frontendDist is not a directory: {}",
            dist_dir.display()
        );
    }
    std::fs::create_dir_all(&dist_dir)
        .unwrap_or_else(|e| panic!("Failed to create {}: {e}", dist_dir.display()));

    let index_html = dist_dir.join("index.html");
    if index_html.exists() && !index_html.is_file() {
        panic!("Stub index.html is not a file: {}", index_html.display());
    }
    if !index_html.exists() {
        let html =
            "<!doctype html><html><head><meta charset=\"utf-8\" /></head><body></body></html>";
        std::fs::write(&index_html, html)
            .unwrap_or_else(|e| panic!("Failed to write {}: {e}", index_html.display()));
    }

    tauri_build::build()
}
