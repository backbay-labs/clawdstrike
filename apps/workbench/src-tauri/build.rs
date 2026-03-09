fn main() {
    // Create stub dist/index.html so `cargo test` works without vite build
    let dist = std::path::Path::new("../dist");
    if !dist.exists() {
        std::fs::create_dir_all(dist).ok();
        std::fs::write(dist.join("index.html"), "<html><body></body></html>").ok();
    }
    tauri_build::build();
}
