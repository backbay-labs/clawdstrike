#[cfg(target_os = "macos")]
mod collector;
pub mod host;
pub mod status;

#[cfg(target_os = "macos")]
pub use collector::start_status_collector;
pub use host::MacosHostService;

#[cfg(not(target_os = "macos"))]
pub fn start_status_collector<R: tauri::Runtime + 'static>(
    _app: tauri::AppHandle<R>,
    _macos_host: std::sync::Arc<MacosHostService>,
    _shutdown: tokio::sync::broadcast::Receiver<()>,
) {
}
