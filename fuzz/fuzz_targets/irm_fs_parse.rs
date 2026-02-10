#![no_main]

use std::sync::OnceLock;

use arbitrary::Arbitrary;
use clawdstrike::{FilesystemIrm, HostCall, Monitor, Policy};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FsInput {
    function: String,
    path_a: String,
    path_b: String,
    mode: u8,
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

fn trim_input(s: &str) -> String {
    s.chars().take(256).collect()
}

fuzz_target!(|input: FsInput| {
    let irm = FilesystemIrm::new();
    let policy = Policy::default();

    let function = trim_input(&input.function);
    let path_a = trim_input(&input.path_a);
    let path_b = trim_input(&input.path_b);

    let args = match input.mode % 4 {
        0 => vec![serde_json::json!(path_a)],
        1 => vec![
            serde_json::json!({"fd": 3}),
            serde_json::json!({"path": path_a}),
        ],
        2 => vec![
            serde_json::json!({"fd": 9}),
            serde_json::json!({"target_path": path_a}),
            serde_json::json!(path_b),
        ],
        _ => vec![
            serde_json::json!({"file_path": path_a}),
            serde_json::json!({"context": "fuzz"}),
            serde_json::json!({"path": path_b}),
        ],
    };

    let call = HostCall::new(&function, args);
    let _ = runtime().block_on(irm.evaluate(&call, &policy));
});
