#![no_main]

use std::sync::OnceLock;

use arbitrary::Arbitrary;
use clawdstrike::{HostCall, Monitor, NetworkIrm, Policy};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct NetInput {
    function: String,
    url_like: String,
    host_like: String,
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

fuzz_target!(|input: NetInput| {
    let irm = NetworkIrm::new();
    let policy = Policy::default();

    let function = trim_input(&input.function);
    let url_like = trim_input(&input.url_like);
    let host_like = trim_input(&input.host_like);

    let args = match input.mode % 4 {
        0 => vec![serde_json::json!(url_like)],
        1 => vec![serde_json::json!({"url": url_like})],
        2 => vec![serde_json::json!({"host": host_like, "port": 443})],
        _ => vec![
            serde_json::json!({"fd": 3}),
            serde_json::json!(url_like),
            serde_json::json!({"host": host_like}),
        ],
    };

    let call = HostCall::new(&function, args);
    let _ = runtime().block_on(irm.evaluate(&call, &policy));
});
