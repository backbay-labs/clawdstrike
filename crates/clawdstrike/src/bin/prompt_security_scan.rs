use std::io::Read;

use clawdstrike::{detect_prompt_injection_with_limit, JailbreakDetector, OutputSanitizer};

fn main() {
    let mut max_scan_bytes: usize = 200_000;
    let mut input_path: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--max-scan-bytes" => {
                let v = args.next().unwrap_or_default();
                max_scan_bytes = v.parse().unwrap_or(max_scan_bytes);
            }
            "--file" => {
                input_path = Some(args.next().unwrap_or_default());
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: prompt_security_scan [--file PATH] [--max-scan-bytes N]\n\nReads from stdin by default."
                );
                std::process::exit(0);
            }
            _ => {}
        }
    }

    let mut input = String::new();
    if let Some(path) = input_path {
        input = std::fs::read_to_string(path).expect("failed to read file");
    } else {
        std::io::stdin()
            .read_to_string(&mut input)
            .expect("failed to read stdin");
    }

    let prompt_injection = detect_prompt_injection_with_limit(&input, max_scan_bytes);
    let jailbreak = JailbreakDetector::new().detect_sync(&input, None);
    let sanitized = OutputSanitizer::new().sanitize_sync(&input);

    let out = serde_json::json!({
        "prompt_injection": prompt_injection,
        "jailbreak": jailbreak,
        "sanitized": sanitized,
    });

    println!("{}", serde_json::to_string_pretty(&out).expect("json"));
}
