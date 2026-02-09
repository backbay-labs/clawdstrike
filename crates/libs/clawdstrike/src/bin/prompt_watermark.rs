use std::io::Read;

use clawdstrike::{
    PromptWatermarker, WatermarkConfig, WatermarkExtractor, WatermarkPayload,
    WatermarkVerifierConfig,
};

fn main() {
    let mut mode = "extract".to_string();
    let mut input_path: Option<String> = None;
    let mut app: Option<String> = None;
    let mut session: Option<String> = None;
    let mut seed_hex: Option<String> = None;
    let mut trusted_keys: Vec<String> = Vec::new();
    let mut allow_unverified = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => mode = args.next().unwrap_or_else(|| "extract".to_string()),
            "--file" => input_path = Some(args.next().unwrap_or_default()),
            "--app" => app = Some(args.next().unwrap_or_default()),
            "--session" => session = Some(args.next().unwrap_or_default()),
            "--seed" => seed_hex = Some(args.next().unwrap_or_default()),
            "--trusted-pubkey" => trusted_keys.push(args.next().unwrap_or_default()),
            "--allow-unverified" => allow_unverified = true,
            "--help" | "-h" => {
                eprintln!(
                    "Usage: prompt_watermark --mode (embed|extract) [--file PATH] [--app APP] [--session SESSION] [--seed HEX] [--trusted-pubkey HEX] [--allow-unverified]\n\nReads from stdin by default."
                );
                std::process::exit(0);
            }
            _ => {}
        }
    }

    let mut input = String::new();
    if let Some(path) = input_path {
        match std::fs::read_to_string(path) {
            Ok(s) => input = s,
            Err(e) => {
                eprintln!("Error: failed to read file: {e}");
                std::process::exit(2);
            }
        }
    } else if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("Error: failed to read stdin: {e}");
        std::process::exit(2);
    }

    match mode.as_str() {
        "embed" => {
            let app = match app {
                Some(v) => v,
                None => {
                    eprintln!("Error: --app is required in embed mode");
                    std::process::exit(2);
                }
            };
            let session = match session {
                Some(v) => v,
                None => {
                    eprintln!("Error: --session is required in embed mode");
                    std::process::exit(2);
                }
            };

            let mut cfg = WatermarkConfig::default();
            cfg.private_key = seed_hex;
            cfg.generate_keypair = cfg.private_key.is_none();

            let watermarker = match PromptWatermarker::new(cfg) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("Error: failed to create watermarker: {e:?}");
                    std::process::exit(2);
                }
            };
            let payload = WatermarkPayload::new(app, session);
            let out = match watermarker.watermark(&input, Some(payload)) {
                Ok(out) => out,
                Err(e) => {
                    eprintln!("Error: failed to watermark input: {e:?}");
                    std::process::exit(2);
                }
            };
            println!("{}", out.watermarked);
        }
        "extract" => {
            let extractor = WatermarkExtractor::new(WatermarkVerifierConfig {
                trusted_public_keys: trusted_keys,
                allow_unverified,
            });
            let r = extractor.extract(&input);
            match serde_json::to_string_pretty(&r) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("Error: failed to encode json: {e}");
                    std::process::exit(2);
                }
            }
        }
        _ => {
            eprintln!("Unknown mode: {mode}");
            std::process::exit(2);
        }
    }
}
