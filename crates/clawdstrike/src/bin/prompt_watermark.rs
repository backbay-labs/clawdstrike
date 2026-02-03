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

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => mode = args.next().unwrap_or_else(|| "extract".to_string()),
            "--file" => input_path = Some(args.next().unwrap_or_default()),
            "--app" => app = Some(args.next().unwrap_or_default()),
            "--session" => session = Some(args.next().unwrap_or_default()),
            "--seed" => seed_hex = Some(args.next().unwrap_or_default()),
            "--trusted-pubkey" => trusted_keys.push(args.next().unwrap_or_default()),
            "--help" | "-h" => {
                eprintln!(
                    "Usage: prompt_watermark --mode (embed|extract) [--file PATH] [--app APP] [--session SESSION] [--seed HEX] [--trusted-pubkey HEX]\n\nReads from stdin by default."
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

    match mode.as_str() {
        "embed" => {
            let app = app.expect("--app required in embed mode");
            let session = session.expect("--session required in embed mode");

            let mut cfg = WatermarkConfig::default();
            cfg.private_key = seed_hex;
            cfg.generate_keypair = cfg.private_key.is_none();

            let watermarker = PromptWatermarker::new(cfg).expect("watermarker");
            let payload = WatermarkPayload::new(app, session);
            let out = watermarker
                .watermark(&input, Some(payload))
                .expect("watermark");
            println!("{}", out.watermarked);
        }
        "extract" => {
            let extractor = WatermarkExtractor::new(WatermarkVerifierConfig {
                trusted_public_keys: trusted_keys,
                allow_unverified: false,
            });
            let r = extractor.extract(&input);
            println!("{}", serde_json::to_string_pretty(&r).expect("json"));
        }
        _ => {
            eprintln!("Unknown mode: {mode}");
            std::process::exit(2);
        }
    }
}
