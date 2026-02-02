//! Basic receipt verification example
//!
//! This example demonstrates how to verify a signed clawdstrike receipt.

use std::env;
use std::fs;
use std::process;

fn main() {
    // Get receipt path from command line
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <signed-receipt.json> <pubkey.hex>", args[0]);
        process::exit(1);
    }

    let receipt_path = &args[1];
    let pubkey_path = &args[2];

    // Load the receipt
    let receipt_json = match fs::read_to_string(receipt_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Error reading receipt: {}", e);
            process::exit(1);
        }
    };

    let pubkey_hex = match fs::read_to_string(pubkey_path) {
        Ok(content) => content.trim().to_string(),
        Err(e) => {
            eprintln!("Error reading public key: {}", e);
            process::exit(1);
        }
    };

    let public_key = match hush_core::PublicKey::from_hex(&pubkey_hex) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error parsing public key: {}", e);
            process::exit(1);
        }
    };

    let signed: hush_core::SignedReceipt = match serde_json::from_str(&receipt_json) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error parsing signed receipt: {}", e);
            process::exit(1);
        }
    };

    let keys = hush_core::receipt::PublicKeySet::new(public_key);
    let result = signed.verify(&keys);

    // Display receipt info
    println!("Receipt Verification");
    println!("====================\n");
    println!("Version:    {}", signed.receipt.version);
    println!("Timestamp:  {}", signed.receipt.timestamp);
    println!("Content:    {}", signed.receipt.content_hash);
    println!(
        "Verdict:    {}",
        if signed.receipt.verdict.passed {
            "PASS"
        } else {
            "FAIL"
        }
    );
    println!();

    if result.valid {
        println!("Signature:  VALID");
        println!();
        println!("Signed receipt verified.");
        process::exit(0);
    }

    println!("Signature:  INVALID");
    for err in result.errors {
        println!("  - {}", err);
    }
    process::exit(1);
}
