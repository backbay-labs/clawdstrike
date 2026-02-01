//! Basic receipt verification example
//!
//! This example demonstrates how to verify a hushclaw receipt,
//! checking both the Ed25519 signature and Merkle root.

use hush_core::{Receipt, verify_receipt, VerificationResult};
use std::env;
use std::fs;
use std::process;

fn main() {
    // Get receipt path from command line
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <receipt.json>", args[0]);
        process::exit(1);
    }

    let receipt_path = &args[1];

    // Load the receipt
    let receipt_json = match fs::read_to_string(receipt_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Error reading receipt: {}", e);
            process::exit(1);
        }
    };

    // Parse the receipt
    let receipt: Receipt = match serde_json::from_str(&receipt_json) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error parsing receipt: {}", e);
            process::exit(1);
        }
    };

    // Display receipt info
    println!("Receipt Verification");
    println!("====================\n");
    println!("Run ID:     {}", receipt.run_id);
    println!("Started:    {}", receipt.started_at);
    println!("Ended:      {}", receipt.ended_at);
    println!("Events:     {}", receipt.events.len());
    println!("Denials:    {}", receipt.denied_count);
    println!();

    // Verify the receipt
    match verify_receipt(&receipt) {
        VerificationResult::Valid => {
            println!("Signature:  VALID");
            println!("Merkle:     VALID");
            println!();
            println!("Receipt is authentic and unmodified.");
            process::exit(0);
        }
        VerificationResult::InvalidSignature => {
            println!("Signature:  INVALID");
            println!();
            println!("Receipt signature verification failed!");
            process::exit(1);
        }
        VerificationResult::InvalidMerkleRoot => {
            println!("Signature:  VALID");
            println!("Merkle:     INVALID");
            println!();
            println!("Receipt events may have been tampered with!");
            process::exit(1);
        }
        VerificationResult::Error(e) => {
            eprintln!("Verification error: {}", e);
            process::exit(1);
        }
    }
}
