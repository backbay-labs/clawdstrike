//! Example demonstrating how to read system-wide file descriptor limits.
//!
//! This example shows the difference between:
//! - System-wide limits from /proc/sys/fs/
//! - Per-process limits from getrlimit()
//!
//! Run with: cargo run --example sys_limits

#[cfg(any(target_os = "linux", target_os = "android"))]
fn main() {
    use rlimit::{Resource, SysLimits};

    println!("=== System-wide File Descriptor Limits ===\n");

    // Read system-wide limits
    match SysLimits::read() {
        Ok(limits) => {
            if let Some(file_max) = limits.file_max {
                println!("System file-max:       {}", file_max);
                println!("  (Maximum number of file descriptors system-wide)");
            }

            if let Some(file_nr) = &limits.file_nr {
                println!("\nCurrent file descriptor usage:");
                println!("  Allocated:           {}", file_nr.allocated);
                println!("  Free:                {}", file_nr.free);
                println!("  Maximum:             {}", file_nr.maximum);

                let usage_percent = if file_nr.maximum > 0 {
                    (file_nr.allocated as f64 / file_nr.maximum as f64) * 100.0
                } else {
                    0.0
                };
                println!("  Usage:               {:.2}%", usage_percent);
            }

            if let Some(nr_open) = limits.nr_open {
                println!("\nPer-process nr_open:   {}", nr_open);
                println!("  (Maximum NOFILE limit that can be set per-process)");
            }
        }
        Err(e) => {
            eprintln!("Failed to read system limits: {}", e);
            return;
        }
    }

    println!("\n=== Per-process NOFILE Limit ===\n");

    // Compare with per-process NOFILE limit
    match Resource::NOFILE.get() {
        Ok((soft, hard)) => {
            println!("NOFILE soft limit:     {}", soft);
            println!("NOFILE hard limit:     {}", hard);
            println!("  (Limits for this process only)");
        }
        Err(e) => {
            eprintln!("Failed to get NOFILE limit: {}", e);
        }
    }

    println!("\n=== Key Differences ===\n");
    println!("• file-max: System-wide limit on total file descriptors");
    println!("• nr_open:  Maximum value for per-process NOFILE limit");
    println!("• NOFILE:   Actual limit for this specific process");
    println!();
    println!("Hierarchy: file-max >= sum(all process NOFILE) and NOFILE <= nr_open");
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn main() {
    println!("This example only works on Linux and Android systems.");
    println!("System-wide limits are not available on this platform.");
}
