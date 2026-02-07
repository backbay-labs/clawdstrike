use anyhow::Result;
use colored::Colorize;

pub async fn run(nats_url: &str, is_json: bool, verbose: bool) -> Result<()> {
    let client = spine::nats_transport::connect(nats_url).await?;
    let js = spine::nats_transport::jetstream(client.clone());

    let server_info = client.server_info();

    if is_json {
        let info = serde_json::json!({
            "connected": true,
            "nats_url": nats_url,
            "server_id": server_info.server_id,
            "server_name": server_info.server_name,
            "version": server_info.version,
            "max_payload": server_info.max_payload,
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }

    println!("{}", "NATS Connection Status".bold().green());
    println!("  {} {}", "URL:".bold(), nats_url);
    println!("  {} {}", "Server ID:".bold(), server_info.server_id);
    println!("  {} {}", "Server Name:".bold(), server_info.server_name);
    println!("  {} {}", "Version:".bold(), server_info.version);
    println!("  {} {}", "Max Payload:".bold(), server_info.max_payload);

    if verbose {
        println!("\n{}", "JetStream Streams".bold().green());

        let stream_names = ["CLAWDSTRIKE_ENVELOPES", "CLAWDSTRIKE_CHECKPOINTS"];
        for name in &stream_names {
            match js.get_stream(name).await {
                Ok(mut stream) => {
                    let info = stream.info().await;
                    match info {
                        Ok(info) => {
                            println!("  {} {}", "Stream:".bold(), name);
                            println!("    Subjects: {:?}", info.config.subjects);
                            println!("    Messages: {}", info.state.messages);
                            println!("    Bytes: {}", info.state.bytes);
                            println!(
                                "    First seq: {}",
                                info.state.first_sequence
                            );
                            println!(
                                "    Last seq: {}",
                                info.state.last_sequence
                            );
                            println!();
                        }
                        Err(e) => {
                            println!("  {} {} ({})", "Stream:".bold(), name, e.to_string().red());
                        }
                    }
                }
                Err(_) => {
                    println!(
                        "  {} {} {}",
                        "Stream:".bold(),
                        name,
                        "(not found)".yellow()
                    );
                }
            }
        }
    }

    Ok(())
}
