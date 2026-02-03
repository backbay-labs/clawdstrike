use std::io::{Read as _, Write};

use crate::{ExitCode, RegoCommands};

pub fn cmd_policy_rego(command: RegoCommands, _stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    match command {
        RegoCommands::Compile { file } => {
            let _ = writeln!(
                stderr,
                "Rego/OPA integration is not implemented in this build (requested: compile {}).",
                file
            );
            ExitCode::ConfigError
        }
        RegoCommands::Eval { file, input } => {
            if input == "-" {
                let mut buf = String::new();
                let _ = std::io::stdin().read_to_string(&mut buf);
            }

            let _ = writeln!(
                stderr,
                "Rego/OPA integration is not implemented in this build (requested: eval {} with input {}).",
                file, input
            );
            ExitCode::ConfigError
        }
    }
}

