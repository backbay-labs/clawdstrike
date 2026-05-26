//! Package-manager command classification (npm/pnpm/yarn/pip/cargo/etc).

use super::shell_tokens::{executable_name, first_non_option_arg_index};

pub(super) struct PackageCommand {
    pub(super) manager: &'static str,
    pub(super) image: String,
    pub(super) args: Vec<String>,
}

pub(super) fn package_command(command: &[String]) -> Option<PackageCommand> {
    let image = command.first()?.clone();
    let executable = executable_name(&image);
    if python_module_is_pip(command) {
        return Some(PackageCommand {
            manager: "pip",
            image,
            args: command.iter().skip(3).cloned().collect(),
        });
    }
    let manager = match executable.as_str() {
        "npm" => "npm",
        "pnpm" => "pnpm",
        "yarn" => "yarn",
        "pip" | "pip3" => "pip",
        "cargo" => "cargo",
        "brew" => "brew",
        "go" => "go",
        "gem" => "gem",
        _ => return None,
    };
    Some(PackageCommand {
        manager,
        image,
        args: command.iter().skip(1).cloned().collect(),
    })
}

fn python_module_is_pip(command: &[String]) -> bool {
    let Some(executable) = command.first().map(|value| executable_name(value)) else {
        return false;
    };
    matches!(
        executable.as_str(),
        "python" | "python3" | "python2" | "python.exe" | "python3.exe"
    ) && command.get(1).is_some_and(|arg| arg == "-m")
        && command
            .get(2)
            .map(|arg| executable_name(arg) == "pip")
            .unwrap_or(false)
}

pub(super) fn package_script_phase_and_package(
    manager: &str,
    args: &[String],
) -> Option<(String, Option<String>)> {
    let command_index = first_non_option_arg_index(args)?;
    let command = args.get(command_index)?.to_ascii_lowercase();
    let after_command = &args[command_index + 1..];
    let phase = match manager {
        "npm" | "pnpm" => match command.as_str() {
            "install" | "i" | "ci" | "add" | "rebuild" => "install".to_string(),
            "run" | "run-script" | "exec" | "dlx" => {
                package_script_name(after_command).unwrap_or_else(|| command.clone())
            }
            _ if package_lifecycle_phase(&command) => command.clone(),
            _ => return None,
        },
        "yarn" => match command.as_str() {
            "install" | "add" | "upgrade" => "install".to_string(),
            "run" => package_script_name(after_command).unwrap_or_else(|| "run".to_string()),
            _ if package_lifecycle_phase(&command) => command.clone(),
            _ => return None,
        },
        "pip" => match command.as_str() {
            "install" => "install".to_string(),
            "wheel" => "build".to_string(),
            _ => return None,
        },
        "cargo" => match command.as_str() {
            "install" | "build" | "run" | "test" => command.clone(),
            _ => return None,
        },
        "brew" => match command.as_str() {
            "install" | "reinstall" | "upgrade" | "bundle" => "install".to_string(),
            _ => return None,
        },
        "go" => match command.as_str() {
            "install" | "get" => "install".to_string(),
            "run" | "build" | "test" => command.clone(),
            _ => return None,
        },
        "gem" => match command.as_str() {
            "install" | "build" => command.clone(),
            _ => return None,
        },
        _ => return None,
    };
    let package = package_name_from_args(after_command);
    Some((phase, package))
}

fn package_script_name(args: &[String]) -> Option<String> {
    args.iter()
        .find(|arg| !arg.starts_with('-') && !arg.contains('='))
        .map(ToString::to_string)
}

fn package_lifecycle_phase(value: &str) -> bool {
    [
        "preinstall",
        "install",
        "postinstall",
        "prepare",
        "build",
        "build.rs",
        "setup.py",
        "test",
    ]
    .iter()
    .any(|phase| value.contains(phase))
}

fn package_name_from_args(args: &[String]) -> Option<String> {
    args.iter()
        .find(|arg| {
            let value = arg.as_str();
            !value.starts_with('-')
                && !value.contains('=')
                && value != "."
                && value != "--"
                && !package_lifecycle_phase(&value.to_ascii_lowercase())
        })
        .map(ToString::to_string)
}

pub(super) fn package_registry_manager(command: &[String]) -> Option<&'static str> {
    match executable_name(command.first()?).as_str() {
        "npm" => Some("npm"),
        "pnpm" => Some("pnpm"),
        "yarn" => Some("yarn"),
        _ => None,
    }
}

pub(super) fn package_registry_token_command_is_sensitive(
    command_name: &str,
    args: &[String],
) -> bool {
    let joined = args.join(" ").to_ascii_lowercase();
    match command_name {
        "token" => args
            .first()
            .map(|arg| {
                matches!(
                    arg.to_ascii_lowercase().as_str(),
                    "list" | "create" | "revoke" | "delete"
                )
            })
            .unwrap_or(false),
        "config" => {
            args.first()
                .map(|arg| matches!(arg.to_ascii_lowercase().as_str(), "get" | "set" | "delete"))
                .unwrap_or(false)
                && package_registry_auth_config_reference(&joined)
        }
        _ => false,
    }
}

fn package_registry_auth_config_reference(value: &str) -> bool {
    value.contains("_authtoken")
        || value.contains("node_auth_token")
        || value.contains("npm_token")
        || value.contains("npm_config_")
}
