//! Top-level `hush pkg` dispatcher: routes a parsed `PkgCommands` to the
//! owning subcommand handler.

use std::io::Write;

use super::*;

pub fn cmd_pkg(command: PkgCommands, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    match command {
        PkgCommands::Init { pkg_type, name } => cmd_pkg_init(&pkg_type, &name, stdout, stderr),
        PkgCommands::Pack { path } => cmd_pkg_pack(path.as_deref(), stdout, stderr),
        PkgCommands::Install {
            source,
            version,
            registry,
            trust_level,
            allow_unverified,
        } => cmd_pkg_install(
            &source,
            version.as_deref(),
            registry.as_deref(),
            trust_level.as_deref(),
            allow_unverified,
            stdout,
            stderr,
        ),
        PkgCommands::List => cmd_pkg_list(stdout, stderr),
        PkgCommands::Verify {
            name,
            version,
            trust_level,
            registry,
        } => cmd_pkg_verify(
            &name,
            &version,
            &trust_level,
            registry.as_deref(),
            stdout,
            stderr,
        ),
        PkgCommands::Info { name, version } => cmd_pkg_info(&name, &version, stdout, stderr),
        PkgCommands::Test { path, filter } => {
            cmd_pkg_test(path.as_deref(), filter.as_deref(), stdout, stderr)
        }
        PkgCommands::Login { registry } => cmd_pkg_login(registry.as_deref(), stdout, stderr),
        PkgCommands::Publish {
            path,
            registry,
            oidc,
        } => cmd_pkg_publish(path.as_deref(), registry.as_deref(), oidc, stdout, stderr),
        PkgCommands::Search {
            query,
            limit,
            page,
            registry,
        } => cmd_pkg_search(&query, limit, page, registry.as_deref(), stdout, stderr),
        PkgCommands::Audit {
            name,
            registry,
            limit,
        } => cmd_pkg_audit(&name, registry.as_deref(), limit, stdout, stderr),
        PkgCommands::Yank {
            name,
            version,
            registry,
        } => cmd_pkg_yank(&name, &version, registry.as_deref(), stdout, stderr),
        PkgCommands::Stats { name, registry } => {
            cmd_pkg_stats(&name, registry.as_deref(), stdout, stderr)
        }
        PkgCommands::TrustedPublishers { command } => {
            cmd_pkg_trusted_publishers(command, stdout, stderr)
        }
        PkgCommands::Org { command } => cmd_pkg_org(command, stdout, stderr),
        PkgCommands::Mirror { command } => crate::mirror::cmd_mirror(command, stdout, stderr),
    }
}
