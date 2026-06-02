#![allow(clippy::needless_pass_by_value)]
//! `hush pkg` subcommands — package management for `.cpkg` archives.

#[cfg(test)]
use clawdstrike::pkg::archive;
#[cfg(test)]
use clawdstrike::pkg::manifest::{parse_pkg_manifest_toml, PkgType};
#[cfg(test)]
use clawdstrike::pkg::merkle::LeafData;
#[cfg(test)]
use clawdstrike::pkg::store::{PackageStore, StoreMetadata};

#[cfg(test)]
use crate::registry_config::{is_file_source, RegistryConfig};
use crate::ExitCode;

pub(super) const PLUGIN_MANIFEST_FILENAME: &str = "clawdstrike.plugin.toml";
const MAX_REGISTRY_DOWNLOAD_BYTES: u64 = 100 * 1024 * 1024;

mod audit_stats;
mod auth;
mod command;
mod dispatch;
mod init;
mod install;
mod list_verify_info;
mod org;
mod pack;
mod publish;
mod scaffold;
mod search;
mod test_cmd;
mod trust;
mod trusted_publishers;
mod util;
mod yank;

use audit_stats::{cmd_pkg_audit, cmd_pkg_stats};
pub use command::{CliPkgType, OrgCommands, PkgCommands, TrustedPublisherCommands};
pub use dispatch::cmd_pkg;
use init::cmd_pkg_init;
use install::cmd_pkg_install;
#[cfg(test)]
use install::{
    create_install_rollback_backup, read_archive_identity, recompute_installed_content_fingerprint,
    requested_identity_matches_install, restore_install_from_backup,
    select_default_registry_version,
};
use list_verify_info::{cmd_pkg_info, cmd_pkg_list, cmd_pkg_verify};
use org::cmd_pkg_org;
use pack::cmd_pkg_pack;
#[cfg(test)]
use pack::validate_pack_contents;
use publish::{cmd_pkg_login, cmd_pkg_publish};
#[cfg(test)]
use scaffold::scaffold_package;
use search::cmd_pkg_search;
use test_cmd::cmd_pkg_test;
#[cfg(test)]
use trust::{
    checkpoint_signature_message, verify_transparency_proof, RegistryAttestation, RegistryProof,
};
use trusted_publishers::cmd_pkg_trusted_publishers;
#[cfg(test)]
use util::{truncate_with_ellipsis, urlencoding_simple};
use yank::cmd_pkg_yank;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
