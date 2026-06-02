//! Clap argument-type definitions for the `hush pkg` command family.

use std::path::PathBuf;

use clap::Subcommand;

use clawdstrike::pkg::manifest::PkgType;

/// Map `PkgType` to clap `ValueEnum` without adding clap to the library crate.
#[derive(Clone, Debug)]
pub enum CliPkgType {
    Guard,
    PolicyPack,
    Adapter,
    Engine,
    Template,
    Bundle,
}

impl clap::ValueEnum for CliPkgType {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self::Guard,
            Self::PolicyPack,
            Self::Adapter,
            Self::Engine,
            Self::Template,
            Self::Bundle,
        ]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Guard => clap::builder::PossibleValue::new("guard"),
            Self::PolicyPack => clap::builder::PossibleValue::new("policy-pack"),
            Self::Adapter => clap::builder::PossibleValue::new("adapter"),
            Self::Engine => clap::builder::PossibleValue::new("engine"),
            Self::Template => clap::builder::PossibleValue::new("template"),
            Self::Bundle => clap::builder::PossibleValue::new("bundle"),
        })
    }
}

impl CliPkgType {
    pub(super) fn to_pkg_type(&self) -> PkgType {
        match self {
            Self::Guard => PkgType::Guard,
            Self::PolicyPack => PkgType::PolicyPack,
            Self::Adapter => PkgType::Adapter,
            Self::Engine => PkgType::Engine,
            Self::Template => PkgType::Template,
            Self::Bundle => PkgType::Bundle,
        }
    }

    pub(super) fn label(&self) -> &'static str {
        match self {
            Self::Guard => "guard",
            Self::PolicyPack => "policy-pack",
            Self::Adapter => "adapter",
            Self::Engine => "engine",
            Self::Template => "template",
            Self::Bundle => "bundle",
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum PkgCommands {
    /// Initialize a new package in the current directory
    Init {
        /// Package type
        #[arg(long, value_enum)]
        pkg_type: CliPkgType,
        /// Package name (e.g., @acme/my-guard)
        #[arg(long)]
        name: String,
    },
    /// Build a .cpkg archive from the current directory (or specified path)
    Pack {
        /// Path to package directory (defaults to current dir)
        path: Option<PathBuf>,
    },
    /// Install a package from a local .cpkg file or the registry
    Install {
        /// Path to .cpkg file, or package name for registry install
        source: String,
        /// Version to install (for registry packages)
        #[arg(long)]
        version: Option<String>,
        /// Registry URL override
        #[arg(long)]
        registry: Option<String>,
        /// Minimum trust level for registry installs (unverified, signed, verified, certified)
        #[arg(long, default_value = "signed")]
        trust_level: Option<String>,
        /// Allow installing unverified packages (dangerous)
        #[arg(long)]
        allow_unverified: bool,
    },
    /// List installed packages
    List,
    /// Verify an installed package's integrity and trust level
    Verify {
        /// Package name (e.g., @scope/name)
        name: String,
        /// Specific version to verify (default: installed version)
        #[arg(long)]
        version: String,
        /// Minimum required trust level (unverified, signed, verified, certified)
        #[arg(long, default_value = "signed")]
        trust_level: String,
        /// Registry URL (for fetching attestations and proofs)
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show details about an installed package
    Info {
        /// Package name
        name: String,
        /// Package version
        #[arg(long)]
        version: String,
    },
    /// Run guard test fixtures against a WASM guard plugin
    Test {
        /// Path to the guard package directory (defaults to current dir)
        path: Option<PathBuf>,
        /// Filter: only run fixtures whose name contains this string
        #[arg(long)]
        filter: Option<String>,
    },
    /// Authenticate with a package registry
    Login {
        /// Registry URL override
        #[arg(long)]
        registry: Option<String>,
    },
    /// Publish a package to the registry
    Publish {
        /// Path to package directory (defaults to current dir)
        path: Option<PathBuf>,
        /// Registry URL override
        #[arg(long)]
        registry: Option<String>,
        /// Use OIDC token for authentication (for CI/CD environments)
        #[arg(long)]
        oidc: bool,
    },
    /// Search for packages in the registry
    Search {
        /// Search query
        query: String,
        /// Maximum number of results
        #[arg(long, default_value = "20")]
        limit: usize,
        /// Page number (0-indexed)
        #[arg(long, default_value = "0")]
        page: usize,
        /// Registry URL override
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show package publish history
    Audit {
        /// Package name
        name: String,
        /// Registry URL
        #[arg(long)]
        registry: Option<String>,
        /// Limit results
        #[arg(long, default_value = "20")]
        limit: u32,
    },
    /// Yank (soft-delete) a package version from the registry
    Yank {
        /// Package name (e.g., @scope/name)
        name: String,
        /// Version to yank
        #[arg(long)]
        version: String,
        /// Registry URL override
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show package download and usage statistics
    Stats {
        /// Package name
        name: String,
        /// Registry URL
        #[arg(long)]
        registry: Option<String>,
    },
    /// Organization management
    Org {
        #[command(subcommand)]
        command: OrgCommands,
    },
    /// Manage trusted publishers for OIDC-based CI/CD publishing
    TrustedPublishers {
        #[command(subcommand)]
        command: TrustedPublisherCommands,
    },
    /// Mirror packages from an upstream registry for air-gapped or local use
    Mirror {
        #[command(subcommand)]
        command: crate::mirror::MirrorCommands,
    },
}

#[derive(Debug, Subcommand)]
pub enum TrustedPublisherCommands {
    /// Add a trusted publisher for a package
    Add {
        /// Package name (e.g., @acme/my-guard)
        package: String,
        /// OIDC provider: github or gitlab
        #[arg(long)]
        provider: String,
        /// Repository in owner/repo format
        #[arg(long)]
        repo: String,
        /// Optional workflow filter (e.g., release.yml)
        #[arg(long)]
        workflow: Option<String>,
        /// Optional environment filter (e.g., production)
        #[arg(long)]
        environment: Option<String>,
        /// Registry URL override
        #[arg(long)]
        registry: Option<String>,
    },
    /// List trusted publishers for a package
    List {
        /// Package name
        package: String,
        /// Registry URL override
        #[arg(long)]
        registry: Option<String>,
    },
    /// Remove a trusted publisher by ID
    Remove {
        /// Package name
        package: String,
        /// Trusted publisher ID
        #[arg(long)]
        id: i64,
        /// Registry URL override
        #[arg(long)]
        registry: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum OrgCommands {
    /// Create a new organization
    Create {
        /// Organization name (used as @scope)
        name: String,
        /// Display name
        #[arg(long)]
        display_name: Option<String>,
        /// Registry URL
        #[arg(long)]
        registry: Option<String>,
    },
    /// List organization members
    Members {
        /// Organization name
        name: String,
        /// Registry URL
        #[arg(long)]
        registry: Option<String>,
    },
    /// Invite a member to the organization
    Invite {
        /// Organization name
        org: String,
        /// Member's public key (hex)
        publisher_key: String,
        /// Role: owner, maintainer, member
        #[arg(long, default_value = "member")]
        role: String,
        /// Registry URL
        #[arg(long)]
        registry: Option<String>,
    },
    /// Remove a member from the organization
    Remove {
        /// Organization name
        org: String,
        /// Member's public key (hex)
        publisher_key: String,
        /// Registry URL
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show organization info
    Info {
        /// Organization name
        name: String,
        /// Registry URL
        #[arg(long)]
        registry: Option<String>,
    },
}
