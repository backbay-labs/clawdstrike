use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

use super::manifest::{
    parse_plugin_manifest_toml, PluginManifest, PluginResourceLimits, PluginSandbox,
    PluginTrustLevel,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginExecutionMode {
    Native,
    Wasm,
}

#[derive(Clone, Debug)]
pub struct PluginInspectResult {
    pub root: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest: PluginManifest,
    pub execution_mode: PluginExecutionMode,
}

#[derive(Clone, Debug)]
pub struct PluginLoadPlan {
    pub inspect: PluginInspectResult,
    pub guard_ids: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PluginLoaderOptions {
    pub from_dir: PathBuf,
    pub trusted_only: bool,
    pub allow_wasm_sandbox: bool,
    pub current_clawdstrike_version: String,
    pub max_resources: Option<PluginResourceLimits>,
}

impl Default for PluginLoaderOptions {
    fn default() -> Self {
        Self {
            from_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            trusted_only: true,
            allow_wasm_sandbox: false,
            current_clawdstrike_version: "0.1.0".to_string(),
            max_resources: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PluginLoader {
    options: PluginLoaderOptions,
}

impl PluginLoader {
    pub fn new(options: PluginLoaderOptions) -> Self {
        Self { options }
    }

    pub fn inspect(&self, plugin_ref: &str) -> Result<PluginInspectResult> {
        let root = resolve_plugin_root(plugin_ref, &self.options.from_dir)?;
        let manifest_path = root.join("clawdstrike.plugin.toml");
        let content = std::fs::read_to_string(&manifest_path).map_err(|e| {
            Error::ConfigError(format!(
                "failed to read plugin manifest {}: {}",
                manifest_path.display(),
                e
            ))
        })?;

        let manifest = parse_plugin_manifest_toml(&content)?;
        self.validate_trust_policy(&manifest)?;
        self.validate_compatibility(&manifest)?;
        self.validate_resource_limits(&manifest)?;

        Ok(PluginInspectResult {
            root,
            manifest_path,
            execution_mode: to_execution_mode(manifest.trust.sandbox),
            manifest,
        })
    }

    pub fn plan_load(&self, plugin_ref: &str) -> Result<PluginLoadPlan> {
        let inspect = self.inspect(plugin_ref)?;

        if inspect.execution_mode == PluginExecutionMode::Wasm {
            return Err(Error::ConfigError(format!(
                "WASM plugin loading scaffold is present but runtime is not implemented yet: {}",
                inspect.manifest.plugin.name
            )));
        }

        let guard_ids = inspect
            .manifest
            .guards
            .iter()
            .map(|g| g.name.clone())
            .collect::<Vec<_>>();

        Ok(PluginLoadPlan { inspect, guard_ids })
    }

    fn validate_trust_policy(&self, manifest: &PluginManifest) -> Result<()> {
        if self.options.trusted_only && manifest.trust.level != PluginTrustLevel::Trusted {
            return Err(Error::ConfigError(format!(
                "refusing to load untrusted plugin: {}",
                manifest.plugin.name
            )));
        }

        if manifest.trust.sandbox == PluginSandbox::Wasm && !self.options.allow_wasm_sandbox {
            return Err(Error::ConfigError(format!(
                "refusing to load wasm-sandboxed plugin until WASM sandbox is enabled: {}",
                manifest.plugin.name
            )));
        }

        Ok(())
    }

    fn validate_compatibility(&self, manifest: &PluginManifest) -> Result<()> {
        let Some(compat) = &manifest.clawdstrike else {
            return Ok(());
        };

        let Some(current) = parse_semver(&self.options.current_clawdstrike_version) else {
            return Ok(());
        };

        if let Some(min) = compat.min_version.as_deref().and_then(parse_semver) {
            if compare_semver(current, min).is_lt() {
                return Err(Error::ConfigError(format!(
                    "plugin {} requires clawdstrike >= {} (current {})",
                    manifest.plugin.name,
                    compat.min_version.as_deref().unwrap_or(""),
                    self.options.current_clawdstrike_version
                )));
            }
        }

        if let Some(max) = compat.max_version.as_deref() {
            if !satisfies_max_version(current, max) {
                return Err(Error::ConfigError(format!(
                    "plugin {} requires clawdstrike <= {} (current {})",
                    manifest.plugin.name, max, self.options.current_clawdstrike_version
                )));
            }
        }

        Ok(())
    }

    fn validate_resource_limits(&self, manifest: &PluginManifest) -> Result<()> {
        let Some(max) = &self.options.max_resources else {
            return Ok(());
        };

        if manifest.resources.max_memory_mb > max.max_memory_mb {
            return Err(Error::ConfigError(format!(
                "plugin {} max_memory_mb={} exceeds loader limit {}",
                manifest.plugin.name, manifest.resources.max_memory_mb, max.max_memory_mb
            )));
        }
        if manifest.resources.max_cpu_ms > max.max_cpu_ms {
            return Err(Error::ConfigError(format!(
                "plugin {} max_cpu_ms={} exceeds loader limit {}",
                manifest.plugin.name, manifest.resources.max_cpu_ms, max.max_cpu_ms
            )));
        }
        if manifest.resources.max_timeout_ms > max.max_timeout_ms {
            return Err(Error::ConfigError(format!(
                "plugin {} max_timeout_ms={} exceeds loader limit {}",
                manifest.plugin.name, manifest.resources.max_timeout_ms, max.max_timeout_ms
            )));
        }

        Ok(())
    }
}

pub fn resolve_plugin_root(plugin_ref: &str, from_dir: &Path) -> Result<PathBuf> {
    let raw = PathBuf::from(plugin_ref);
    let candidate = if raw.is_absolute() {
        raw
    } else {
        from_dir.join(raw)
    };

    if candidate.exists() {
        let meta = std::fs::metadata(&candidate).map_err(|e| {
            Error::ConfigError(format!(
                "failed to stat plugin reference {}: {}",
                candidate.display(),
                e
            ))
        })?;
        return Ok(if meta.is_dir() {
            candidate
        } else {
            candidate
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
        });
    }

    Err(Error::ConfigError(format!(
        "plugin reference not found (only local paths are supported in scaffold mode): {}",
        plugin_ref
    )))
}

fn to_execution_mode(sandbox: PluginSandbox) -> PluginExecutionMode {
    match sandbox {
        PluginSandbox::Native => PluginExecutionMode::Native,
        PluginSandbox::Wasm => PluginExecutionMode::Wasm,
    }
}

type Semver = [u32; 3];

fn parse_semver(value: &str) -> Option<Semver> {
    let mut parts = value.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let patch = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some([major, minor, patch])
}

fn compare_semver(a: Semver, b: Semver) -> std::cmp::Ordering {
    a.cmp(&b)
}

fn satisfies_max_version(current: Semver, max_version: &str) -> bool {
    if let Some(max) = parse_semver(max_version) {
        return compare_semver(current, max).is_le();
    }

    if let Some(major) = parse_major_wildcard(max_version) {
        return current[0] == major;
    }

    if let Some((major, minor)) = parse_minor_wildcard(max_version) {
        return current[0] == major && current[1] == minor;
    }

    true
}

fn parse_major_wildcard(value: &str) -> Option<u32> {
    let mut parts = value.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let wildcard = parts.next()?;
    if wildcard != "x" || parts.next().is_some() {
        return None;
    }
    Some(major)
}

fn parse_minor_wildcard(value: &str) -> Option<(u32, u32)> {
    let mut parts = value.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let wildcard = parts.next()?;
    if wildcard != "x" || parts.next().is_some() {
        return None;
    }
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn write_manifest(dir: &TempDir, content: &str) {
        std::fs::write(dir.path().join("clawdstrike.plugin.toml"), content)
            .expect("write manifest");
    }

    #[test]
    fn inspect_trusted_native_manifest() {
        let dir = TempDir::new().expect("tempdir");
        write_manifest(
            &dir,
            r#"
[plugin]
version = "1.0.0"
name = "acme-plugin"

[[guards]]
name = "acme.guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        );

        let loader = PluginLoader::new(PluginLoaderOptions {
            from_dir: dir.path().to_path_buf(),
            ..PluginLoaderOptions::default()
        });

        let inspected = loader.inspect(".").expect("inspect");
        assert_eq!(inspected.execution_mode, PluginExecutionMode::Native);
        assert_eq!(inspected.manifest.plugin.name, "acme-plugin");
    }

    #[test]
    fn trusted_only_loader_rejects_untrusted() {
        let dir = TempDir::new().expect("tempdir");
        write_manifest(
            &dir,
            r#"
[plugin]
version = "1.0.0"
name = "acme-plugin"

[[guards]]
name = "acme.guard"

[trust]
level = "untrusted"
sandbox = "wasm"
"#,
        );

        let loader = PluginLoader::new(PluginLoaderOptions {
            from_dir: dir.path().to_path_buf(),
            ..PluginLoaderOptions::default()
        });

        let err = loader.inspect(".").expect_err("should reject untrusted");
        assert!(err
            .to_string()
            .contains("refusing to load untrusted plugin"));
    }

    #[test]
    fn loader_checks_min_version_compatibility() {
        let dir = TempDir::new().expect("tempdir");
        write_manifest(
            &dir,
            r#"
[plugin]
version = "1.0.0"
name = "acme-plugin"

[clawdstrike]
min_version = "9.9.9"

[[guards]]
name = "acme.guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        );

        let loader = PluginLoader::new(PluginLoaderOptions {
            from_dir: dir.path().to_path_buf(),
            current_clawdstrike_version: "0.1.0".to_string(),
            ..PluginLoaderOptions::default()
        });

        let err = loader
            .inspect(".")
            .expect_err("should reject incompatible version");
        assert!(err.to_string().contains("requires clawdstrike >="));
    }
}
