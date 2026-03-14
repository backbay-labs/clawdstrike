//! SQLite database layer for package metadata and search.

use std::io;
use std::path::Path;

use rusqlite::{params, Connection, Error as SqliteError, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::error::RegistryError;

/// A row from the `packages` table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackageRow {
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub total_downloads: u64,
}

/// A row from the `versions` table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionRow {
    pub name: String,
    pub version: String,
    pub pkg_type: String,
    pub checksum: String,
    pub manifest_toml: String,
    pub publisher_key: String,
    pub publisher_sig: String,
    pub registry_sig: Option<String>,
    pub dependencies_json: String,
    pub yanked: bool,
    pub published_at: String,
    /// SHA-256 hash of the publish attestation (if created).
    #[serde(default)]
    pub attestation_hash: Option<String>,
    /// Key ID of the registry key that counter-signed this version.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Transparency log leaf index.
    #[serde(default)]
    pub leaf_index: Option<u64>,
    /// Download count for this version.
    #[serde(default)]
    pub download_count: u64,
}

/// A row from the `api_keys` table.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ApiKeyRow {
    pub key_hash: String,
    pub publisher_key: Option<String>,
    pub created_at: String,
}

/// A row from the `trusted_publishers` table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustedPublisher {
    pub id: i64,
    pub package_name: String,
    pub provider: String,
    pub repository: String,
    pub workflow: Option<String>,
    pub environment: Option<String>,
    pub created_at: String,
    pub created_by: String,
}

/// A row from the `organizations` table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Organization {
    pub id: i64,
    pub name: String,
    pub display_name: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub verified: bool,
}

/// A row from the `org_members` table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgMember {
    pub publisher_key: String,
    pub role: String,
    pub joined_at: String,
}

/// Search result item.
#[derive(Clone, Debug, Serialize)]
pub struct SearchResult {
    pub name: String,
    pub description: Option<String>,
    pub latest_version: Option<String>,
}

/// Aggregate download statistics for a package.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackageStats {
    pub name: String,
    pub total_downloads: u64,
    pub versions: Vec<VersionStats>,
    pub first_published: Option<String>,
    pub latest_version: Option<String>,
}

/// Per-version download statistics.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionStats {
    pub version: String,
    pub downloads: u64,
    pub published_at: String,
}

/// A popular package entry.
#[derive(Clone, Debug, Serialize)]
pub struct PopularPackage {
    pub name: String,
    pub description: Option<String>,
    pub total_downloads: u64,
    pub latest_version: Option<String>,
}

/// Database handle wrapping a SQLite connection.
pub struct RegistryDb {
    conn: Connection,
}

/// Build a conservative FTS5 MATCH query from user text.
///
/// The resulting expression contains only quoted literal tokens joined with
/// `AND`, preventing user-supplied FTS operators from changing query semantics.
fn build_fts_literal_query(query: &str) -> Option<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();

    for ch in query.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '/' | '@' | ':' | '%') {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }

    if tokens.is_empty() {
        return None;
    }

    Some(
        tokens
            .into_iter()
            .map(|token| format!("\"{}\"", token.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" AND "),
    )
}

/// Escape a user string for literal matching inside SQLite `LIKE` patterns.
fn escape_sqlite_like_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '%' | '_' | '\\' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn is_duplicate_column_error(err: &SqliteError) -> bool {
    match err {
        SqliteError::SqliteFailure(_, Some(msg)) => {
            msg.to_ascii_lowercase().contains("duplicate column name")
        }
        _ => false,
    }
}

fn execute_add_column_if_missing(conn: &Connection, sql: &str) -> Result<(), RegistryError> {
    match conn.execute(sql, []) {
        Ok(_) => Ok(()),
        Err(err) if is_duplicate_column_error(&err) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn sqlite_i64_to_u64(value: i64, field: &str) -> Result<u64, RegistryError> {
    u64::try_from(value).map_err(|_| {
        RegistryError::Database(SqliteError::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid negative value for {field}: {value}"),
            )),
        ))
    })
}

fn u64_to_sqlite_i64(value: u64, field: &str) -> Result<i64, RegistryError> {
    i64::try_from(value)
        .map_err(|_| RegistryError::Integrity(format!("value out of range for {field}: {value}")))
}

fn sqlite_row_i64_to_u64(value: i64, field: &'static str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| {
        SqliteError::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid negative value for {field}: {value}"),
            )),
        )
    })
}

fn sqlite_row_opt_i64_to_opt_u64(
    value: Option<i64>,
    field: &'static str,
) -> rusqlite::Result<Option<u64>> {
    value.map(|v| sqlite_row_i64_to_u64(v, field)).transpose()
}

impl RegistryDb {
    /// Open (or create) the registry database at the given path.
    pub fn open(path: &Path) -> Result<Self, RegistryError> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Open an in-memory database (for testing).
    #[allow(dead_code)]
    pub fn open_in_memory() -> Result<Self, RegistryError> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<(), RegistryError> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS packages (
                name TEXT PRIMARY KEY,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS versions (
                name TEXT NOT NULL REFERENCES packages(name),
                version TEXT NOT NULL,
                pkg_type TEXT NOT NULL,
                checksum TEXT NOT NULL,
                manifest_toml TEXT NOT NULL,
                publisher_key TEXT NOT NULL,
                publisher_sig TEXT NOT NULL,
                registry_sig TEXT,
                dependencies_json TEXT NOT NULL DEFAULT '{}',
                yanked INTEGER NOT NULL DEFAULT 0,
                published_at TEXT NOT NULL,
                PRIMARY KEY (name, version)
            );

            CREATE TABLE IF NOT EXISTS api_keys (
                key_hash TEXT PRIMARY KEY,
                publisher_key TEXT,
                created_at TEXT NOT NULL
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS search_index USING fts5(
                name, description, keywords
            );

            CREATE TABLE IF NOT EXISTS registry_keys (
                key_id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                valid_until TEXT,
                status TEXT NOT NULL DEFAULT 'active'
            );

            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                display_name TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                verified INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS org_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER NOT NULL REFERENCES organizations(id),
                publisher_key TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                invited_by TEXT,
                joined_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(org_id, publisher_key)
            );

            CREATE TABLE IF NOT EXISTS trusted_publishers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                provider TEXT NOT NULL,
                repository TEXT NOT NULL,
                workflow TEXT,
                environment TEXT,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL
            );
            ",
        )?;

        // Add columns that may not exist in older databases.
        // SQLite does not support ADD COLUMN IF NOT EXISTS.
        execute_add_column_if_missing(
            &self.conn,
            "ALTER TABLE versions ADD COLUMN attestation_hash TEXT",
        )?;
        execute_add_column_if_missing(&self.conn, "ALTER TABLE versions ADD COLUMN key_id TEXT")?;
        execute_add_column_if_missing(
            &self.conn,
            "ALTER TABLE versions ADD COLUMN leaf_index INTEGER",
        )?;
        execute_add_column_if_missing(
            &self.conn,
            "ALTER TABLE versions ADD COLUMN download_count INTEGER NOT NULL DEFAULT 0",
        )?;
        execute_add_column_if_missing(
            &self.conn,
            "ALTER TABLE packages ADD COLUMN total_downloads INTEGER NOT NULL DEFAULT 0",
        )?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Packages
    // -----------------------------------------------------------------------

    /// Insert or update a package row. Returns `true` if a new package was created.
    pub fn upsert_package(
        &self,
        name: &str,
        description: Option<&str>,
        now: &str,
    ) -> Result<bool, RegistryError> {
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT name FROM packages WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?;

        if existing.is_some() {
            self.conn.execute(
                "UPDATE packages SET description = COALESCE(?1, description), updated_at = ?2 WHERE name = ?3",
                params![description, now, name],
            )?;
            let effective_description: String = self.conn.query_row(
                "SELECT COALESCE(description, '') FROM packages WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )?;
            // Keep FTS in sync with package metadata updates. Refresh by name
            // rather than rowid lookup so a missing FTS row cannot create
            // duplicate entries for the same package.
            self.conn
                .execute("DELETE FROM search_index WHERE name = ?1", params![name])?;
            self.conn.execute(
                "INSERT INTO search_index (name, description, keywords) VALUES (?1, ?2, '')",
                params![name, effective_description],
            )?;
            Ok(false)
        } else {
            self.conn.execute(
                "INSERT INTO packages (name, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
                params![name, description, now],
            )?;
            // Update FTS index.
            self.conn.execute(
                "INSERT INTO search_index (name, description, keywords) VALUES (?1, ?2, '')",
                params![name, description.unwrap_or("")],
            )?;
            Ok(true)
        }
    }

    /// Get a package by name.
    pub fn get_package(&self, name: &str) -> Result<Option<PackageRow>, RegistryError> {
        let row = self
            .conn
            .query_row(
                "SELECT name, description, created_at, updated_at, total_downloads FROM packages WHERE name = ?1",
                params![name],
                |row| {
                    Ok(PackageRow {
                        name: row.get(0)?,
                        description: row.get(1)?,
                        created_at: row.get(2)?,
                        updated_at: row.get(3)?,
                        total_downloads: sqlite_row_i64_to_u64(
                            row.get::<_, i64>(4)?,
                            "packages.total_downloads",
                        )?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    // -----------------------------------------------------------------------
    // Versions
    // -----------------------------------------------------------------------

    /// Insert a new version row. Returns an error if the version already exists.
    pub fn insert_version(&self, v: &VersionRow) -> Result<(), RegistryError> {
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT version FROM versions WHERE name = ?1 AND version = ?2",
                params![v.name, v.version],
                |row| row.get(0),
            )
            .optional()?;

        if existing.is_some() {
            return Err(RegistryError::Conflict(format!(
                "version {} of {} already exists",
                v.version, v.name
            )));
        }

        self.conn.execute(
            "INSERT INTO versions (name, version, pkg_type, checksum, manifest_toml, publisher_key, publisher_sig, registry_sig, dependencies_json, yanked, published_at, attestation_hash, key_id, leaf_index) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                v.name,
                v.version,
                v.pkg_type,
                v.checksum,
                v.manifest_toml,
                v.publisher_key,
                v.publisher_sig,
                v.registry_sig,
                v.dependencies_json,
                v.yanked as i32,
                v.published_at,
                v.attestation_hash,
                v.key_id,
                v.leaf_index
                    .map(|i| u64_to_sqlite_i64(i, "versions.leaf_index"))
                    .transpose()?,
            ],
        )?;
        Ok(())
    }

    /// List all versions for a package.
    pub fn list_versions(&self, name: &str) -> Result<Vec<VersionRow>, RegistryError> {
        let mut stmt = self.conn.prepare(
            "SELECT name, version, pkg_type, checksum, manifest_toml, publisher_key, publisher_sig, registry_sig, dependencies_json, yanked, published_at, attestation_hash, key_id, leaf_index, download_count FROM versions WHERE name = ?1 ORDER BY published_at ASC",
        )?;
        let rows = stmt
            .query_map(params![name], |row| {
                Ok(VersionRow {
                    name: row.get(0)?,
                    version: row.get(1)?,
                    pkg_type: row.get(2)?,
                    checksum: row.get(3)?,
                    manifest_toml: row.get(4)?,
                    publisher_key: row.get(5)?,
                    publisher_sig: row.get(6)?,
                    registry_sig: row.get(7)?,
                    dependencies_json: row.get(8)?,
                    yanked: row.get::<_, i32>(9)? != 0,
                    published_at: row.get(10)?,
                    attestation_hash: row.get(11)?,
                    key_id: row.get(12)?,
                    leaf_index: sqlite_row_opt_i64_to_opt_u64(
                        row.get::<_, Option<i64>>(13)?,
                        "versions.leaf_index",
                    )?,
                    download_count: sqlite_row_i64_to_u64(
                        row.get::<_, i64>(14)?,
                        "versions.download_count",
                    )?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Get a specific version.
    pub fn get_version(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Option<VersionRow>, RegistryError> {
        let row = self
            .conn
            .query_row(
                "SELECT name, version, pkg_type, checksum, manifest_toml, publisher_key, publisher_sig, registry_sig, dependencies_json, yanked, published_at, attestation_hash, key_id, leaf_index, download_count FROM versions WHERE name = ?1 AND version = ?2",
                params![name, version],
                |row| {
                    Ok(VersionRow {
                        name: row.get(0)?,
                        version: row.get(1)?,
                        pkg_type: row.get(2)?,
                        checksum: row.get(3)?,
                        manifest_toml: row.get(4)?,
                        publisher_key: row.get(5)?,
                        publisher_sig: row.get(6)?,
                        registry_sig: row.get(7)?,
                        dependencies_json: row.get(8)?,
                        yanked: row.get::<_, i32>(9)? != 0,
                        published_at: row.get(10)?,
                        attestation_hash: row.get(11)?,
                        key_id: row.get(12)?,
                        leaf_index: sqlite_row_opt_i64_to_opt_u64(
                            row.get::<_, Option<i64>>(13)?,
                            "versions.leaf_index",
                        )?,
                        download_count: sqlite_row_i64_to_u64(
                            row.get::<_, i64>(14)?,
                            "versions.download_count",
                        )?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Yank a version.
    pub fn yank_version(&self, name: &str, version: &str) -> Result<bool, RegistryError> {
        let count = self.conn.execute(
            "UPDATE versions SET yanked = 1 WHERE name = ?1 AND version = ?2 AND yanked = 0",
            params![name, version],
        )?;
        Ok(count > 0)
    }

    /// Roll back a previously inserted package version.
    ///
    /// This is used as a compensating action when publish fails after DB
    /// writes (for example sparse index write failures) but before Merkle
    /// append. If the package has no remaining versions after deletion, the
    /// package row and search index row are also removed.
    pub fn rollback_published_version(
        &self,
        name: &str,
        version: &str,
    ) -> Result<(), RegistryError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM versions WHERE name = ?1 AND version = ?2",
            params![name, version],
        )?;
        tx.execute(
            "DELETE FROM packages WHERE name = ?1 AND NOT EXISTS (SELECT 1 FROM versions WHERE name = ?1)",
            params![name],
        )?;
        tx.execute(
            "DELETE FROM search_index WHERE name = ?1 AND NOT EXISTS (SELECT 1 FROM packages WHERE name = ?1)",
            params![name],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Return whether any version references the given content checksum.
    pub fn has_versions_with_checksum(&self, checksum: &str) -> Result<bool, RegistryError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM versions WHERE checksum = ?1",
            params![checksum],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    // -----------------------------------------------------------------------
    // Registry Keys
    // -----------------------------------------------------------------------

    /// Insert or update a registry key record.
    pub fn upsert_registry_key(
        &self,
        key_info: &crate::keys::RegistryKeyInfo,
    ) -> Result<(), RegistryError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO registry_keys (key_id, public_key, created_at, valid_until, status) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                key_info.key_id,
                key_info.public_key,
                key_info.created_at,
                key_info.valid_until,
                key_info.status.to_string(),
            ],
        )?;
        Ok(())
    }

    /// Get a registry key by key ID.
    pub fn get_registry_key(
        &self,
        key_id: &str,
    ) -> Result<Option<crate::keys::RegistryKeyInfo>, RegistryError> {
        let row = self
            .conn
            .query_row(
                "SELECT key_id, public_key, created_at, valid_until, status FROM registry_keys WHERE key_id = ?1",
                params![key_id],
                |row| {
                    let status_raw: String = row.get(4)?;
                    let status = match status_raw.as_str() {
                        "active" => crate::keys::KeyStatus::Active,
                        "deprecated" => crate::keys::KeyStatus::Deprecated,
                        "revoked" => crate::keys::KeyStatus::Revoked,
                        _ => {
                            return Err(rusqlite::Error::FromSqlConversionFailure(
                                4,
                                rusqlite::types::Type::Text,
                                Box::new(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!("invalid key status '{status_raw}'"),
                                )),
                            ));
                        }
                    };

                    Ok(crate::keys::RegistryKeyInfo {
                        key_id: row.get(0)?,
                        public_key: row.get(1)?,
                        created_at: row.get(2)?,
                        valid_until: row.get(3)?,
                        status,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Update the attestation hash for a specific version.
    #[allow(dead_code)]
    pub fn set_attestation_hash(
        &self,
        name: &str,
        version: &str,
        attestation_hash: &str,
        key_id: &str,
    ) -> Result<(), RegistryError> {
        self.conn.execute(
            "UPDATE versions SET attestation_hash = ?1, key_id = ?2 WHERE name = ?3 AND version = ?4",
            params![attestation_hash, key_id, name, version],
        )?;
        Ok(())
    }

    /// Update the leaf_index for a specific version.
    #[allow(dead_code)]
    pub fn update_leaf_index(
        &self,
        name: &str,
        version: &str,
        leaf_index: u64,
    ) -> Result<(), RegistryError> {
        self.conn.execute(
            "UPDATE versions SET leaf_index = ?1 WHERE name = ?2 AND version = ?3",
            params![
                u64_to_sqlite_i64(leaf_index, "versions.leaf_index")?,
                name,
                version
            ],
        )?;
        Ok(())
    }

    /// List all versions across all packages in deterministic transparency order.
    ///
    /// Indexed rows are ordered by `leaf_index ASC` first, then legacy
    /// unindexed rows by publish timestamp/name/version.
    pub fn list_all_versions_ordered(&self) -> Result<Vec<VersionRow>, RegistryError> {
        let mut stmt = self.conn.prepare(
            "SELECT name, version, pkg_type, checksum, manifest_toml, publisher_key, publisher_sig, registry_sig, dependencies_json, yanked, published_at, attestation_hash, key_id, leaf_index, download_count
             FROM versions
             ORDER BY
               CASE WHEN leaf_index IS NULL THEN 1 ELSE 0 END ASC,
               leaf_index ASC,
               published_at ASC,
               name ASC,
               version ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(VersionRow {
                    name: row.get(0)?,
                    version: row.get(1)?,
                    pkg_type: row.get(2)?,
                    checksum: row.get(3)?,
                    manifest_toml: row.get(4)?,
                    publisher_key: row.get(5)?,
                    publisher_sig: row.get(6)?,
                    registry_sig: row.get(7)?,
                    dependencies_json: row.get(8)?,
                    yanked: row.get::<_, i32>(9)? != 0,
                    published_at: row.get(10)?,
                    attestation_hash: row.get(11)?,
                    key_id: row.get(12)?,
                    leaf_index: sqlite_row_opt_i64_to_opt_u64(
                        row.get::<_, Option<i64>>(13)?,
                        "versions.leaf_index",
                    )?,
                    download_count: sqlite_row_i64_to_u64(
                        row.get::<_, i64>(14)?,
                        "versions.download_count",
                    )?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Return whether `publisher_key` has published at least one version of
    /// the given package.
    pub fn is_package_publisher(
        &self,
        package_name: &str,
        publisher_key: &str,
    ) -> Result<bool, RegistryError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM versions WHERE name = ?1 AND publisher_key = ?2",
            params![package_name, publisher_key],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    // -----------------------------------------------------------------------
    // Download Statistics
    // -----------------------------------------------------------------------

    /// Atomically increment both the version and package download counters.
    pub fn increment_download(&self, name: &str, version: &str) -> Result<(), RegistryError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE versions SET download_count = download_count + 1 WHERE name = ?1 AND version = ?2",
            params![name, version],
        )?;
        tx.execute(
            "UPDATE packages SET total_downloads = total_downloads + 1 WHERE name = ?1",
            params![name],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Get aggregate download statistics for a package.
    pub fn get_package_stats(&self, name: &str) -> Result<Option<PackageStats>, RegistryError> {
        let pkg = self.get_package(name)?;
        let pkg = match pkg {
            Some(p) => p,
            None => return Ok(None),
        };

        let mut stmt = self.conn.prepare(
            "SELECT version, download_count, published_at FROM versions WHERE name = ?1 ORDER BY published_at DESC",
        )?;
        let version_stats: Vec<VersionStats> = stmt
            .query_map(params![name], |row| {
                Ok(VersionStats {
                    version: row.get(0)?,
                    downloads: sqlite_row_i64_to_u64(
                        row.get::<_, i64>(1)?,
                        "versions.download_count",
                    )?,
                    published_at: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let first_published = version_stats.last().map(|v| v.published_at.clone());
        let latest_version = version_stats.first().map(|v| v.version.clone());

        Ok(Some(PackageStats {
            name: pkg.name,
            total_downloads: pkg.total_downloads,
            versions: version_stats,
            first_published,
            latest_version,
        }))
    }

    /// Get the most popular packages ordered by total downloads.
    pub fn get_popular_packages(&self, limit: u32) -> Result<Vec<PopularPackage>, RegistryError> {
        let mut stmt = self.conn.prepare(
            "SELECT p.name, p.description, p.total_downloads, (SELECT v.version FROM versions v WHERE v.name = p.name ORDER BY v.published_at DESC LIMIT 1) FROM packages p ORDER BY p.total_downloads DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(PopularPackage {
                    name: row.get(0)?,
                    description: row.get(1)?,
                    total_downloads: sqlite_row_i64_to_u64(
                        row.get::<_, i64>(2)?,
                        "packages.total_downloads",
                    )?,
                    latest_version: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // -----------------------------------------------------------------------
    // Search
    // -----------------------------------------------------------------------

    /// Full-text search across packages.
    pub fn search(
        &self,
        query: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<SearchResult>, RegistryError> {
        // Use FTS5 MATCH if query is non-empty, otherwise list all.
        if query.is_empty() {
            let mut stmt = self.conn.prepare(
                "SELECT p.name, p.description, (SELECT v.version FROM versions v WHERE v.name = p.name ORDER BY v.published_at DESC LIMIT 1) FROM packages p ORDER BY p.updated_at DESC LIMIT ?1 OFFSET ?2",
            )?;
            let rows = stmt
                .query_map(params![limit, offset], |row| {
                    Ok(SearchResult {
                        name: row.get(0)?,
                        description: row.get(1)?,
                        latest_version: row.get(2)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        } else {
            // Build a strict literal-token query so user-provided input cannot
            // inject FTS5 operators.
            let Some(safe_query) = build_fts_literal_query(query) else {
                return Ok(Vec::new());
            };
            let mut stmt = self.conn.prepare(
                "SELECT p.name, p.description, (SELECT v.version FROM versions v WHERE v.name = p.name ORDER BY v.published_at DESC LIMIT 1) FROM search_index JOIN packages p ON p.name = search_index.name WHERE search_index MATCH ?1 ORDER BY rank LIMIT ?2 OFFSET ?3",
            )?;
            let rows = stmt
                .query_map(params![safe_query, limit, offset], |row| {
                    Ok(SearchResult {
                        name: row.get(0)?,
                        description: row.get(1)?,
                        latest_version: row.get(2)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        }
    }

    /// Count total search matches for pagination.
    pub fn count_search_results(&self, query: &str) -> Result<u64, RegistryError> {
        if query.is_empty() {
            let count: i64 = self
                .conn
                .query_row("SELECT COUNT(*) FROM packages", [], |row| row.get(0))?;
            return sqlite_i64_to_u64(count, "search.count");
        }

        // Keep query sanitation aligned with `search`.
        let Some(safe_query) = build_fts_literal_query(query) else {
            return Ok(0);
        };
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM search_index JOIN packages p ON p.name = search_index.name WHERE search_index MATCH ?1",
            params![safe_query],
            |row| row.get(0),
        )?;
        sqlite_i64_to_u64(count, "search.count")
    }

    // -----------------------------------------------------------------------
    // API Keys
    // -----------------------------------------------------------------------

    /// Insert an API key hash.
    #[allow(dead_code)]
    pub fn insert_api_key(
        &self,
        key_hash: &str,
        publisher_key: Option<&str>,
        now: &str,
    ) -> Result<(), RegistryError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO api_keys (key_hash, publisher_key, created_at) VALUES (?1, ?2, ?3)",
            params![key_hash, publisher_key, now],
        )?;
        Ok(())
    }

    /// Look up an API key by its SHA-256 hash.
    #[allow(dead_code)]
    pub fn get_api_key(&self, key_hash: &str) -> Result<Option<ApiKeyRow>, RegistryError> {
        let row = self
            .conn
            .query_row(
                "SELECT key_hash, publisher_key, created_at FROM api_keys WHERE key_hash = ?1",
                params![key_hash],
                |row| {
                    Ok(ApiKeyRow {
                        key_hash: row.get(0)?,
                        publisher_key: row.get(1)?,
                        created_at: row.get(2)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    // -----------------------------------------------------------------------
    // Trusted Publishers
    // -----------------------------------------------------------------------

    /// Add a trusted publisher for OIDC-based publishing.
    /// Returns the new row's ID.
    pub fn add_trusted_publisher(
        &self,
        package_name: &str,
        provider: &str,
        repository: &str,
        workflow: Option<&str>,
        environment: Option<&str>,
        created_by: &str,
    ) -> Result<i64, RegistryError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO trusted_publishers (package_name, provider, repository, workflow, environment, created_at, created_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![package_name, provider, repository, workflow, environment, now, created_by],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// List all trusted publishers for a package.
    pub fn get_trusted_publishers(
        &self,
        package_name: &str,
    ) -> Result<Vec<TrustedPublisher>, RegistryError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, package_name, provider, repository, workflow, environment, created_at, created_by FROM trusted_publishers WHERE package_name = ?1 ORDER BY created_at ASC",
        )?;
        let rows = stmt
            .query_map(params![package_name], |row| {
                Ok(TrustedPublisher {
                    id: row.get(0)?,
                    package_name: row.get(1)?,
                    provider: row.get(2)?,
                    repository: row.get(3)?,
                    workflow: row.get(4)?,
                    environment: row.get(5)?,
                    created_at: row.get(6)?,
                    created_by: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Remove a trusted publisher by package + ID.
    /// Returns `true` if a row was deleted.
    pub fn remove_trusted_publisher_for_package(
        &self,
        package_name: &str,
        id: i64,
    ) -> Result<bool, RegistryError> {
        let count = self.conn.execute(
            "DELETE FROM trusted_publishers WHERE package_name = ?1 AND id = ?2",
            params![package_name, id],
        )?;
        Ok(count > 0)
    }

    // -----------------------------------------------------------------------
    // Organizations
    // -----------------------------------------------------------------------

    /// Create a new organization. The creator automatically becomes an owner.
    /// Returns the new organization's ID.
    pub fn create_organization(
        &self,
        name: &str,
        display_name: Option<&str>,
        creator_key: &str,
    ) -> Result<i64, RegistryError> {
        let now = chrono::Utc::now().to_rfc3339();

        // Check for existing org with this name.
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM organizations WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?;

        if existing.is_some() {
            return Err(RegistryError::Conflict(format!(
                "organization '{}' already exists",
                name
            )));
        }

        self.conn.execute(
            "INSERT INTO organizations (name, display_name, created_by, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![name, display_name, creator_key, now],
        )?;

        let org_id = self.conn.last_insert_rowid();

        // Creator becomes owner.
        self.conn.execute(
            "INSERT INTO org_members (org_id, publisher_key, role, invited_by, joined_at) VALUES (?1, ?2, 'owner', ?3, ?4)",
            params![org_id, creator_key, creator_key, now],
        )?;

        Ok(org_id)
    }

    /// Get an organization by name.
    pub fn get_organization(&self, name: &str) -> Result<Option<Organization>, RegistryError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, name, display_name, created_by, created_at, verified FROM organizations WHERE name = ?1",
                params![name],
                |row| {
                    Ok(Organization {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        display_name: row.get(2)?,
                        created_by: row.get(3)?,
                        created_at: row.get(4)?,
                        verified: row.get::<_, i32>(5)? != 0,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// List all organizations.
    #[allow(dead_code)]
    pub fn list_organizations(&self) -> Result<Vec<Organization>, RegistryError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, display_name, created_by, created_at, verified FROM organizations ORDER BY name ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(Organization {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    display_name: row.get(2)?,
                    created_by: row.get(3)?,
                    created_at: row.get(4)?,
                    verified: row.get::<_, i32>(5)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Add a member to an organization.
    pub fn add_org_member(
        &self,
        org_id: i64,
        publisher_key: &str,
        role: &str,
        invited_by: Option<&str>,
    ) -> Result<(), RegistryError> {
        let now = chrono::Utc::now().to_rfc3339();

        // Check if already a member.
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT role FROM org_members WHERE org_id = ?1 AND publisher_key = ?2",
                params![org_id, publisher_key],
                |row| row.get(0),
            )
            .optional()?;

        if existing.is_some() {
            return Err(RegistryError::Conflict(format!(
                "key '{}' is already a member of this organization",
                publisher_key
            )));
        }

        self.conn.execute(
            "INSERT INTO org_members (org_id, publisher_key, role, invited_by, joined_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![org_id, publisher_key, role, invited_by, now],
        )?;

        Ok(())
    }

    /// Remove a member from an organization.
    /// Returns an error if the member is the last owner.
    pub fn remove_org_member(&self, org_id: i64, publisher_key: &str) -> Result<(), RegistryError> {
        // Check the member's current role.
        let role: Option<String> = self
            .conn
            .query_row(
                "SELECT role FROM org_members WHERE org_id = ?1 AND publisher_key = ?2",
                params![org_id, publisher_key],
                |row| row.get(0),
            )
            .optional()?;

        let role = match role {
            Some(r) => r,
            None => {
                return Err(RegistryError::NotFound(
                    "member not found in organization".into(),
                ));
            }
        };

        // If the member is an owner, ensure they're not the last one.
        if role == "owner" {
            let owner_count: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM org_members WHERE org_id = ?1 AND role = 'owner'",
                params![org_id],
                |row| row.get(0),
            )?;
            if owner_count <= 1 {
                return Err(RegistryError::BadRequest(
                    "cannot remove the last owner of an organization".into(),
                ));
            }
        }

        self.conn.execute(
            "DELETE FROM org_members WHERE org_id = ?1 AND publisher_key = ?2",
            params![org_id, publisher_key],
        )?;

        Ok(())
    }

    /// List all members of an organization.
    pub fn get_org_members(&self, org_id: i64) -> Result<Vec<OrgMember>, RegistryError> {
        let mut stmt = self.conn.prepare(
            "SELECT publisher_key, role, joined_at FROM org_members WHERE org_id = ?1 ORDER BY joined_at ASC",
        )?;
        let rows = stmt
            .query_map(params![org_id], |row| {
                Ok(OrgMember {
                    publisher_key: row.get(0)?,
                    role: row.get(1)?,
                    joined_at: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Get a member's role in an organization.
    pub fn get_member_role(
        &self,
        org_id: i64,
        publisher_key: &str,
    ) -> Result<Option<String>, RegistryError> {
        let role = self
            .conn
            .query_row(
                "SELECT role FROM org_members WHERE org_id = ?1 AND publisher_key = ?2",
                params![org_id, publisher_key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(role)
    }

    /// Check if a publisher key is a member of an organization (by name).
    #[allow(dead_code)]
    pub fn is_org_member(
        &self,
        org_name: &str,
        publisher_key: &str,
    ) -> Result<bool, RegistryError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM org_members m JOIN organizations o ON o.id = m.org_id WHERE o.name = ?1 AND m.publisher_key = ?2",
            params![org_name, publisher_key],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// List all packages in an organization's scope.
    pub fn list_org_packages(&self, org_name: &str) -> Result<Vec<PackageRow>, RegistryError> {
        let escaped_org_name = escape_sqlite_like_literal(org_name);
        let mut stmt = self.conn.prepare(
            "SELECT name, description, created_at, updated_at, total_downloads FROM packages WHERE name LIKE ?1 ESCAPE '\\' ORDER BY name ASC",
        )?;
        let pattern = format!("@{escaped_org_name}/%");
        let rows = stmt
            .query_map(params![pattern], |row| {
                Ok(PackageRow {
                    name: row.get(0)?,
                    description: row.get(1)?,
                    created_at: row.get(2)?,
                    updated_at: row.get(3)?,
                    total_downloads: sqlite_row_i64_to_u64(
                        row.get::<_, i64>(4)?,
                        "packages.total_downloads",
                    )?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Count members in an organization.
    pub fn count_org_members(&self, org_id: i64) -> Result<i64, RegistryError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM org_members WHERE org_id = ?1",
            params![org_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Count packages in an organization's scope.
    pub fn count_org_packages(&self, org_name: &str) -> Result<i64, RegistryError> {
        let escaped_org_name = escape_sqlite_like_literal(org_name);
        let pattern = format!("@{escaped_org_name}/%");
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM packages WHERE name LIKE ?1 ESCAPE '\\'",
            params![pattern],
            |row| row.get(0),
        )?;
        Ok(count)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> RegistryDb {
        RegistryDb::open_in_memory().unwrap()
    }

    #[test]
    fn create_and_get_package() {
        let db = test_db();
        let created = db
            .upsert_package("my-guard", Some("A guard"), "2025-01-01T00:00:00Z")
            .unwrap();
        assert!(created);

        let pkg = db.get_package("my-guard").unwrap().unwrap();
        assert_eq!(pkg.name, "my-guard");
        assert_eq!(pkg.description.as_deref(), Some("A guard"));
    }

    #[test]
    fn upsert_package_updates() {
        let db = test_db();
        db.upsert_package("my-guard", Some("v1"), "2025-01-01T00:00:00Z")
            .unwrap();
        let created = db
            .upsert_package("my-guard", Some("v2"), "2025-01-02T00:00:00Z")
            .unwrap();
        assert!(!created);

        let pkg = db.get_package("my-guard").unwrap().unwrap();
        assert_eq!(pkg.description.as_deref(), Some("v2"));
        assert_eq!(pkg.updated_at, "2025-01-02T00:00:00Z");
    }

    #[test]
    fn upsert_package_refreshes_search_index_description() {
        let db = test_db();
        db.upsert_package("my-guard", Some("v1-desc"), "2025-01-01T00:00:00Z")
            .unwrap();
        let initial = db.search("v1-desc", 10, 0).unwrap();
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].name, "my-guard");

        db.upsert_package("my-guard", Some("v2-updated"), "2025-01-02T00:00:00Z")
            .unwrap();

        let stale = db.search("v1-desc", 10, 0).unwrap();
        assert!(stale.is_empty());

        let updated = db.search("v2-updated", 10, 0).unwrap();
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0].name, "my-guard");
    }

    #[test]
    fn upsert_package_recreates_missing_search_index_row_without_duplicates() {
        let db = test_db();
        db.upsert_package("my-guard", Some("v1-desc"), "2025-01-01T00:00:00Z")
            .unwrap();

        db.conn
            .execute(
                "DELETE FROM search_index WHERE name = ?1",
                params!["my-guard"],
            )
            .unwrap();

        db.upsert_package("my-guard", Some("v2-desc"), "2025-01-02T00:00:00Z")
            .unwrap();

        let fts_count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM search_index WHERE name = ?1",
                params!["my-guard"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(fts_count, 1);

        let results = db.search("v2-desc", 10, 0).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "my-guard");
    }

    #[test]
    fn insert_and_list_versions() {
        let db = test_db();
        db.upsert_package("my-guard", None, "2025-01-01T00:00:00Z")
            .unwrap();

        let v = VersionRow {
            name: "my-guard".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "abc123".into(),
            manifest_toml: "[package]\nname = \"my-guard\"".into(),
            publisher_key: "pubkey_hex".into(),
            publisher_sig: "sig_hex".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: None,
            download_count: 0,
        };
        db.insert_version(&v).unwrap();

        let versions = db.list_versions("my-guard").unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "1.0.0");
    }

    #[test]
    fn duplicate_version_rejected() {
        let db = test_db();
        db.upsert_package("pkg", None, "2025-01-01T00:00:00Z")
            .unwrap();

        let v = VersionRow {
            name: "pkg".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "abc".into(),
            manifest_toml: "".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: None,
            download_count: 0,
        };
        db.insert_version(&v).unwrap();

        let err = db.insert_version(&v).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn yank_version() {
        let db = test_db();
        db.upsert_package("pkg", None, "2025-01-01T00:00:00Z")
            .unwrap();

        let v = VersionRow {
            name: "pkg".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "abc".into(),
            manifest_toml: "".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: None,
            download_count: 0,
        };
        db.insert_version(&v).unwrap();

        let yanked = db.yank_version("pkg", "1.0.0").unwrap();
        assert!(yanked);

        let row = db.get_version("pkg", "1.0.0").unwrap().unwrap();
        assert!(row.yanked);

        // Yanking again returns false.
        let yanked_again = db.yank_version("pkg", "1.0.0").unwrap();
        assert!(!yanked_again);
    }

    #[test]
    fn rollback_published_version_removes_orphaned_package_and_search_row() {
        let db = test_db();
        db.upsert_package("pkg", Some("Pkg"), "2025-01-01T00:00:00Z")
            .unwrap();
        db.insert_version(&VersionRow {
            name: "pkg".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "abc".into(),
            manifest_toml: "".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: Some(0),
            download_count: 0,
        })
        .unwrap();

        db.rollback_published_version("pkg", "1.0.0").unwrap();

        assert!(db.get_version("pkg", "1.0.0").unwrap().is_none());
        assert!(db.get_package("pkg").unwrap().is_none());
        assert!(db.search("pkg", 10, 0).unwrap().is_empty());
    }

    #[test]
    fn rollback_published_version_keeps_package_when_other_versions_exist() {
        let db = test_db();
        db.upsert_package("pkg", Some("Pkg"), "2025-01-01T00:00:00Z")
            .unwrap();
        db.insert_version(&VersionRow {
            name: "pkg".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "abc".into(),
            manifest_toml: "".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: Some(0),
            download_count: 0,
        })
        .unwrap();
        db.insert_version(&VersionRow {
            name: "pkg".into(),
            version: "1.1.0".into(),
            pkg_type: "guard".into(),
            checksum: "def".into(),
            manifest_toml: "".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-02T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: Some(1),
            download_count: 0,
        })
        .unwrap();

        db.rollback_published_version("pkg", "1.1.0").unwrap();

        assert!(db.get_package("pkg").unwrap().is_some());
        assert!(db.get_version("pkg", "1.0.0").unwrap().is_some());
        assert!(db.get_version("pkg", "1.1.0").unwrap().is_none());
        assert!(!db.search("pkg", 10, 0).unwrap().is_empty());
    }

    #[test]
    fn has_versions_with_checksum_reports_references() {
        let db = test_db();
        db.upsert_package("pkg", Some("Pkg"), "2025-01-01T00:00:00Z")
            .unwrap();
        db.insert_version(&VersionRow {
            name: "pkg".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "0xaaa".into(),
            manifest_toml: "".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: Some(0),
            download_count: 0,
        })
        .unwrap();

        assert!(db.has_versions_with_checksum("0xaaa").unwrap());
        assert!(!db.has_versions_with_checksum("0xbbb").unwrap());
    }

    #[test]
    fn get_registry_key_reads_persisted_record() {
        let db = test_db();
        let key = crate::keys::RegistryKeyInfo {
            key_id: "kid-test".into(),
            public_key: "pk-test".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            valid_until: Some("2026-12-31T00:00:00Z".into()),
            status: crate::keys::KeyStatus::Deprecated,
        };
        db.upsert_registry_key(&key).unwrap();

        let loaded = db.get_registry_key("kid-test").unwrap().unwrap();
        assert_eq!(loaded.key_id, "kid-test");
        assert_eq!(loaded.public_key, "pk-test");
        assert_eq!(loaded.valid_until.as_deref(), Some("2026-12-31T00:00:00Z"));
        assert_eq!(loaded.status, crate::keys::KeyStatus::Deprecated);
    }

    #[test]
    fn search_packages() {
        let db = test_db();
        db.upsert_package(
            "secret-scanner",
            Some("Scans for secrets"),
            "2025-01-01T00:00:00Z",
        )
        .unwrap();
        db.upsert_package(
            "path-guard",
            Some("Path access control"),
            "2025-01-02T00:00:00Z",
        )
        .unwrap();

        let results = db.search("secret", 10, 0).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "secret-scanner");
    }

    #[test]
    fn search_empty_query_lists_all() {
        let db = test_db();
        db.upsert_package("pkg-a", None, "2025-01-01T00:00:00Z")
            .unwrap();
        db.upsert_package("pkg-b", None, "2025-01-02T00:00:00Z")
            .unwrap();

        let results = db.search("", 10, 0).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn count_search_results_for_query_and_empty() {
        let db = test_db();
        db.upsert_package(
            "secret-scanner-a",
            Some("Scans for secrets"),
            "2025-01-01T00:00:00Z",
        )
        .unwrap();
        db.upsert_package(
            "secret-scanner-b",
            Some("Also scans for secrets"),
            "2025-01-02T00:00:00Z",
        )
        .unwrap();
        db.upsert_package(
            "path-guard",
            Some("Path access control"),
            "2025-01-03T00:00:00Z",
        )
        .unwrap();

        assert_eq!(db.count_search_results("secret").unwrap(), 2);
        assert_eq!(db.count_search_results("").unwrap(), 3);
    }

    #[test]
    fn build_fts_literal_query_blocks_operator_injection() {
        let q = build_fts_literal_query("alpha\" OR beta").unwrap();
        assert_eq!(q, "\"alpha\" AND \"OR\" AND \"beta\"");
    }

    #[test]
    fn search_and_count_handle_operator_like_input_safely() {
        let db = test_db();
        db.upsert_package("alpha", Some("first"), "2025-01-01T00:00:00Z")
            .unwrap();
        db.upsert_package("beta", Some("second"), "2025-01-02T00:00:00Z")
            .unwrap();

        let q = "alpha\" OR beta";
        let results = db.search(q, 10, 0).unwrap();
        assert!(results.is_empty());
        assert_eq!(db.count_search_results(q).unwrap(), 0);
    }

    #[test]
    fn search_and_count_ignore_punctuation_only_queries() {
        let db = test_db();
        db.upsert_package("alpha", Some("first"), "2025-01-01T00:00:00Z")
            .unwrap();

        let q = "\"\"\" !!!";
        let results = db.search(q, 10, 0).unwrap();
        assert!(results.is_empty());
        assert_eq!(db.count_search_results(q).unwrap(), 0);
    }

    #[test]
    fn api_key_crud() {
        let db = test_db();
        db.insert_api_key("hash123", Some("pubkey_hex"), "2025-01-01T00:00:00Z")
            .unwrap();

        let row = db.get_api_key("hash123").unwrap().unwrap();
        assert_eq!(row.publisher_key.as_deref(), Some("pubkey_hex"));

        // Non-existent key.
        assert!(db.get_api_key("nope").unwrap().is_none());
    }

    // -------------------------------------------------------------------
    // Organization tests
    // -------------------------------------------------------------------

    #[test]
    fn create_and_get_organization() {
        let db = test_db();
        let org_id = db
            .create_organization("acme", Some("Acme Corp"), "creator_key_hex")
            .unwrap();
        assert!(org_id > 0);

        let org = db.get_organization("acme").unwrap().unwrap();
        assert_eq!(org.name, "acme");
        assert_eq!(org.display_name.as_deref(), Some("Acme Corp"));
        assert_eq!(org.created_by, "creator_key_hex");
        assert!(!org.verified);
    }

    #[test]
    fn create_org_duplicate_rejected() {
        let db = test_db();
        db.create_organization("acme", None, "key1").unwrap();
        let err = db.create_organization("acme", None, "key2").unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn creator_becomes_owner() {
        let db = test_db();
        let org_id = db.create_organization("acme", None, "creator_key").unwrap();

        let role = db.get_member_role(org_id, "creator_key").unwrap();
        assert_eq!(role.as_deref(), Some("owner"));
    }

    #[test]
    fn add_and_list_org_members() {
        let db = test_db();
        let org_id = db.create_organization("acme", None, "owner_key").unwrap();

        db.add_org_member(org_id, "member_key", "member", Some("owner_key"))
            .unwrap();
        db.add_org_member(org_id, "maintainer_key", "maintainer", Some("owner_key"))
            .unwrap();

        let members = db.get_org_members(org_id).unwrap();
        assert_eq!(members.len(), 3); // owner + member + maintainer

        let count = db.count_org_members(org_id).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn add_duplicate_member_rejected() {
        let db = test_db();
        let org_id = db.create_organization("acme", None, "owner_key").unwrap();

        let err = db
            .add_org_member(org_id, "owner_key", "member", None)
            .unwrap_err();
        assert!(err.to_string().contains("already a member"));
    }

    #[test]
    fn remove_org_member() {
        let db = test_db();
        let org_id = db.create_organization("acme", None, "owner_key").unwrap();

        db.add_org_member(org_id, "member_key", "member", Some("owner_key"))
            .unwrap();

        db.remove_org_member(org_id, "member_key").unwrap();

        let role = db.get_member_role(org_id, "member_key").unwrap();
        assert!(role.is_none());
    }

    #[test]
    fn cannot_remove_last_owner() {
        let db = test_db();
        let org_id = db.create_organization("acme", None, "owner_key").unwrap();

        let err = db.remove_org_member(org_id, "owner_key").unwrap_err();
        assert!(err.to_string().contains("last owner"));
    }

    #[test]
    fn remove_owner_if_not_last() {
        let db = test_db();
        let org_id = db.create_organization("acme", None, "owner1").unwrap();
        db.add_org_member(org_id, "owner2", "owner", Some("owner1"))
            .unwrap();

        // Now there are two owners, removing one should work.
        db.remove_org_member(org_id, "owner1").unwrap();

        let role = db.get_member_role(org_id, "owner1").unwrap();
        assert!(role.is_none());
    }

    #[test]
    fn is_org_member_check() {
        let db = test_db();
        db.create_organization("acme", None, "owner_key").unwrap();

        assert!(db.is_org_member("acme", "owner_key").unwrap());
        assert!(!db.is_org_member("acme", "stranger_key").unwrap());
    }

    #[test]
    fn list_org_packages() {
        let db = test_db();
        db.create_organization("acme", None, "owner_key").unwrap();

        db.upsert_package("@acme/guard-a", Some("Guard A"), "2025-01-01T00:00:00Z")
            .unwrap();
        db.upsert_package("@acme/guard-b", None, "2025-01-02T00:00:00Z")
            .unwrap();
        db.upsert_package("unscoped-pkg", None, "2025-01-03T00:00:00Z")
            .unwrap();

        let packages = db.list_org_packages("acme").unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().all(|p| p.name.starts_with("@acme/")));

        let count = db.count_org_packages("acme").unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn list_org_packages_escapes_like_wildcards_in_org_name() {
        let db = test_db();
        db.upsert_package(
            "@acme%_co/guard-a",
            Some("matches exact scoped org"),
            "2025-01-01T00:00:00Z",
        )
        .unwrap();
        db.upsert_package(
            "@acmeXXco/guard-b",
            Some("must not match escaped wildcard pattern"),
            "2025-01-02T00:00:00Z",
        )
        .unwrap();

        let packages = db.list_org_packages("acme%_co").unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "@acme%_co/guard-a");

        let count = db.count_org_packages("acme%_co").unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn list_organizations() {
        let db = test_db();
        db.create_organization("acme", Some("Acme Corp"), "key1")
            .unwrap();
        db.create_organization("beta", None, "key2").unwrap();

        let orgs = db.list_organizations().unwrap();
        assert_eq!(orgs.len(), 2);
        assert_eq!(orgs[0].name, "acme");
        assert_eq!(orgs[1].name, "beta");
    }

    #[test]
    fn remove_nonexistent_member_fails() {
        let db = test_db();
        let org_id = db.create_organization("acme", None, "owner_key").unwrap();

        let err = db.remove_org_member(org_id, "nonexistent").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    // -------------------------------------------------------------------
    // Transparency log (leaf_index) tests
    // -------------------------------------------------------------------

    #[test]
    fn update_and_read_leaf_index() {
        let db = test_db();
        db.upsert_package("pkg", None, "2025-01-01T00:00:00Z")
            .unwrap();

        let v = VersionRow {
            name: "pkg".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "abc".into(),
            manifest_toml: "".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: None,
            download_count: 0,
        };
        db.insert_version(&v).unwrap();

        // Initially no leaf_index.
        let row = db.get_version("pkg", "1.0.0").unwrap().unwrap();
        assert!(row.leaf_index.is_none());

        // Update leaf_index.
        db.update_leaf_index("pkg", "1.0.0", 42).unwrap();

        // Read back.
        let row = db.get_version("pkg", "1.0.0").unwrap().unwrap();
        assert_eq!(row.leaf_index, Some(42));
    }

    #[test]
    fn list_all_versions_ordered_returns_correct_order() {
        let db = test_db();
        db.upsert_package("pkg-a", None, "2025-01-01T00:00:00Z")
            .unwrap();
        db.upsert_package("pkg-b", None, "2025-01-02T00:00:00Z")
            .unwrap();

        let v1 = VersionRow {
            name: "pkg-b".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "abc".into(),
            manifest_toml: "".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            // Intentionally older timestamp to assert ordering uses leaf_index.
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: Some(1),
            download_count: 0,
        };
        let v0 = VersionRow {
            name: "pkg-a".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "def".into(),
            manifest_toml: "".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            // Intentionally newer timestamp to assert ordering uses leaf_index.
            published_at: "2025-01-02T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: Some(0),
            download_count: 0,
        };

        // Insert out of order.
        db.insert_version(&v1).unwrap();
        db.insert_version(&v0).unwrap();

        let all = db.list_all_versions_ordered().unwrap();
        assert_eq!(all.len(), 2);
        // Should be sorted by leaf_index ASC first.
        assert_eq!(all[0].name, "pkg-a");
        assert_eq!(all[0].leaf_index, Some(0));
        assert_eq!(all[1].name, "pkg-b");
        assert_eq!(all[1].leaf_index, Some(1));
    }

    #[test]
    fn is_package_publisher_checks_existing_versions() {
        let db = test_db();
        db.upsert_package("pkg", None, "2025-01-01T00:00:00Z")
            .unwrap();
        db.insert_version(&VersionRow {
            name: "pkg".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "abc".into(),
            manifest_toml: "".into(),
            publisher_key: "owner".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: Some(0),
            download_count: 0,
        })
        .unwrap();

        assert!(db.is_package_publisher("pkg", "owner").unwrap());
        assert!(!db.is_package_publisher("pkg", "stranger").unwrap());
    }

    #[test]
    fn insert_version_with_leaf_index() {
        let db = test_db();
        db.upsert_package("pkg", None, "2025-01-01T00:00:00Z")
            .unwrap();

        let v = VersionRow {
            name: "pkg".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "abc".into(),
            manifest_toml: "".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: Some(7),
            download_count: 0,
        };
        db.insert_version(&v).unwrap();

        let row = db.get_version("pkg", "1.0.0").unwrap().unwrap();
        assert_eq!(row.leaf_index, Some(7));
    }

    // -------------------------------------------------------------------
    // Trusted publisher tests
    // -------------------------------------------------------------------

    #[test]
    fn trusted_publisher_crud() {
        let db = test_db();
        let id = db
            .add_trusted_publisher(
                "my-guard",
                "github",
                "acme/my-guard",
                Some("release.yml"),
                None,
                "creator_key",
            )
            .unwrap();
        assert!(id > 0);

        let publishers = db.get_trusted_publishers("my-guard").unwrap();
        assert_eq!(publishers.len(), 1);
        assert_eq!(publishers[0].provider, "github");
        assert_eq!(publishers[0].repository, "acme/my-guard");
        assert_eq!(publishers[0].workflow.as_deref(), Some("release.yml"));
        assert!(publishers[0].environment.is_none());

        let deleted = db
            .remove_trusted_publisher_for_package("my-guard", id)
            .unwrap();
        assert!(deleted);

        let publishers = db.get_trusted_publishers("my-guard").unwrap();
        assert!(publishers.is_empty());
    }

    #[test]
    fn trusted_publisher_remove_nonexistent() {
        let db = test_db();
        let deleted = db
            .remove_trusted_publisher_for_package("my-guard", 9999)
            .unwrap();
        assert!(!deleted);
    }

    #[test]
    fn trusted_publisher_remove_scoped_to_package() {
        let db = test_db();
        let id = db
            .add_trusted_publisher("pkg-a", "github", "acme/pkg-a", None, None, "key1")
            .unwrap();
        db.add_trusted_publisher("pkg-b", "github", "acme/pkg-b", None, None, "key1")
            .unwrap();

        let deleted_wrong_package = db
            .remove_trusted_publisher_for_package("pkg-b", id)
            .unwrap();
        assert!(!deleted_wrong_package);

        let deleted_correct = db
            .remove_trusted_publisher_for_package("pkg-a", id)
            .unwrap();
        assert!(deleted_correct);
    }

    #[test]
    fn trusted_publisher_multiple() {
        let db = test_db();
        db.add_trusted_publisher("pkg", "github", "acme/pkg", None, None, "key1")
            .unwrap();
        db.add_trusted_publisher(
            "pkg",
            "gitlab",
            "acme/pkg",
            None,
            Some("production"),
            "key1",
        )
        .unwrap();

        let publishers = db.get_trusted_publishers("pkg").unwrap();
        assert_eq!(publishers.len(), 2);

        // Different package name returns empty.
        let other = db.get_trusted_publishers("other-pkg").unwrap();
        assert!(other.is_empty());
    }

    // -------------------------------------------------------------------
    // Download statistics tests
    // -------------------------------------------------------------------

    #[test]
    fn increment_download_counts() {
        let db = test_db();
        db.upsert_package("my-guard", Some("A guard"), "2025-01-01T00:00:00Z")
            .unwrap();

        let v = VersionRow {
            name: "my-guard".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "abc123".into(),
            manifest_toml: "[package]\nname = \"my-guard\"".into(),
            publisher_key: "pubkey_hex".into(),
            publisher_sig: "sig_hex".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: None,
            download_count: 0,
        };
        db.insert_version(&v).unwrap();

        db.increment_download("my-guard", "1.0.0").unwrap();
        db.increment_download("my-guard", "1.0.0").unwrap();
        db.increment_download("my-guard", "1.0.0").unwrap();

        let stats = db.get_package_stats("my-guard").unwrap().unwrap();
        assert_eq!(stats.total_downloads, 3);
        assert_eq!(stats.versions[0].downloads, 3);
    }

    #[test]
    fn migration_helper_propagates_non_duplicate_column_errors() {
        let db = test_db();
        execute_add_column_if_missing(
            &db.conn,
            "ALTER TABLE versions ADD COLUMN attestation_hash TEXT",
        )
        .expect("duplicate column should be ignored");
        let err =
            execute_add_column_if_missing(&db.conn, "ALTER TABLE versions ADD COLUMN").unwrap_err();
        assert!(
            matches!(err, RegistryError::Database(_)),
            "invalid migration SQL should not be swallowed"
        );
    }

    #[test]
    fn get_package_rejects_negative_total_downloads() {
        let db = test_db();
        db.conn
            .execute(
                "INSERT INTO packages (name, description, created_at, updated_at, total_downloads) VALUES (?1, ?2, ?3, ?4, ?5)",
                params!["bad-pkg", "bad", "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z", -1i64],
            )
            .unwrap();

        let err = db.get_package("bad-pkg").unwrap_err();
        assert!(matches!(err, RegistryError::Database(_)));
    }

    #[test]
    fn sqlite_i64_to_u64_maps_negative_values_to_database_error() {
        let err = sqlite_i64_to_u64(-1, "search.count").unwrap_err();
        assert!(matches!(err, RegistryError::Database(_)));
    }

    #[test]
    fn list_versions_rejects_negative_leaf_index_and_download_count() {
        let db = test_db();
        db.conn
            .execute(
                "INSERT INTO packages (name, description, created_at, updated_at, total_downloads) VALUES (?1, ?2, ?3, ?4, ?5)",
                params!["bad-version-pkg", "bad", "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z", 0i64],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO versions (name, version, pkg_type, checksum, manifest_toml, publisher_key, publisher_sig, registry_sig, dependencies_json, yanked, published_at, attestation_hash, key_id, leaf_index, download_count) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    "bad-version-pkg",
                    "1.0.0",
                    "guard",
                    "abc",
                    "",
                    "pk",
                    "sig",
                    Option::<String>::None,
                    "{}",
                    0i32,
                    "2025-01-01T00:00:00Z",
                    Option::<String>::None,
                    Option::<String>::None,
                    -1i64,
                    -1i64,
                ],
            )
            .unwrap();

        let err = db.list_versions("bad-version-pkg").unwrap_err();
        assert!(matches!(err, RegistryError::Database(_)));
    }

    #[test]
    fn update_leaf_index_rejects_values_out_of_i64_range() {
        let db = test_db();
        db.upsert_package("pkg", Some("A guard"), "2025-01-01T00:00:00Z")
            .unwrap();
        let v = VersionRow {
            name: "pkg".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "abc123".into(),
            manifest_toml: "".into(),
            publisher_key: "pubkey_hex".into(),
            publisher_sig: "sig_hex".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: None,
            download_count: 0,
        };
        db.insert_version(&v).unwrap();

        let err = db
            .update_leaf_index("pkg", "1.0.0", u64::MAX)
            .expect_err("out-of-range leaf index should fail");
        assert!(matches!(err, RegistryError::Integrity(_)));
    }

    #[test]
    fn get_popular_packages() {
        let db = test_db();

        db.upsert_package("pkg-a", Some("Package A"), "2025-01-01T00:00:00Z")
            .unwrap();
        let va = VersionRow {
            name: "pkg-a".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "aaa".into(),
            manifest_toml: "".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: None,
            download_count: 0,
        };
        db.insert_version(&va).unwrap();

        db.upsert_package("pkg-b", Some("Package B"), "2025-01-02T00:00:00Z")
            .unwrap();
        let vb = VersionRow {
            name: "pkg-b".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "bbb".into(),
            manifest_toml: "".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-02T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: None,
            download_count: 0,
        };
        db.insert_version(&vb).unwrap();

        // Download pkg-b more than pkg-a.
        db.increment_download("pkg-a", "1.0.0").unwrap();
        db.increment_download("pkg-b", "1.0.0").unwrap();
        db.increment_download("pkg-b", "1.0.0").unwrap();
        db.increment_download("pkg-b", "1.0.0").unwrap();

        let popular = db.get_popular_packages(10).unwrap();
        assert_eq!(popular.len(), 2);
        assert_eq!(popular[0].name, "pkg-b");
        assert_eq!(popular[0].total_downloads, 3);
        assert_eq!(popular[1].name, "pkg-a");
        assert_eq!(popular[1].total_downloads, 1);
    }

    #[test]
    fn package_stats_not_found() {
        let db = test_db();
        assert!(db.get_package_stats("nonexistent").unwrap().is_none());
    }
}
