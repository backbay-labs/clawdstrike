//! Backend-owned workspace services for the Huntronomer desktop shell.

pub mod fs;
pub mod settings;
pub mod workspace;

pub use fs::{
    CreatePathKind, DeleteResult, FsService, MoveResult, WorkspaceEntry, WorkspaceEntryKind,
    WorkspaceFile, WriteResult,
};
pub use settings::{WorkspaceSettings, WorkspaceSettingsStore};
pub use workspace::{WorkspaceError, WorkspaceRoot, WorkspaceService};
