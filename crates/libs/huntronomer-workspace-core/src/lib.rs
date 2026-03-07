//! Backend-owned workspace services for the Huntronomer desktop shell.

pub mod fs;
pub mod proc;
pub mod search;
pub mod settings;
pub mod watch;
pub mod workspace;

pub use fs::{
    CreatePathKind, DeleteResult, FsService, MoveResult, WorkspaceEntry, WorkspaceEntryKind,
    WorkspaceFile, WriteResult,
};
pub use proc::{
    AllowedSidecar, ProcService, SidecarExit, SidecarProcessHandle, SpawnSidecarRequest,
};
pub use search::{
    ContentSearchMatch, PathSearchMatch, SearchJobHandle, SearchJobKind, SearchService,
    SearchSummary, WorkspaceSearchEvent, WorkspaceSearchEventKind,
};
pub use settings::{WorkspaceSettings, WorkspaceSettingsStore};
pub use watch::{WatchService, WorkspaceFsEvent, WorkspaceFsEventKind};
pub use workspace::{WorkspaceError, WorkspaceRoot, WorkspaceService};
