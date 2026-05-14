//! Action atom encoding for Logos formulas.
//!
//! Every [`GuardAction`](clawdstrike::guards::GuardAction) variant maps to a
//! family of atoms with a structured naming convention:
//!
//! ```text
//! access("/etc/shadow")     -- file access
//! write("/tmp/secrets.txt") -- file write
//! egress("api.openai.com")  -- network egress
//! exec("rm -rf /")          -- shell command execution
//! mcp("shell_exec")         -- MCP tool invocation
//! patch("/src/main.rs")     -- patch application
//! custom("my_action")       -- custom action type
//! ```
//!
//! In the Logos AST these are represented as [`Formula::Atom`] values with the
//! format `"type(param)"`.

use logos_ffi::Formula;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ActionKind {
    Access,
    Write,
    Egress,
    Exec,
    Mcp,
    Patch,
    Custom,
}

impl ActionKind {
    fn prefix(&self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Write => "write",
            Self::Egress => "egress",
            Self::Exec => "exec",
            Self::Mcp => "mcp",
            Self::Patch => "patch",
            Self::Custom => "custom",
        }
    }

    pub fn all() -> Vec<ActionKind> {
        vec![
            Self::Access,
            Self::Write,
            Self::Egress,
            Self::Exec,
            Self::Mcp,
            Self::Patch,
            Self::Custom,
        ]
    }

    /// The four action kinds every non-trivial policy should cover.
    pub fn core() -> Vec<ActionKind> {
        vec![Self::Access, Self::Egress, Self::Exec, Self::Mcp]
    }

    pub fn from_prefix(prefix: &str) -> Option<ActionKind> {
        match prefix {
            "access" => Some(Self::Access),
            "write" => Some(Self::Write),
            "egress" => Some(Self::Egress),
            "exec" => Some(Self::Exec),
            "mcp" => Some(Self::Mcp),
            "patch" => Some(Self::Patch),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
}

impl fmt::Display for ActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.prefix())
    }
}

/// A typed proposition for Logos formulas: `kind(param)`, e.g. `access(/etc/shadow)`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ActionAtom {
    pub kind: ActionKind,
    pub param: String,
}

impl ActionAtom {
    pub fn new(kind: ActionKind, param: impl Into<String>) -> Self {
        Self {
            kind,
            param: param.into(),
        }
    }

    pub fn access(path: impl Into<String>) -> Self {
        Self::new(ActionKind::Access, path)
    }

    pub fn write(path: impl Into<String>) -> Self {
        Self::new(ActionKind::Write, path)
    }

    pub fn egress(domain: impl Into<String>) -> Self {
        Self::new(ActionKind::Egress, domain)
    }

    pub fn exec(pattern: impl Into<String>) -> Self {
        Self::new(ActionKind::Exec, pattern)
    }

    pub fn mcp(tool: impl Into<String>) -> Self {
        Self::new(ActionKind::Mcp, tool)
    }

    pub fn patch(path: impl Into<String>) -> Self {
        Self::new(ActionKind::Patch, path)
    }

    pub fn custom(action_type: impl Into<String>) -> Self {
        Self::new(ActionKind::Custom, action_type)
    }

    #[must_use]
    pub fn atom_name(&self) -> String {
        format!("{}({})", self.kind.prefix(), self.param)
    }

    #[must_use]
    pub fn to_formula(&self) -> Formula {
        Formula::atom(self.atom_name())
    }
}

impl fmt::Display for ActionAtom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.kind.prefix(), self.param)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atom_name_format() {
        let atom = ActionAtom::access("/etc/shadow");
        assert_eq!(atom.atom_name(), "access(/etc/shadow)");
    }

    #[test]
    fn atom_display() {
        let atom = ActionAtom::egress("api.openai.com");
        assert_eq!(format!("{atom}"), "egress(api.openai.com)");
    }

    #[test]
    fn to_formula_roundtrip() {
        let atom = ActionAtom::exec("rm -rf /");
        let formula = atom.to_formula();
        assert_eq!(format!("{formula}"), "exec(rm -rf /)");
    }

    #[test]
    fn action_kind_display() {
        assert_eq!(format!("{}", ActionKind::Access), "access");
        assert_eq!(format!("{}", ActionKind::Mcp), "mcp");
        assert_eq!(format!("{}", ActionKind::Custom), "custom");
    }
}
