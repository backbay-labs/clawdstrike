pub mod extensions;
pub mod merge;
pub mod rules;
pub mod schema;
pub mod validate;
pub mod version;

pub use extensions::Extensions;
pub use merge::merge;
pub use rules::*;
pub use schema::HushSpec;
pub use validate::{ValidationError, ValidationResult, validate};
pub use version::HUSHSPEC_VERSION;
