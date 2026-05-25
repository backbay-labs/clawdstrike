pub mod conditions;
pub mod detection;
pub mod evaluate;
pub mod extensions;
mod generated_contract;
mod generated_models;
pub mod governance;
pub mod merge;
pub mod panic;
pub mod receipt;
pub mod resolve;
pub mod rules;
pub mod schema;
#[cfg(feature = "signing")]
pub mod signing;
pub mod sink;
pub mod validate;
pub mod version;

pub use conditions::{Condition, RuntimeContext, TimeWindowCondition, evaluate_condition};
pub use detection::{
    DetectionCategory, DetectionConfig, DetectionResult, Detector, DetectorRegistry,
    EvaluationWithDetection, MatchedPattern, RegexExfiltrationDetector, RegexInjectionDetector,
    RegexJailbreakDetector, evaluate_with_detection,
};
pub use evaluate::{
    Decision, EvaluationAction, EvaluationResult, OriginContext, PostureContext, PostureResult,
    evaluate, evaluate_with_context,
};
pub use extensions::Extensions;
pub use governance::{GovernanceWarning, validate_governance};
pub use merge::merge;
pub use panic::{
    activate_panic, check_panic_sentinel, deactivate_panic, is_panic_active, panic_policy,
};
pub use receipt::{AuditConfig, DecisionReceipt, evaluate_audited};
pub use resolve::{
    BUILTIN_NAMES, LoadedSpec, ResolveError, create_composite_loader, load_builtin,
    resolve_from_path, resolve_from_path_with_builtins, resolve_with_loader,
};
pub use rules::*;
pub use schema::HushSpec;
pub use sink::{
    CallbackSink, FileReceiptSink, FilteredSink, MultiSink, NullSink, ReceiptSink, SinkError,
    StderrReceiptSink,
};
pub use validate::{ValidationError, ValidationResult, validate};
pub use version::HUSHSPEC_VERSION;
