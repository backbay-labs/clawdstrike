package guards

// LocalOriginUnsupportedMessage is returned when a caller requests origin-aware
// evaluation against a checker that cannot persist origin runtime state.
const LocalOriginUnsupportedMessage = "origin-aware evaluation is not supported by the local Go engine; use a daemon-backed Clawdstrike instance"

// OriginRuntimeCapable marks checkers that can safely evaluate origin-aware
// requests with session-scoped runtime state.
type OriginRuntimeCapable interface {
	SupportsOriginRuntime() bool
}

// IsOriginAwareRequest returns true when the request requires origin runtime
// support, either because origin context is present or because the action is an
// origin-aware custom action.
func IsOriginAwareRequest(action GuardAction, ctx *GuardContext) bool {
	return (ctx != nil && ctx.Origin != nil) ||
		(action.Type == "custom" && action.CustomType == "origin.output_send")
}

// SupportsOriginRuntime reports whether the checker advertises support for
// origin-aware runtime evaluation.
func SupportsOriginRuntime(value any) bool {
	capable, ok := value.(OriginRuntimeCapable)
	return ok && capable.SupportsOriginRuntime()
}
