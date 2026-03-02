package native

// InstructionLevel represents the privilege level of an instruction.
type InstructionLevel int

const (
	// InstructionLevelSystem is the highest privilege (system prompt).
	InstructionLevelSystem InstructionLevel = iota
	// InstructionLevelDeveloper is developer-provided instructions.
	InstructionLevelDeveloper
	// InstructionLevelUser is user-provided instructions.
	InstructionLevelUser
	// InstructionLevelExternal is externally sourced content (tools, RAG, etc.).
	InstructionLevelExternal
)

// HierarchyEnforcer wraps instruction hierarchy enforcement.
// This is a placeholder for future native implementation.
type HierarchyEnforcer struct {
	configJSON string
}

// NewHierarchyEnforcer creates a new HierarchyEnforcer with default config.
func NewHierarchyEnforcer() *HierarchyEnforcer {
	return &HierarchyEnforcer{}
}

// NewHierarchyEnforcerWithConfig creates a HierarchyEnforcer with a JSON config.
func NewHierarchyEnforcerWithConfig(configJSON string) *HierarchyEnforcer {
	return &HierarchyEnforcer{configJSON: configJSON}
}
