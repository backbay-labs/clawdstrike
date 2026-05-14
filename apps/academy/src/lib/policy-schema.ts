/**
 * JSON Schema for ClawdStrike policy v1.5.0.
 *
 * Hand-crafted to match the Rust `Policy` struct with `deny_unknown_fields`.
 * Every object definition sets `additionalProperties: false` to mirror Rust serde behaviour.
 */

export const policySchema = {
  title: 'ClawdStrike Policy',
  description: 'Policy configuration for ClawdStrike runtime security enforcement (schema v1.5.0)',
  type: 'object',
  additionalProperties: false,
  properties: {
    version: {
      type: 'string',
      enum: ['1.1.0', '1.2.0', '1.3.0', '1.4.0', '1.5.0'],
      description: 'Policy schema version',
    },
    name: {
      type: 'string',
      description: 'Policy name',
    },
    description: {
      type: 'string',
      description: 'Policy description',
    },
    extends: {
      type: 'string',
      description: 'Base ruleset to extend (built-in name, file path, URL, or git ref)',
    },
    merge_strategy: {
      type: 'string',
      enum: ['replace', 'merge', 'deep_merge'],
      description: 'Strategy for merging with base policy',
    },
    guards: { $ref: '#/definitions/GuardConfigs' },
    custom_guards: {
      type: 'array',
      items: { $ref: '#/definitions/PolicyCustomGuardSpec' },
      description: 'Custom guard specifications',
    },
    settings: { $ref: '#/definitions/PolicySettings' },
    posture: {
      type: 'object',
      description: 'Posture configuration (schema varies by posture provider)',
    },
    origins: {
      type: 'object',
      description: 'Origin enclave profiles',
    },
    broker: {
      type: 'object',
      description: 'Secret broker configuration',
    },
  },
  definitions: {
    GuardConfigs: {
      type: 'object',
      additionalProperties: false,
      description: 'Guard configurations for all 13 built-in guards plus custom array',
      properties: {
        forbidden_path: { $ref: '#/definitions/ForbiddenPathConfig' },
        path_allowlist: { $ref: '#/definitions/PathAllowlistConfig' },
        egress_allowlist: { $ref: '#/definitions/EgressAllowlistConfig' },
        secret_leak: { $ref: '#/definitions/SecretLeakConfig' },
        patch_integrity: { $ref: '#/definitions/PatchIntegrityConfig' },
        shell_command: { $ref: '#/definitions/ShellCommandConfig' },
        mcp_tool: { $ref: '#/definitions/McpToolConfig' },
        prompt_injection: { $ref: '#/definitions/PromptInjectionConfig' },
        jailbreak: { $ref: '#/definitions/JailbreakConfig' },
        computer_use: { $ref: '#/definitions/ComputerUseConfig' },
        remote_desktop_side_channel: { $ref: '#/definitions/RemoteDesktopSideChannelConfig' },
        input_injection_capability: { $ref: '#/definitions/InputInjectionCapabilityConfig' },
        spider_sense: { $ref: '#/definitions/SpiderSenseConfig' },
        custom: {
          type: 'array',
          items: { $ref: '#/definitions/CustomGuardSpec' },
          description: 'Custom guard specs',
        },
      },
    },

    ForbiddenPathConfig: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        patterns: { type: 'array', items: { type: 'string' } },
        exceptions: { type: 'array', items: { type: 'string' } },
        additional_patterns: { type: 'array', items: { type: 'string' } },
        remove_patterns: { type: 'array', items: { type: 'string' } },
      },
    },

    PathAllowlistConfig: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        allowed_paths: { type: 'array', items: { type: 'string' } },
      },
    },

    EgressAllowlistConfig: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        allow: { type: 'array', items: { type: 'string' } },
        block: { type: 'array', items: { type: 'string' } },
        default_action: { type: 'string', enum: ['allow', 'block'] },
      },
    },

    SecretLeakConfig: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        patterns: {
          type: 'array',
          items: { $ref: '#/definitions/SecretLeakPattern' },
        },
        skip_paths: { type: 'array', items: { type: 'string' } },
      },
    },

    SecretLeakPattern: {
      type: 'object',
      additionalProperties: false,
      properties: {
        name: { type: 'string' },
        pattern: { type: 'string' },
        severity: { type: 'string', enum: ['info', 'warning', 'error', 'critical'] },
      },
      required: ['name', 'pattern', 'severity'],
    },

    ShellCommandConfig: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        blocked_commands: { type: 'array', items: { type: 'string' } },
        blocked_patterns: { type: 'array', items: { type: 'string' } },
        allowed_commands: { type: 'array', items: { type: 'string' } },
      },
    },

    McpToolConfig: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        allow: { type: 'array', items: { type: 'string' } },
        block: { type: 'array', items: { type: 'string' } },
        require_confirmation: { type: 'array', items: { type: 'string' } },
        default_action: { type: 'string', enum: ['allow', 'block'] },
        max_args_size: { type: 'integer', minimum: 0 },
      },
    },

    PatchIntegrityConfig: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        max_additions: { type: 'integer', minimum: 0 },
        max_deletions: { type: 'integer', minimum: 0 },
        require_balance: { type: 'boolean' },
        max_imbalance_ratio: { type: 'number', minimum: 0 },
        forbidden_patterns: { type: 'array', items: { type: 'string' } },
      },
    },

    PromptInjectionConfig: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        threshold: { type: 'number', minimum: 0, maximum: 1 },
        max_scan_bytes: { type: 'integer', minimum: 0 },
        warn_at_or_above: { type: 'string' },
        block_at_or_above: { type: 'string' },
      },
    },

    JailbreakConfig: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        threshold: { type: 'number', minimum: 0, maximum: 1 },
        layers: { type: 'object' },
        detector: { type: 'object' },
      },
    },

    ComputerUseConfig: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        mode: { type: 'string' },
        allowed_actions: { type: 'array', items: { type: 'string' } },
        blocked_actions: { type: 'array', items: { type: 'string' } },
      },
    },

    RemoteDesktopSideChannelConfig: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        clipboard: { type: 'object' },
        audio: { type: 'object' },
        drive_mapping: { type: 'object' },
        file_transfer: { type: 'object' },
        clipboard_enabled: { type: 'boolean' },
        file_transfer_enabled: { type: 'boolean' },
        audio_enabled: { type: 'boolean' },
        drive_mapping_enabled: { type: 'boolean' },
        printing_enabled: { type: 'boolean' },
        session_share_enabled: { type: 'boolean' },
        max_transfer_size_bytes: { type: 'integer', minimum: 0 },
      },
    },

    InputInjectionCapabilityConfig: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        allowed_capabilities: { type: 'array', items: { type: 'string' } },
        blocked_capabilities: { type: 'array', items: { type: 'string' } },
        allowed_input_types: { type: 'array', items: { type: 'string' } },
        require_postcondition_probe: { type: 'boolean' },
      },
    },

    SpiderSenseConfig: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        threshold: { type: 'number' },
        pattern_db_path: { type: 'string' },
        embedding_api_url: { type: 'string' },
        embedding_api_key: { type: 'string' },
        embedding_model: { type: 'string' },
        similarity_threshold: { type: 'number' },
        ambiguity_band: { type: 'number' },
        top_k: { type: 'integer', minimum: 1 },
        pattern_db_version: { type: 'string' },
        pattern_db_checksum: { type: 'string' },
      },
    },

    CustomGuardSpec: {
      type: 'object',
      additionalProperties: false,
      properties: {
        package: { type: 'string' },
        version: { type: 'string' },
        config: { type: 'object' },
      },
    },

    PolicyCustomGuardSpec: {
      type: 'object',
      additionalProperties: false,
      properties: {
        id: { type: 'string' },
        enabled: { type: 'boolean' },
        config: { type: 'object' },
      },
      required: ['id'],
    },

    PolicySettings: {
      type: 'object',
      additionalProperties: false,
      properties: {
        fail_fast: { type: 'boolean' },
        verbose_logging: { type: 'boolean' },
        session_timeout_secs: { type: 'integer', minimum: 0 },
      },
    },
  },
} as const;
