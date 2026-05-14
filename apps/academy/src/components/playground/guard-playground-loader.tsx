'use client';

import dynamic from 'next/dynamic';
import type { GuardName } from '@/lib/guards/types';
import { WASM_GUARDS, TS_GUARDS } from '@/lib/guards/types';

const PromptInjectionPlayground = dynamic(
  () => import('@/components/playground/prompt-injection-playground'),
  {
    ssr: false,
    loading: () => (
      <div className="h-64 animate-pulse bg-muted rounded-lg my-6" />
    ),
  }
);

const GenericGuardPlayground = dynamic(
  () => import('@/components/playground/generic-guard-playground'),
  {
    ssr: false,
    loading: () => (
      <div className="h-64 animate-pulse bg-muted rounded-lg my-6" />
    ),
  }
);

export interface GuardPlaygroundProps {
  guard?: GuardName;
  actionType?:
    | 'file_access'
    | 'file_write'
    | 'network_egress'
    | 'shell_command'
    | 'mcp_tool'
    | 'patch'
    | 'text'
    | 'custom';
  placeholder?: string;
  defaultInput?: string;
  defaultConfig?: Record<string, unknown>;
  examples?: { label: string; value: string }[];
  customActionType?: string;
}

export function GuardPlayground({
  guard,
  actionType = 'text',
  placeholder = 'Enter a value to evaluate...',
  defaultInput,
  defaultConfig,
  examples,
  customActionType,
}: GuardPlaygroundProps) {
  // No guard specified or prompt_injection: use the full-featured WASM playground
  if (!guard || guard === 'prompt_injection') {
    return <PromptInjectionPlayground />;
  }

  // Other WASM guards (jailbreak, spider_sense, etc.) use the generic playground
  // with actionType="text" so evaluateGuard dispatches to the correct WASM detector
  if (WASM_GUARDS.has(guard)) {
    return (
      <GenericGuardPlayground
        guard={guard}
        actionType="text"
        placeholder={placeholder}
        defaultInput={defaultInput}
        config={defaultConfig}
        examples={examples}
      />
    );
  }

  // TS-simulated guards use the generic playground
  if (TS_GUARDS.has(guard)) {
    return (
      <GenericGuardPlayground
        guard={guard}
        actionType={actionType}
        placeholder={placeholder}
        defaultInput={defaultInput}
        config={defaultConfig}
        examples={examples}
        customActionType={customActionType}
      />
    );
  }

  // Unknown guard -- fall back to prompt injection playground
  return <PromptInjectionPlayground />;
}
