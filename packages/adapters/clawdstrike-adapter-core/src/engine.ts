import type { Decision, PolicyEvent } from './types.js';

export interface PolicyEngineLike {
  evaluate(event: PolicyEvent): Promise<Decision> | Decision;
  redactSecrets?(value: string): string;
}

