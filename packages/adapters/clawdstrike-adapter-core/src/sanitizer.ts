import type { SecurityContext } from './context.js';

export interface RedactionInfo {
  type: 'secret' | 'pii' | 'sensitive';
  pattern: string;
  location?: string;
}

export interface OutputSanitizer<T = unknown> {
  sanitize(output: T, context: SecurityContext): T;
  containsSensitive(output: T): boolean;
  getRedactions(output: T): RedactionInfo[];
}

