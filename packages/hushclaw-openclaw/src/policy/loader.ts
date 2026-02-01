import { load } from 'js-yaml';
import { readFile } from 'fs/promises';
import type { PolicyConfig } from './types.js';

export function loadPolicyFromString(content: string): PolicyConfig {
  const parsed = load(content);
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('Policy must be a YAML object');
  }
  return parsed as PolicyConfig;
}

export async function loadPolicy(path: string): Promise<PolicyConfig> {
  const content = await readFile(path, 'utf-8');
  return loadPolicyFromString(content);
}
