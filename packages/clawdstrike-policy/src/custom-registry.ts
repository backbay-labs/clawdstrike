import type { PolicyEvent } from '@clawdstrike/adapter-core';

import type { GuardResult } from './async/types.js';

export interface CustomGuard {
  name: string;
  handles(event: PolicyEvent): boolean;
  check(event: PolicyEvent): GuardResult | Promise<GuardResult>;
}

export interface CustomGuardFactory {
  id: string;
  build(config: Record<string, unknown>): CustomGuard;
}

export class CustomGuardRegistry {
  private readonly factories = new Map<string, CustomGuardFactory>();

  register(factory: CustomGuardFactory): void {
    const id = factory.id;
    if (!id || typeof id !== 'string') {
      throw new Error('CustomGuardFactory.id must be a non-empty string');
    }
    if (this.factories.has(id)) {
      throw new Error(`duplicate custom guard factory id: ${id}`);
    }
    this.factories.set(id, factory);
  }

  build(id: string, config: Record<string, unknown>): CustomGuard {
    const factory = this.factories.get(id);
    if (!factory) {
      throw new Error(`unknown custom guard id: ${id}`);
    }
    return factory.build(config);
  }
}

