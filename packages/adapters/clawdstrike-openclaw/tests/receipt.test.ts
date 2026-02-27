/**
 * @clawdstrike/openclaw - Receipt/Attestation Tests
 */

import { describe, it, expect } from 'vitest';
import { ReceiptSigner } from '../src/receipt/signer.js';
import type { DecisionReceipt } from '../src/receipt/types.js';
import type { Decision, PolicyEvent } from '../src/types.js';

/** Helper to create a sample Decision */
function makeDenyDecision(): Decision {
  return {
    status: 'deny',
    reason_code: 'FORBIDDEN_PATH',
    guard: 'forbidden_path',
    severity: 'high',
    message: 'Access to SSH key denied',
    reason: 'Path matches forbidden pattern',
  };
}

function makeAllowDecision(): Decision {
  return {
    status: 'allow',
    guard: 'egress_allowlist',
    message: 'Egress permitted',
  };
}

/** Helper to create a sample PolicyEvent */
function makeToolEvent(): PolicyEvent {
  return {
    eventId: 'evt-001',
    eventType: 'tool_call',
    timestamp: new Date().toISOString(),
    sessionId: 'session-abc',
    data: {
      type: 'tool',
      toolName: 'read_file',
      parameters: { path: '/etc/passwd' },
    },
  };
}

function makeFileEvent(): PolicyEvent {
  return {
    eventId: 'evt-002',
    eventType: 'file_read',
    timestamp: new Date().toISOString(),
    data: {
      type: 'file',
      path: '/home/user/.ssh/id_rsa',
      operation: 'read',
    },
  };
}

const SAMPLE_POLICY_HASH = ReceiptSigner.hashPolicy({ version: '1.1.0', guards: {} });

describe('ReceiptSigner', () => {
  describe('createReceipt', () => {
    it('should return a valid DecisionReceipt', () => {
      const signer = new ReceiptSigner();
      const receipt = signer.createReceipt(
        makeDenyDecision(),
        makeToolEvent(),
        SAMPLE_POLICY_HASH,
      );

      expect(receipt).not.toBeNull();
      const r = receipt as DecisionReceipt;

      expect(r.id).toBeDefined();
      expect(typeof r.id).toBe('string');
      expect(r.id.length).toBeGreaterThan(0);
    });

    it('should have correct structure', () => {
      const signer = new ReceiptSigner();
      const receipt = signer.createReceipt(
        makeDenyDecision(),
        makeToolEvent(),
        SAMPLE_POLICY_HASH,
      ) as DecisionReceipt;

      // Required fields
      expect(receipt).toHaveProperty('id');
      expect(receipt).toHaveProperty('timestamp');
      expect(receipt).toHaveProperty('policyHash');
      expect(receipt).toHaveProperty('decision');
      expect(receipt).toHaveProperty('event');
      expect(receipt).toHaveProperty('signature');
      expect(receipt).toHaveProperty('algorithm');
      expect(receipt).toHaveProperty('keyId');
    });

    it('should include ISO 8601 timestamp', () => {
      const signer = new ReceiptSigner();
      const before = new Date().toISOString();
      const receipt = signer.createReceipt(
        makeDenyDecision(),
        makeToolEvent(),
        SAMPLE_POLICY_HASH,
      ) as DecisionReceipt;
      const after = new Date().toISOString();

      // Timestamp should be parseable and within the window
      const ts = new Date(receipt.timestamp);
      expect(ts.getTime()).toBeGreaterThanOrEqual(new Date(before).getTime());
      expect(ts.getTime()).toBeLessThanOrEqual(new Date(after).getTime());
    });

    it('should include the policy hash', () => {
      const signer = new ReceiptSigner();
      const receipt = signer.createReceipt(
        makeDenyDecision(),
        makeToolEvent(),
        SAMPLE_POLICY_HASH,
      ) as DecisionReceipt;

      expect(receipt.policyHash).toBe(SAMPLE_POLICY_HASH);
    });

    it('should include decision status and guard name', () => {
      const signer = new ReceiptSigner();
      const decision = makeDenyDecision();
      const receipt = signer.createReceipt(
        decision,
        makeToolEvent(),
        SAMPLE_POLICY_HASH,
      ) as DecisionReceipt;

      expect(receipt.decision.status).toBe('deny');
      expect(receipt.decision.guard).toBe('forbidden_path');
      expect(receipt.decision.reason).toBe('Path matches forbidden pattern');
    });

    it('should include event type and tool name for tool events', () => {
      const signer = new ReceiptSigner();
      const receipt = signer.createReceipt(
        makeDenyDecision(),
        makeToolEvent(),
        SAMPLE_POLICY_HASH,
      ) as DecisionReceipt;

      expect(receipt.event.type).toBe('tool_call');
      expect(receipt.event.toolName).toBe('read_file');
      expect(receipt.event.resource).toBe('read_file');
    });

    it('should extract resource from file events', () => {
      const signer = new ReceiptSigner();
      const receipt = signer.createReceipt(
        makeDenyDecision(),
        makeFileEvent(),
        SAMPLE_POLICY_HASH,
      ) as DecisionReceipt;

      expect(receipt.event.type).toBe('file_read');
      expect(receipt.event.resource).toBe('/home/user/.ssh/id_rsa');
      expect(receipt.event.toolName).toBeUndefined();
    });

    it('should always use EdDSA algorithm', () => {
      const signer = new ReceiptSigner();
      const receipt = signer.createReceipt(
        makeAllowDecision(),
        makeToolEvent(),
        SAMPLE_POLICY_HASH,
      ) as DecisionReceipt;

      expect(receipt.algorithm).toBe('EdDSA');
    });

    it('should produce unsigned stubs (signature and keyId are null)', () => {
      const signer = new ReceiptSigner();
      const receipt = signer.createReceipt(
        makeDenyDecision(),
        makeToolEvent(),
        SAMPLE_POLICY_HASH,
      ) as DecisionReceipt;

      expect(receipt.signature).toBeNull();
      expect(receipt.keyId).toBeNull();
    });

    it('should generate unique IDs for each receipt', () => {
      const signer = new ReceiptSigner();
      const ids = new Set<string>();

      for (let i = 0; i < 100; i++) {
        const receipt = signer.createReceipt(
          makeDenyDecision(),
          makeToolEvent(),
          SAMPLE_POLICY_HASH,
        ) as DecisionReceipt;
        ids.add(receipt.id);
      }

      expect(ids.size).toBe(100);
    });
  });

  describe('disabled signer', () => {
    it('should return null when receipts are disabled', () => {
      const signer = new ReceiptSigner({ enabled: false });
      const receipt = signer.createReceipt(
        makeDenyDecision(),
        makeToolEvent(),
        SAMPLE_POLICY_HASH,
      );

      expect(receipt).toBeNull();
    });
  });

  describe('hashPolicy', () => {
    it('should produce consistent SHA-256 for the same input', () => {
      const policy = { version: '1.1.0', guards: { forbidden_path: true } };
      const hash1 = ReceiptSigner.hashPolicy(policy);
      const hash2 = ReceiptSigner.hashPolicy(policy);

      expect(hash1).toBe(hash2);
    });

    it('should produce a 64-character hex string (SHA-256)', () => {
      const hash = ReceiptSigner.hashPolicy({ version: '1.1.0' });

      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should produce different hashes for different inputs', () => {
      const hash1 = ReceiptSigner.hashPolicy({ version: '1.1.0' });
      const hash2 = ReceiptSigner.hashPolicy({ version: '2.0.0' });

      expect(hash1).not.toBe(hash2);
    });

    it('should produce the same hash regardless of key order', () => {
      const hash1 = ReceiptSigner.hashPolicy({ a: 1, b: 2 });
      const hash2 = ReceiptSigner.hashPolicy({ b: 2, a: 1 });

      expect(hash1).toBe(hash2);
    });

    it('should handle nested objects with canonical key ordering', () => {
      const hash1 = ReceiptSigner.hashPolicy({ outer: { z: 1, a: 2 } });
      const hash2 = ReceiptSigner.hashPolicy({ outer: { a: 2, z: 1 } });

      expect(hash1).toBe(hash2);
    });
  });

  describe('verify', () => {
    it('should return true for unsigned receipts', () => {
      const signer = new ReceiptSigner();
      const receipt = signer.createReceipt(
        makeDenyDecision(),
        makeToolEvent(),
        SAMPLE_POLICY_HASH,
      ) as DecisionReceipt;

      expect(ReceiptSigner.verify(receipt)).toBe(true);
    });

    it('should return false for receipts with a signature (no WASM verifier)', () => {
      const signer = new ReceiptSigner();
      const receipt = signer.createReceipt(
        makeDenyDecision(),
        makeToolEvent(),
        SAMPLE_POLICY_HASH,
      ) as DecisionReceipt;

      // Simulate a signed receipt
      receipt.signature = 'fake-signature-value';
      receipt.keyId = 'key-001';

      expect(ReceiptSigner.verify(receipt)).toBe(false);
    });
  });
});
