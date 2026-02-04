/**
 * Receipt Types - Policy decision receipts with verification
 */

export interface Receipt {
  id: string;
  timestamp: string;
  policy_hash: string;
  event: ReceiptEvent;
  decision: ReceiptDecision;
  guards: GuardResult[];
  session_id?: string;
  agent_id?: string;
  metadata?: Record<string, unknown>;
}

export interface ReceiptEvent {
  event_id: string;
  event_type: string;
  action_type: string;
  target?: string;
  content_hash?: string;
}

export interface ReceiptDecision {
  allowed: boolean;
  denied: boolean;
  warn: boolean;
  reason?: string;
  severity?: string;
}

export interface GuardResult {
  guard_id: string;
  guard_name: string;
  allowed: boolean;
  denied: boolean;
  warn: boolean;
  severity?: string;
  message?: string;
  duration_ms?: number;
}

export interface SignedReceipt extends Receipt {
  signature: string;
  public_key: string;
  merkle_root?: string;
  merkle_proof?: MerkleProof;
}

export interface MerkleProof {
  leaf_hash: string;
  siblings: string[];
  path_bits: boolean[];
  root: string;
}

export interface ReceiptVerification {
  valid: boolean;
  signature_valid: boolean;
  merkle_valid?: boolean;
  timestamp_valid: boolean;
  policy_hash_match?: boolean;
  errors: string[];
}

export interface ReceiptBundle {
  receipts: SignedReceipt[];
  merkle_root: string;
  bundle_signature: string;
  signed_at: string;
}
