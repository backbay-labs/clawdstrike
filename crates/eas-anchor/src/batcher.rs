//! Attestation batching logic for the EAS anchor service.
//!
//! Collects pending checkpoint attestations and flushes them in batches
//! based on size limits and time intervals.

use std::time::{Duration, Instant};

/// A pending attestation waiting to be anchored on-chain.
#[derive(Debug, Clone)]
pub struct PendingAttestation {
    /// SHA-256 checkpoint hash (32 bytes).
    pub checkpoint_hash: [u8; 32],
    /// Monotonic checkpoint sequence number.
    pub checkpoint_seq: u64,
    /// Merkle tree size at this checkpoint.
    pub tree_size: u64,
    /// Ed25519 public key of the log operator (32 bytes).
    pub log_operator_key: [u8; 32],
    /// Ed25519 public key of the witness (32 bytes).
    pub witness_key: [u8; 32],
    /// When this attestation was received.
    pub received_at: Instant,
}

/// Batches pending attestations for efficient on-chain submission.
pub struct AttestationBatcher {
    pending: Vec<PendingAttestation>,
    max_batch_size: usize,
    batch_interval: Duration,
    last_flush: Instant,
}

impl AttestationBatcher {
    /// Create a new batcher with the given size limit and flush interval.
    pub fn new(max_batch_size: usize, batch_interval: Duration) -> Self {
        Self {
            pending: Vec::new(),
            max_batch_size,
            batch_interval,
            last_flush: Instant::now(),
        }
    }

    /// Add a pending attestation to the batch.
    pub fn add(&mut self, attestation: PendingAttestation) {
        self.pending.push(attestation);
    }

    /// Returns `true` if the batch should be flushed (size limit reached
    /// or interval elapsed with pending items).
    pub fn should_flush(&self) -> bool {
        self.pending.len() >= self.max_batch_size
            || (!self.pending.is_empty() && self.last_flush.elapsed() >= self.batch_interval)
    }

    /// Drain all pending attestations and reset the flush timer.
    pub fn drain(&mut self) -> Vec<PendingAttestation> {
        self.last_flush = Instant::now();
        std::mem::take(&mut self.pending)
    }

    /// Number of pending attestations.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether there are no pending attestations.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Time remaining until the next interval-based flush.
    pub fn time_until_flush(&self) -> Duration {
        self.batch_interval
            .checked_sub(self.last_flush.elapsed())
            .unwrap_or(Duration::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_attestation(seq: u64) -> PendingAttestation {
        PendingAttestation {
            checkpoint_hash: [seq as u8; 32],
            checkpoint_seq: seq,
            tree_size: seq * 10,
            log_operator_key: [0xAA; 32],
            witness_key: [0xBB; 32],
            received_at: Instant::now(),
        }
    }

    #[test]
    fn empty_batcher_does_not_flush() {
        let batcher = AttestationBatcher::new(10, Duration::from_secs(300));
        assert!(!batcher.should_flush());
        assert!(batcher.is_empty());
        assert_eq!(batcher.len(), 0);
    }

    #[test]
    fn flush_on_max_batch_size() {
        let mut batcher = AttestationBatcher::new(3, Duration::from_secs(300));
        batcher.add(make_attestation(1));
        batcher.add(make_attestation(2));
        assert!(!batcher.should_flush());
        assert_eq!(batcher.len(), 2);

        batcher.add(make_attestation(3));
        assert!(batcher.should_flush());
        assert_eq!(batcher.len(), 3);
    }

    #[test]
    fn drain_returns_all_and_resets() {
        let mut batcher = AttestationBatcher::new(10, Duration::from_secs(300));
        batcher.add(make_attestation(1));
        batcher.add(make_attestation(2));
        batcher.add(make_attestation(3));

        let drained = batcher.drain();
        assert_eq!(drained.len(), 3);
        assert!(batcher.is_empty());
        assert!(!batcher.should_flush());

        // Verify data integrity
        assert_eq!(drained[0].checkpoint_seq, 1);
        assert_eq!(drained[1].checkpoint_seq, 2);
        assert_eq!(drained[2].checkpoint_seq, 3);
    }

    #[test]
    fn drain_on_empty_returns_empty_vec() {
        let mut batcher = AttestationBatcher::new(10, Duration::from_secs(300));
        let drained = batcher.drain();
        assert!(drained.is_empty());
    }

    #[test]
    fn flush_on_time_interval() {
        let mut batcher = AttestationBatcher::new(100, Duration::from_millis(0));
        batcher.add(make_attestation(1));
        // With zero interval, should flush immediately if there are pending items
        assert!(batcher.should_flush());
    }

    #[test]
    fn no_flush_without_pending_even_after_interval() {
        let batcher = AttestationBatcher::new(100, Duration::from_millis(0));
        // Even with zero interval, no flush if empty
        assert!(!batcher.should_flush());
    }

    #[test]
    fn time_until_flush_decreases() {
        let batcher = AttestationBatcher::new(10, Duration::from_secs(300));
        let remaining = batcher.time_until_flush();
        // Should be close to 300 seconds (within a reasonable margin)
        assert!(remaining.as_secs() <= 300);
    }

    #[test]
    fn batch_preserves_attestation_data() {
        let mut batcher = AttestationBatcher::new(10, Duration::from_secs(300));
        let att = PendingAttestation {
            checkpoint_hash: [0x42; 32],
            checkpoint_seq: 999,
            tree_size: 5000,
            log_operator_key: [0x11; 32],
            witness_key: [0x22; 32],
            received_at: Instant::now(),
        };
        batcher.add(att);

        let drained = batcher.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].checkpoint_hash, [0x42; 32]);
        assert_eq!(drained[0].checkpoint_seq, 999);
        assert_eq!(drained[0].tree_size, 5000);
        assert_eq!(drained[0].log_operator_key, [0x11; 32]);
        assert_eq!(drained[0].witness_key, [0x22; 32]);
    }

    #[test]
    fn multiple_drain_cycles() {
        let mut batcher = AttestationBatcher::new(2, Duration::from_secs(300));

        // First cycle
        batcher.add(make_attestation(1));
        batcher.add(make_attestation(2));
        assert!(batcher.should_flush());
        let first = batcher.drain();
        assert_eq!(first.len(), 2);

        // Second cycle
        batcher.add(make_attestation(3));
        assert!(!batcher.should_flush());
        batcher.add(make_attestation(4));
        assert!(batcher.should_flush());
        let second = batcher.drain();
        assert_eq!(second.len(), 2);
        assert_eq!(second[0].checkpoint_seq, 3);
        assert_eq!(second[1].checkpoint_seq, 4);
    }
}
