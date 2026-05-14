//! Proptest generators for differential testing.
//!
//! Uses pool-based string selection instead of regex strategies (~10x faster
//! at high case counts).

use proptest::prelude::*;
use std::collections::HashSet;

use crate::spec::SpecSeverity;
use crate::spec::SpecVerdict;

const GUARD_NAMES: &[&str] = &[
    "a",
    "ab",
    "abc",
    "guard",
    "check",
    "block",
    "allow",
    "scan",
    "policy",
    "deny",
    "egress",
    "secret",
    "patch",
    "shell",
    "mcp",
    "inject",
    "jailbreak",
    "spider",
    "cua",
    "rds",
];

const KEY_NAMES: &[&str] = &[
    "a.yaml",
    "bb.yaml",
    "ccc.yaml",
    "default.yaml",
    "strict.yaml",
    "perm.yaml",
    "agent.yaml",
    "cicd.yaml",
    "remote.yaml",
    "spider.yaml",
    "extra.yaml",
    "base.yaml",
    "child.yaml",
    "root.yaml",
    "leaf.yaml",
];

const SHORT_VALS: &[&str] = &[
    "a", "bb", "ccc", "dd", "eee", "f", "gg", "hhh", "ii", "jjj", "k", "ll", "mmm", "nn", "ooo",
    "p", "qq", "rrr", "ss", "ttt",
];

fn pool_guard(idx: usize) -> String {
    GUARD_NAMES[idx % GUARD_NAMES.len()].to_string()
}

fn pool_key(idx: usize) -> String {
    KEY_NAMES[idx % KEY_NAMES.len()].to_string()
}

fn pool_short(idx: usize) -> String {
    SHORT_VALS[idx % SHORT_VALS.len()].to_string()
}

pub fn arb_spec_severity() -> impl Strategy<Value = SpecSeverity> {
    prop_oneof![
        Just(SpecSeverity::Info),
        Just(SpecSeverity::Warning),
        Just(SpecSeverity::Error),
        Just(SpecSeverity::Critical),
    ]
}

pub fn arb_core_severity() -> impl Strategy<Value = clawdstrike::core::CoreSeverity> {
    prop_oneof![
        Just(clawdstrike::core::CoreSeverity::Info),
        Just(clawdstrike::core::CoreSeverity::Warning),
        Just(clawdstrike::core::CoreSeverity::Error),
        Just(clawdstrike::core::CoreSeverity::Critical),
    ]
}

pub fn arb_spec_verdict() -> impl Strategy<Value = SpecVerdict> {
    (
        any::<bool>(),
        arb_spec_severity(),
        any::<bool>(),
        0usize..GUARD_NAMES.len(),
    )
        .prop_map(|(allowed, severity, sanitized, guard_idx)| SpecVerdict {
            allowed,
            severity,
            sanitized,
            guard: pool_guard(guard_idx),
            message: String::new(),
        })
}

pub fn arb_core_verdict() -> impl Strategy<Value = clawdstrike::core::CoreVerdict> {
    (
        any::<bool>(),
        arb_core_severity(),
        any::<bool>(),
        0usize..GUARD_NAMES.len(),
    )
        .prop_map(
            |(allowed, severity, sanitized, guard_idx)| clawdstrike::core::CoreVerdict {
                allowed,
                severity,
                sanitized,
                guard: pool_guard(guard_idx),
                message: String::new(),
            },
        )
}

/// Paired (spec, impl) verdict from the same random seed.
pub fn arb_paired_verdict() -> impl Strategy<Value = (SpecVerdict, clawdstrike::core::CoreVerdict)>
{
    (
        any::<bool>(),
        0u8..4,
        any::<bool>(),
        0usize..GUARD_NAMES.len(),
    )
        .prop_map(|(allowed, sev_idx, sanitized, guard_idx)| {
            let spec_sev = match sev_idx {
                0 => SpecSeverity::Info,
                1 => SpecSeverity::Warning,
                2 => SpecSeverity::Error,
                _ => SpecSeverity::Critical,
            };
            let core_sev = match sev_idx {
                0 => clawdstrike::core::CoreSeverity::Info,
                1 => clawdstrike::core::CoreSeverity::Warning,
                2 => clawdstrike::core::CoreSeverity::Error,
                _ => clawdstrike::core::CoreSeverity::Critical,
            };

            let guard = pool_guard(guard_idx);
            let spec = SpecVerdict {
                allowed,
                severity: spec_sev,
                sanitized,
                guard: guard.clone(),
                message: String::new(),
            };
            let core = clawdstrike::core::CoreVerdict {
                allowed,
                severity: core_sev,
                sanitized,
                guard,
                message: String::new(),
            };
            (spec, core)
        })
}

pub fn arb_paired_verdicts(
) -> impl Strategy<Value = (Vec<SpecVerdict>, Vec<clawdstrike::core::CoreVerdict>)> {
    prop::collection::vec(arb_paired_verdict(), 1..50).prop_map(|pairs| {
        let (specs, cores): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        (specs, cores)
    })
}

pub fn arb_option_i32() -> impl Strategy<Value = Option<i32>> {
    prop_oneof![Just(None), any::<i32>().prop_map(Some)]
}

pub fn arb_option_pair() -> impl Strategy<Value = (Option<i32>, Option<i32>)> {
    (arb_option_i32(), arb_option_i32())
}

pub fn arb_nonempty_str() -> impl Strategy<Value = String> {
    (0usize..SHORT_VALS.len()).prop_map(pool_short)
}

pub fn arb_str_pair() -> impl Strategy<Value = (String, String)> {
    (
        prop_oneof![
            Just(String::new()),
            (0usize..SHORT_VALS.len()).prop_map(pool_short)
        ],
        prop_oneof![
            Just(String::new()),
            (0usize..SHORT_VALS.len()).prop_map(pool_short)
        ],
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyedItem {
    pub key: u8,
    pub value: String,
}

pub fn arb_keyed_item() -> impl Strategy<Value = KeyedItem> {
    (0u8..20, 0usize..SHORT_VALS.len()).prop_map(|(key, val_idx)| KeyedItem {
        key,
        value: pool_short(val_idx),
    })
}

pub fn arb_keyed_vec_pair() -> impl Strategy<Value = (Vec<KeyedItem>, Vec<KeyedItem>)> {
    (
        prop::collection::vec(arb_keyed_item(), 0..15),
        prop::collection::vec(arb_keyed_item(), 0..15),
    )
}

/// Like `arb_keyed_vec_pair` but deduplicates keys within each vector.
pub fn arb_unique_keyed_vec_pair() -> impl Strategy<Value = (Vec<KeyedItem>, Vec<KeyedItem>)> {
    arb_keyed_vec_pair().prop_map(|(base, child)| {
        fn dedup(items: Vec<KeyedItem>) -> Vec<KeyedItem> {
            let mut positions: [Option<usize>; 20] = [None; 20];
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let k = item.key as usize;
                if let Some(idx) = positions[k] {
                    out[idx] = item;
                } else {
                    positions[k] = Some(out.len());
                    out.push(item);
                }
            }
            out
        }
        (dedup(base), dedup(child))
    })
}

pub fn arb_key() -> impl Strategy<Value = String> {
    (0usize..KEY_NAMES.len()).prop_map(pool_key)
}

pub fn arb_visited_set() -> impl Strategy<Value = HashSet<String>> {
    prop::collection::hash_set(arb_key(), 0..10)
}

pub fn arb_depth() -> impl Strategy<Value = usize> {
    0usize..40
}

pub fn arb_cycle_scenario() -> impl Strategy<Value = (String, HashSet<String>, usize)> {
    (arb_key(), arb_visited_set(), arb_depth())
}

/// Scenario where the key is guaranteed to be in the visited set.
pub fn arb_cycle_present_scenario() -> impl Strategy<Value = (String, HashSet<String>, usize)> {
    // Generate 1..10 key indices, then pick one of them as the "present" key.
    // This avoids the expensive prop_flat_map + prop_filter pattern.
    (
        prop::collection::vec(0usize..KEY_NAMES.len(), 1..10),
        0usize..10,
        0usize..=32,
    )
        .prop_map(|(key_indices, pick_idx, depth)| {
            let mut set = HashSet::with_capacity(key_indices.len());
            for &idx in &key_indices {
                set.insert(pool_key(idx));
            }
            let present_key = pool_key(key_indices[pick_idx % key_indices.len()]);
            (present_key, set, depth)
        })
}
