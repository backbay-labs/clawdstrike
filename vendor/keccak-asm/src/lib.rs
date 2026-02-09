#![doc = include_str!("../README.md")]
#![no_std]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub use digest::{self, Digest};

use core::fmt;
#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
use digest::{
    block_buffer::Eager,
    consts::{U104, U136, U144, U28, U32, U48, U64, U72},
    core_api::{AlgorithmName, BlockSizeUser, BufferKindUser},
    typenum::Unsigned,
    FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset, Update,
};

#[macro_use]
mod macros;
mod state;
use state::Sha3State;

// Paddings
const KECCAK: u8 = 0x01;
const SHA3: u8 = 0x06;
// const SHAKE: u8 = 0x1f;
// const CSHAKE: u8 = 0x4;

impl_sha3!(Keccak224, U28, U144, KECCAK, "Keccak-224");
impl_sha3!(Keccak256, U32, U136, KECCAK, "Keccak-256");
impl_sha3!(Keccak384, U48, U104, KECCAK, "Keccak-384");
impl_sha3!(Keccak512, U64, U72, KECCAK, "Keccak-512");

// TODO: Block size is not derived from bits
// impl_sha3!(Keccak256Full, U200, U136, KECCAK, "SHA-3 CryptoNight variant");

impl_sha3!(Sha3_224, U28, U144, SHA3, "SHA-3-224", "2.16.840.1.101.3.4.2.7");
impl_sha3!(Sha3_256, U32, U136, SHA3, "SHA-3-256", "2.16.840.1.101.3.4.2.8");
impl_sha3!(Sha3_384, U48, U104, SHA3, "SHA-3-384", "2.16.840.1.101.3.4.2.9");
impl_sha3!(Sha3_512, U64, U72, SHA3, "SHA-3-512", "2.16.840.1.101.3.4.2.10");

#[doc(hidden)]
pub use sha3_asm::IMPL;
