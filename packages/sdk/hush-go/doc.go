// Package hush provides Go bindings for ClawdStrike's security enforcement library.
//
// This package wraps the hush-ffi C library via cgo, providing idiomatic Go
// access to cryptographic operations (Ed25519, SHA-256, Keccak-256), receipt
// signing and verification, Merkle tree operations, jailbreak detection,
// output sanitization, and prompt watermarking.
//
// The native library (libhush_ffi) must be available on the library path.
package hush
