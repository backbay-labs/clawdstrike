//! Merkle tree root computation, proof generation, and proof verification FFI functions.

use std::ffi::{c_char, CStr};

use hush_core::hashing::Hash;
use hush_core::merkle::MerkleTree;

use crate::error::{ffi_try, set_last_error};

fn merkle_tree_from_leaf_hashes_json(json_str: &str) -> Result<MerkleTree, String> {
    let hex_strs: Vec<String> = serde_json::from_str(json_str).map_err(|e| e.to_string())?;

    let hashes: Vec<Hash> = hex_strs
        .iter()
        .map(|h| Hash::from_hex(h).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;

    MerkleTree::from_hashes(hashes).map_err(|e| e.to_string())
}

/// Compute the Merkle root from a JSON array of hex-encoded leaf hashes.
///
/// Returns a hex-encoded root hash with `0x` prefix.
/// Caller must free the returned string with `hush_free_string`.
/// Returns `NULL` on error.
///
/// # Safety
///
/// `leaf_hashes_json` must be a valid NUL-terminated C string containing
/// a JSON array of hex-encoded hash strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_merkle_root(leaf_hashes_json: *const c_char) -> *mut c_char {
    crate::error::with_ffi_guard(
        || {
            if leaf_hashes_json.is_null() {
                set_last_error("null pointer");
                return std::ptr::null_mut();
            }

            let json_str = ffi_try!(
                unsafe { CStr::from_ptr(leaf_hashes_json) }.to_str(),
                std::ptr::null_mut()
            );

            let tree = ffi_try!(
                merkle_tree_from_leaf_hashes_json(json_str),
                std::ptr::null_mut()
            );

            crate::string_to_c(tree.root().to_hex_prefixed())
        },
        std::ptr::null_mut(),
    )
}

/// Generate a Merkle inclusion proof for a leaf at the given index.
///
/// Returns a JSON-serialized `MerkleProof`.
/// Caller must free the returned string with `hush_free_string`.
/// Returns `NULL` on error.
///
/// # Safety
///
/// `leaf_hashes_json` must be a valid NUL-terminated C string containing
/// a JSON array of hex-encoded hash strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_merkle_proof(
    leaf_hashes_json: *const c_char,
    index: usize,
) -> *mut c_char {
    crate::error::with_ffi_guard(
        || {
            if leaf_hashes_json.is_null() {
                set_last_error("null pointer");
                return std::ptr::null_mut();
            }

            let json_str = ffi_try!(
                unsafe { CStr::from_ptr(leaf_hashes_json) }.to_str(),
                std::ptr::null_mut()
            );

            let tree = ffi_try!(
                merkle_tree_from_leaf_hashes_json(json_str),
                std::ptr::null_mut()
            );
            let proof = ffi_try!(tree.inclusion_proof(index), std::ptr::null_mut());
            let json = ffi_try!(serde_json::to_string(&proof), std::ptr::null_mut());
            crate::string_to_c(json)
        },
        std::ptr::null_mut(),
    )
}

/// Verify a Merkle inclusion proof.
///
/// Returns 1 if valid, 0 if invalid, -1 on error.
///
/// # Safety
///
/// - `leaf_hex` must be a valid NUL-terminated C string (hex-encoded hash).
/// - `proof_json` must be a valid NUL-terminated C string (JSON-serialized `MerkleProof`).
/// - `root_hex` must be a valid NUL-terminated C string (hex-encoded root hash).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hush_verify_merkle_proof(
    leaf_hex: *const c_char,
    proof_json: *const c_char,
    root_hex: *const c_char,
) -> i32 {
    crate::error::with_ffi_guard(
        || {
            if leaf_hex.is_null() || proof_json.is_null() || root_hex.is_null() {
                set_last_error("null pointer");
                return -1;
            }

            let leaf_str = ffi_try!(unsafe { CStr::from_ptr(leaf_hex) }.to_str(), -1);
            let proof_str = ffi_try!(unsafe { CStr::from_ptr(proof_json) }.to_str(), -1);
            let root_str = ffi_try!(unsafe { CStr::from_ptr(root_hex) }.to_str(), -1);

            let leaf = ffi_try!(Hash::from_hex(leaf_str), -1);
            let root = ffi_try!(Hash::from_hex(root_str), -1);
            let proof: hush_core::MerkleProof = ffi_try!(serde_json::from_str(proof_str), -1);

            i32::from(proof.verify_hash(leaf, &root))
        },
        -1,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hush_core::hashing::sha256;

    fn make_leaf_hashes_json(count: usize) -> String {
        let hashes: Vec<String> = (0..count)
            .map(|i| sha256(format!("leaf{}", i).as_bytes()).to_hex_prefixed())
            .collect();
        serde_json::to_string(&hashes).unwrap()
    }

    #[test]
    fn test_merkle_root() {
        let json = make_leaf_hashes_json(4);
        let c_json = std::ffi::CString::new(json).unwrap();
        let root_ptr = unsafe { hush_merkle_root(c_json.as_ptr()) };
        assert!(!root_ptr.is_null());
        let root = unsafe { CStr::from_ptr(root_ptr) }.to_str().unwrap();
        assert!(root.starts_with("0x"));
        assert_eq!(root.len(), 66);
        unsafe { crate::hush_free_string(root_ptr) };
    }

    #[test]
    fn test_merkle_proof_and_verify() {
        let json = make_leaf_hashes_json(4);
        let c_json = std::ffi::CString::new(json).unwrap();

        // Compute root
        let root_ptr = unsafe { hush_merkle_root(c_json.as_ptr()) };
        assert!(!root_ptr.is_null());
        let root_str = unsafe { CStr::from_ptr(root_ptr) }.to_str().unwrap();

        // Generate proof for index 1
        let proof_ptr = unsafe { hush_merkle_proof(c_json.as_ptr(), 1) };
        assert!(!proof_ptr.is_null());
        let proof_str = unsafe { CStr::from_ptr(proof_ptr) }.to_str().unwrap();

        // Get leaf hash
        let leaf_hash = sha256(b"leaf1").to_hex_prefixed();
        let c_leaf = std::ffi::CString::new(leaf_hash).unwrap();
        let c_root = std::ffi::CString::new(root_str).unwrap();
        let c_proof = std::ffi::CString::new(proof_str).unwrap();

        let result =
            unsafe { hush_verify_merkle_proof(c_leaf.as_ptr(), c_proof.as_ptr(), c_root.as_ptr()) };
        assert_eq!(result, 1);

        // Wrong leaf should fail
        let wrong_leaf = sha256(b"wrong").to_hex_prefixed();
        let c_wrong = std::ffi::CString::new(wrong_leaf).unwrap();
        let result2 = unsafe {
            hush_verify_merkle_proof(c_wrong.as_ptr(), c_proof.as_ptr(), c_root.as_ptr())
        };
        assert_eq!(result2, 0);

        unsafe { crate::hush_free_string(root_ptr) };
        unsafe { crate::hush_free_string(proof_ptr) };
    }

    #[test]
    fn test_merkle_proof_out_of_bounds() {
        let json = make_leaf_hashes_json(2);
        let c_json = std::ffi::CString::new(json).unwrap();
        let proof_ptr = unsafe { hush_merkle_proof(c_json.as_ptr(), 99) };
        assert!(proof_ptr.is_null());
    }

    #[test]
    fn test_null_pointers() {
        assert!(unsafe { hush_merkle_root(std::ptr::null()) }.is_null());
        assert!(unsafe { hush_merkle_proof(std::ptr::null(), 0) }.is_null());
        assert_eq!(
            unsafe {
                hush_verify_merkle_proof(std::ptr::null(), std::ptr::null(), std::ptr::null())
            },
            -1
        );
    }

    #[test]
    fn test_two_leaf_tree() {
        let h1 = sha256(b"a").to_hex_prefixed();
        let h2 = sha256(b"b").to_hex_prefixed();
        let json = serde_json::to_string(&vec![&h1, &h2]).unwrap();
        let c_json = std::ffi::CString::new(json).unwrap();

        let root_ptr = unsafe { hush_merkle_root(c_json.as_ptr()) };
        assert!(!root_ptr.is_null());
        let root = unsafe { CStr::from_ptr(root_ptr) }.to_str().unwrap();

        // Prove index 0
        let proof_ptr = unsafe { hush_merkle_proof(c_json.as_ptr(), 0) };
        assert!(!proof_ptr.is_null());

        let c_leaf = std::ffi::CString::new(h1.clone()).unwrap();
        let c_root = std::ffi::CString::new(root).unwrap();
        let c_proof =
            std::ffi::CString::new(unsafe { CStr::from_ptr(proof_ptr) }.to_str().unwrap()).unwrap();

        let result =
            unsafe { hush_verify_merkle_proof(c_leaf.as_ptr(), c_proof.as_ptr(), c_root.as_ptr()) };
        assert_eq!(result, 1);

        unsafe { crate::hush_free_string(root_ptr) };
        unsafe { crate::hush_free_string(proof_ptr) };
    }
}
