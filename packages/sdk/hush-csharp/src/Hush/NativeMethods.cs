using System;
using System.Runtime.InteropServices;
using Hush.Internal;

namespace Hush
{
    /// <summary>
    /// P/Invoke declarations for all hush_ffi C ABI functions.
    /// </summary>
    internal static class NativeMethods
    {
        private const string LibName = "hush_ffi";

        // ── Infra ──────────────────────────────────────────────────────

        /// <summary>
        /// Return the last error message (static pointer, do NOT free).
        /// </summary>
        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_last_error();

        /// <summary>
        /// Free a callee-allocated string.
        /// </summary>
        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void hush_free_string(IntPtr ptr);

        /// <summary>
        /// Return the library version (static pointer, do NOT free).
        /// </summary>
        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_version();

        // ── Hashing ────────────────────────────────────────────────────

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hush_sha256(
            byte[] data, UIntPtr len, byte[] out_32);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_sha256_hex(
            byte[] data, UIntPtr len);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hush_keccak256(
            byte[] data, UIntPtr len, byte[] out_32);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_keccak256_hex(
            byte[] data, UIntPtr len);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_canonicalize_json(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string json);

        // ── Keypair ────────────────────────────────────────────────────

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_keypair_generate();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_keypair_from_seed(byte[] seed_32);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_keypair_from_hex(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string hex);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_keypair_public_key_hex(SafeKeypairHandle kp);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hush_keypair_public_key_bytes(
            SafeKeypairHandle kp, byte[] out_32);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_keypair_sign_hex(
            SafeKeypairHandle kp, byte[] msg, UIntPtr len);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hush_keypair_sign(
            SafeKeypairHandle kp, byte[] msg, UIntPtr len, byte[] out_64);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_keypair_to_hex(SafeKeypairHandle kp);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void hush_keypair_destroy(IntPtr kp);

        // ── Verify ─────────────────────────────────────────────────────

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hush_verify_ed25519(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string pk_hex,
            byte[] msg, UIntPtr len,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string sig_hex);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hush_verify_ed25519_bytes(
            byte[] pk_32, byte[] msg, UIntPtr len, byte[] sig_64);

        // ── Receipt ────────────────────────────────────────────────────

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_verify_receipt(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string receipt_json,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string signer_hex,
            IntPtr cosigner_hex);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_sign_receipt(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string receipt_json,
            SafeKeypairHandle kp);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_hash_receipt(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string receipt_json,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string algorithm);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_receipt_canonical_json(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string receipt_json);

        // ── Merkle ─────────────────────────────────────────────────────

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_merkle_root(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string leaf_hashes_json);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_merkle_proof(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string leaf_hashes_json,
            UIntPtr index);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int hush_verify_merkle_proof(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string leaf_hex,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string proof_json,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string root_hex);

        // ── Security ───────────────────────────────────────────────────

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_detect_jailbreak(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string text,
            IntPtr session_id,
            IntPtr config_json);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_sanitize_output(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string text,
            IntPtr config_json);

        // ── Watermark ──────────────────────────────────────────────────

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_watermark_public_key(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string config_json);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_watermark_prompt(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string prompt,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string config_json,
            IntPtr app_id,
            IntPtr session_id);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr hush_extract_watermark(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string text,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string config_json);
    }
}
