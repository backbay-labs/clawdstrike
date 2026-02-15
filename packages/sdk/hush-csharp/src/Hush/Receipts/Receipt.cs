using System;
using System.Runtime.InteropServices;
using Hush.Crypto;
using Hush.Internal;

namespace Hush.Receipts
{
    /// <summary>
    /// Operations on Ed25519-signed audit receipts.
    /// </summary>
    public static class Receipt
    {
        /// <summary>
        /// Verify a receipt's signature.
        /// </summary>
        /// <param name="receiptJson">The receipt as a JSON string.</param>
        /// <param name="signerHex">Hex-encoded public key of the expected signer.</param>
        /// <param name="cosignerHex">Optional hex-encoded cosigner public key, or null.</param>
        /// <returns>Verification result as a JSON string.</returns>
        public static string Verify(string receiptJson, string signerHex, string? cosignerHex = null)
        {
            if (receiptJson == null) throw new ArgumentNullException(nameof(receiptJson));
            if (signerHex == null) throw new ArgumentNullException(nameof(signerHex));
            Utf8Validation.RejectEmbeddedNul(receiptJson, nameof(receiptJson));
            Utf8Validation.RejectEmbeddedNul(signerHex, nameof(signerHex));
            if (cosignerHex != null)
                Utf8Validation.RejectEmbeddedNul(cosignerHex, nameof(cosignerHex));

            IntPtr cosignerPtr = IntPtr.Zero;
            try
            {
                if (cosignerHex != null)
                    cosignerPtr = Marshal.StringToCoTaskMemUTF8(cosignerHex);

                var ptr = NativeMethods.hush_verify_receipt(receiptJson, signerHex, cosignerPtr);
                HushException.ThrowIfNull(ptr);
                using var ns = new NativeString(ptr);
                return ns.ToString()!;
            }
            finally
            {
                if (cosignerPtr != IntPtr.Zero)
                    Marshal.FreeCoTaskMem(cosignerPtr);
            }
        }

        /// <summary>
        /// Sign a receipt with the given keypair.
        /// </summary>
        /// <param name="receiptJson">The receipt as a JSON string.</param>
        /// <param name="keypair">The signing keypair.</param>
        /// <returns>The signed receipt as a JSON string.</returns>
        public static string Sign(string receiptJson, Keypair keypair)
        {
            if (receiptJson == null) throw new ArgumentNullException(nameof(receiptJson));
            if (keypair == null) throw new ArgumentNullException(nameof(keypair));
            Utf8Validation.RejectEmbeddedNul(receiptJson, nameof(receiptJson));

            var ptr = NativeMethods.hush_sign_receipt(receiptJson, keypair.Handle);
            HushException.ThrowIfNull(ptr);
            using var ns = new NativeString(ptr);
            return ns.ToString()!;
        }

        /// <summary>
        /// Compute a hash of the receipt.
        /// </summary>
        /// <param name="receiptJson">The receipt as a JSON string.</param>
        /// <param name="algorithm">Hash algorithm: "sha256" or "keccak256".</param>
        /// <returns>The hex-encoded hash string.</returns>
        public static string Hash(string receiptJson, string algorithm)
        {
            if (receiptJson == null) throw new ArgumentNullException(nameof(receiptJson));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            Utf8Validation.RejectEmbeddedNul(receiptJson, nameof(receiptJson));
            Utf8Validation.RejectEmbeddedNul(algorithm, nameof(algorithm));

            var ptr = NativeMethods.hush_hash_receipt(receiptJson, algorithm);
            HushException.ThrowIfNull(ptr);
            using var ns = new NativeString(ptr);
            return ns.ToString()!;
        }

        /// <summary>
        /// Canonicalize the receipt JSON according to RFC 8785.
        /// </summary>
        /// <param name="receiptJson">The receipt as a JSON string.</param>
        /// <returns>The canonicalized JSON string.</returns>
        public static string CanonicalJson(string receiptJson)
        {
            if (receiptJson == null) throw new ArgumentNullException(nameof(receiptJson));
            Utf8Validation.RejectEmbeddedNul(receiptJson, nameof(receiptJson));

            var ptr = NativeMethods.hush_receipt_canonical_json(receiptJson);
            HushException.ThrowIfNull(ptr);
            using var ns = new NativeString(ptr);
            return ns.ToString()!;
        }
    }
}
