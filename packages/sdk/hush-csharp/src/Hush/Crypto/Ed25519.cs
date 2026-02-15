using System;
using Hush.Internal;

namespace Hush.Crypto
{
    /// <summary>
    /// Ed25519 signature verification.
    /// </summary>
    public static class Ed25519
    {
        /// <summary>
        /// Verify an Ed25519 signature using hex-encoded public key and signature.
        /// </summary>
        /// <param name="publicKeyHex">Hex-encoded 32-byte public key.</param>
        /// <param name="message">The signed message bytes.</param>
        /// <param name="signatureHex">Hex-encoded 64-byte signature.</param>
        /// <returns>True if the signature is valid.</returns>
        public static bool Verify(string publicKeyHex, byte[] message, string signatureHex)
        {
            if (publicKeyHex == null) throw new ArgumentNullException(nameof(publicKeyHex));
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (signatureHex == null) throw new ArgumentNullException(nameof(signatureHex));
            Utf8Validation.RejectEmbeddedNul(publicKeyHex, nameof(publicKeyHex));
            Utf8Validation.RejectEmbeddedNul(signatureHex, nameof(signatureHex));

            var rc = NativeMethods.hush_verify_ed25519(
                publicKeyHex, message, (UIntPtr)message.Length, signatureHex);
            // 1 = valid, 0 = invalid, negative = error
            if (rc < 0)
                throw HushException.FromLastError();
            return rc == 1;
        }

        /// <summary>
        /// Verify an Ed25519 signature using raw byte arrays.
        /// </summary>
        /// <param name="publicKey">32-byte public key.</param>
        /// <param name="message">The signed message bytes.</param>
        /// <param name="signature">64-byte signature.</param>
        /// <returns>True if the signature is valid.</returns>
        public static bool VerifyBytes(byte[] publicKey, byte[] message, byte[] signature)
        {
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (signature == null) throw new ArgumentNullException(nameof(signature));
            if (publicKey.Length != 32)
                throw new ArgumentException("Public key must be 32 bytes.", nameof(publicKey));
            if (signature.Length != 64)
                throw new ArgumentException("Signature must be 64 bytes.", nameof(signature));

            var rc = NativeMethods.hush_verify_ed25519_bytes(
                publicKey, message, (UIntPtr)message.Length, signature);
            if (rc < 0)
                throw HushException.FromLastError();
            return rc == 1;
        }
    }
}
