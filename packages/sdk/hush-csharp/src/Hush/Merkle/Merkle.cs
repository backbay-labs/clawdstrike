using System;
using Hush.Internal;

namespace Hush.Merkle
{
    /// <summary>
    /// Merkle tree operations: root computation, proof generation, and verification.
    /// </summary>
    public static class Merkle
    {
        /// <summary>
        /// Compute the Merkle root from a JSON array of hex-encoded leaf hashes.
        /// </summary>
        /// <param name="leafHashesJson">JSON array of hex strings, e.g. <c>["aabb..","ccdd.."]</c>.</param>
        /// <returns>The hex-encoded Merkle root.</returns>
        public static string ComputeRoot(string leafHashesJson)
        {
            if (leafHashesJson == null) throw new ArgumentNullException(nameof(leafHashesJson));
            Utf8Validation.RejectEmbeddedNul(leafHashesJson, nameof(leafHashesJson));
            var ptr = NativeMethods.hush_merkle_root(leafHashesJson);
            HushException.ThrowIfNull(ptr);
            using var ns = new NativeString(ptr);
            return ns.ToString()!;
        }

        /// <summary>
        /// Generate a Merkle inclusion proof for the leaf at the given index.
        /// </summary>
        /// <param name="leafHashesJson">JSON array of hex-encoded leaf hashes.</param>
        /// <param name="index">Zero-based leaf index.</param>
        /// <returns>The proof as a JSON string.</returns>
        public static string GenerateProof(string leafHashesJson, int index)
        {
            if (leafHashesJson == null) throw new ArgumentNullException(nameof(leafHashesJson));
            Utf8Validation.RejectEmbeddedNul(leafHashesJson, nameof(leafHashesJson));
            if (index < 0)
                throw new ArgumentOutOfRangeException(nameof(index), "Index must be non-negative.");
            var ptr = NativeMethods.hush_merkle_proof(leafHashesJson, (UIntPtr)index);
            HushException.ThrowIfNull(ptr);
            using var ns = new NativeString(ptr);
            return ns.ToString()!;
        }

        /// <summary>
        /// Verify a Merkle inclusion proof.
        /// </summary>
        /// <param name="leafHex">Hex-encoded leaf hash.</param>
        /// <param name="proofJson">The proof as a JSON string (from <see cref="GenerateProof"/>).</param>
        /// <param name="rootHex">The expected hex-encoded Merkle root.</param>
        /// <returns>True if the proof is valid.</returns>
        public static bool VerifyProof(string leafHex, string proofJson, string rootHex)
        {
            if (leafHex == null) throw new ArgumentNullException(nameof(leafHex));
            if (proofJson == null) throw new ArgumentNullException(nameof(proofJson));
            if (rootHex == null) throw new ArgumentNullException(nameof(rootHex));
            Utf8Validation.RejectEmbeddedNul(leafHex, nameof(leafHex));
            Utf8Validation.RejectEmbeddedNul(proofJson, nameof(proofJson));
            Utf8Validation.RejectEmbeddedNul(rootHex, nameof(rootHex));

            var rc = NativeMethods.hush_verify_merkle_proof(leafHex, proofJson, rootHex);
            if (rc < 0)
                throw HushException.FromLastError();
            return rc == 1;
        }
    }
}
