using System;
using Hush.Internal;

namespace Hush.Crypto
{
    /// <summary>
    /// SHA-256 and Keccak-256 hash functions backed by hush-core.
    /// </summary>
    public static class Hash
    {
        /// <summary>
        /// Compute the SHA-256 hash of the input data.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>A 32-byte SHA-256 digest.</returns>
        public static byte[] Sha256(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            var output = new byte[32];
            var rc = NativeMethods.hush_sha256(data, (UIntPtr)data.Length, output);
            HushException.ThrowIfError(rc);
            return output;
        }

        /// <summary>
        /// Compute the SHA-256 hash and return it as a lowercase hex string.
        /// The returned value is not <c>0x</c>-prefixed.
        /// </summary>
        public static string Sha256Hex(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            var ptr = NativeMethods.hush_sha256_hex(data, (UIntPtr)data.Length);
            HushException.ThrowIfNull(ptr);
            using var ns = new NativeString(ptr);
            return ns.ToString()!;
        }

        /// <summary>
        /// Compute the Keccak-256 hash of the input data.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>A 32-byte Keccak-256 digest.</returns>
        public static byte[] Keccak256(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            var output = new byte[32];
            var rc = NativeMethods.hush_keccak256(data, (UIntPtr)data.Length, output);
            HushException.ThrowIfError(rc);
            return output;
        }

        /// <summary>
        /// Compute the Keccak-256 hash and return it as a lowercase hex string.
        /// The returned value is not <c>0x</c>-prefixed.
        /// </summary>
        public static string Keccak256Hex(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            var ptr = NativeMethods.hush_keccak256_hex(data, (UIntPtr)data.Length);
            HushException.ThrowIfNull(ptr);
            using var ns = new NativeString(ptr);
            return ns.ToString()!;
        }
    }
}
