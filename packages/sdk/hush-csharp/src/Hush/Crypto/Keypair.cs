using System;
using Hush.Internal;

namespace Hush.Crypto
{
    /// <summary>
    /// An Ed25519 keypair backed by hush-core. Wraps the native HushKeypair
    /// opaque pointer and releases it on dispose.
    /// </summary>
    public sealed class Keypair : IDisposable
    {
        private readonly SafeKeypairHandle _handle;
        private bool _disposed;

        private Keypair(SafeKeypairHandle handle)
        {
            _handle = handle;
        }

        /// <summary>
        /// Generate a new random Ed25519 keypair.
        /// </summary>
        public static Keypair Generate()
        {
            var ptr = NativeMethods.hush_keypair_generate();
            HushException.ThrowIfNull(ptr);
            return new Keypair(new SafeKeypairHandle(ptr));
        }

        /// <summary>
        /// Create a keypair from a 32-byte seed.
        /// </summary>
        public static Keypair FromSeed(byte[] seed)
        {
            if (seed == null) throw new ArgumentNullException(nameof(seed));
            if (seed.Length != 32)
                throw new ArgumentException("Seed must be exactly 32 bytes.", nameof(seed));
            var ptr = NativeMethods.hush_keypair_from_seed(seed);
            HushException.ThrowIfNull(ptr);
            return new Keypair(new SafeKeypairHandle(ptr));
        }

        /// <summary>
        /// Create a keypair from a hex-encoded secret key.
        /// </summary>
        public static Keypair FromHex(string hex)
        {
            if (hex == null) throw new ArgumentNullException(nameof(hex));
            Utf8Validation.RejectEmbeddedNul(hex, nameof(hex));
            var ptr = NativeMethods.hush_keypair_from_hex(hex);
            HushException.ThrowIfNull(ptr);
            return new Keypair(new SafeKeypairHandle(ptr));
        }

        /// <summary>
        /// Get the public key as a hex string.
        /// </summary>
        public string PublicKeyHex
        {
            get
            {
                ThrowIfDisposed();
                var ptr = NativeMethods.hush_keypair_public_key_hex(_handle);
                HushException.ThrowIfNull(ptr);
                using var ns = new NativeString(ptr);
                return ns.ToString()!;
            }
        }

        /// <summary>
        /// Get the public key as a 32-byte array.
        /// </summary>
        public byte[] PublicKeyBytes
        {
            get
            {
                ThrowIfDisposed();
                var output = new byte[32];
                var rc = NativeMethods.hush_keypair_public_key_bytes(
                    _handle, output);
                HushException.ThrowIfError(rc);
                return output;
            }
        }

        /// <summary>
        /// Sign a message and return the signature as a hex string.
        /// </summary>
        public string SignHex(byte[] message)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));
            ThrowIfDisposed();
            var ptr = NativeMethods.hush_keypair_sign_hex(
                _handle, message, (UIntPtr)message.Length);
            HushException.ThrowIfNull(ptr);
            using var ns = new NativeString(ptr);
            return ns.ToString()!;
        }

        /// <summary>
        /// Sign a message and return the 64-byte signature.
        /// </summary>
        public byte[] Sign(byte[] message)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));
            ThrowIfDisposed();
            var output = new byte[64];
            var rc = NativeMethods.hush_keypair_sign(
                _handle, message, (UIntPtr)message.Length, output);
            HushException.ThrowIfError(rc);
            return output;
        }

        /// <summary>
        /// Export the full keypair as a hex string.
        /// </summary>
        public string ToHex()
        {
            ThrowIfDisposed();
            var ptr = NativeMethods.hush_keypair_to_hex(_handle);
            HushException.ThrowIfNull(ptr);
            using var ns = new NativeString(ptr);
            return ns.ToString()!;
        }

        /// <summary>
        /// Get the raw handle for passing to receipt functions.
        /// </summary>
        internal SafeKeypairHandle Handle
        {
            get
            {
                ThrowIfDisposed();
                return _handle;
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(Keypair));
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _handle.Dispose();
                _disposed = true;
            }
        }
    }
}
