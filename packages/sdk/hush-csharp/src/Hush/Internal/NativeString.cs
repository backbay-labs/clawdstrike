using System;
using System.Runtime.InteropServices;

namespace Hush.Internal
{
    /// <summary>
    /// Wraps a callee-allocated native string pointer and frees it on dispose.
    /// </summary>
    internal sealed class NativeString : IDisposable
    {
        private IntPtr _ptr;
        private bool _disposed;

        /// <summary>
        /// Creates a NativeString from a pointer returned by a hush_ffi function.
        /// The pointer will be freed via <c>hush_free_string</c> on dispose.
        /// </summary>
        public NativeString(IntPtr ptr)
        {
            _ptr = ptr;
        }

        /// <summary>
        /// Returns true if the underlying pointer is null.
        /// </summary>
        public bool IsNull => _ptr == IntPtr.Zero;

        /// <summary>
        /// Converts the native UTF-8 string to a managed string.
        /// Returns null if the pointer is null.
        /// </summary>
        public override string? ToString()
        {
            if (_ptr == IntPtr.Zero)
                return null;
            return Marshal.PtrToStringUTF8(_ptr);
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                if (_ptr != IntPtr.Zero)
                {
                    NativeMethods.hush_free_string(_ptr);
                    _ptr = IntPtr.Zero;
                }
                _disposed = true;
            }
        }
    }
}
