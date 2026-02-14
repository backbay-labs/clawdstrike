using System;
using System.Runtime.InteropServices;

namespace Hush
{
    /// <summary>
    /// Exception thrown when a native hush_ffi call fails.
    /// </summary>
    public class HushException : Exception
    {
        public HushException(string message) : base(message) { }

        internal static HushException FromLastError()
        {
            var ptr = NativeMethods.hush_last_error();
            var msg = Marshal.PtrToStringUTF8(ptr) ?? "unknown error";
            return new HushException(msg);
        }

        internal static void ThrowIfNull(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
                throw FromLastError();
        }

        internal static void ThrowIfError(int result)
        {
            if (result < 0)
                throw FromLastError();
        }
    }
}
