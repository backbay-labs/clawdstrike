using System;
using System.Runtime.InteropServices;

namespace Hush.Internal
{
    /// <summary>
    /// A SafeHandle wrapping an opaque HushKeypair pointer.
    /// Releases the native keypair via <c>hush_keypair_destroy</c>.
    /// </summary>
    internal sealed class SafeKeypairHandle : SafeHandle
    {
        public SafeKeypairHandle() : base(IntPtr.Zero, true) { }

        public SafeKeypairHandle(IntPtr handle) : base(IntPtr.Zero, true)
        {
            SetHandle(handle);
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            if (handle != IntPtr.Zero)
            {
                NativeMethods.hush_keypair_destroy(handle);
                handle = IntPtr.Zero;
            }
            return true;
        }
    }
}
