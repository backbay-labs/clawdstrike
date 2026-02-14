using System;
using Hush.Crypto;

namespace Hush.Tests
{
    internal static class TestNative
    {
        internal static bool IsAvailable()
        {
            try
            {
                var _ = Hash.Sha256(new byte[] { 0 });
                return true;
            }
            catch (DllNotFoundException)
            {
                return false;
            }
        }

        internal static bool Require()
        {
            if (IsAvailable())
                return true;

            if (Environment.GetEnvironmentVariable("HUSH_FFI_REQUIRED") == "1")
                throw new InvalidOperationException("hush_ffi native library required for tests (HUSH_FFI_REQUIRED=1) but was not found");

            return false;
        }
    }
}

