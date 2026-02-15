using System;

namespace Hush.Internal
{
    internal static class Utf8Validation
    {
        internal static void RejectEmbeddedNul(string value, string paramName)
        {
            if (value.IndexOf('\0') >= 0)
                throw new ArgumentException(
                    "String contains an embedded NUL (\\0) character, which cannot be passed to native hush_ffi APIs.",
                    paramName);
        }
    }
}

