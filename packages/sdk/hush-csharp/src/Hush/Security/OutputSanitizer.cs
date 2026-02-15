using System;
using System.Runtime.InteropServices;
using Hush.Internal;

namespace Hush.Security
{
    /// <summary>
    /// Output sanitization to strip sensitive data from agent responses.
    /// </summary>
    public static class OutputSanitizer
    {
        /// <summary>
        /// Sanitize the given text, removing detected secrets and sensitive data.
        /// </summary>
        /// <param name="text">The text to sanitize.</param>
        /// <param name="configJson">Optional JSON configuration string.</param>
        /// <returns>Sanitization result as a JSON string.</returns>
        public static string Sanitize(string text, string? configJson = null)
        {
            if (text == null) throw new ArgumentNullException(nameof(text));
            Utf8Validation.RejectEmbeddedNul(text, nameof(text));
            if (configJson != null)
                Utf8Validation.RejectEmbeddedNul(configJson, nameof(configJson));

            IntPtr configPtr = IntPtr.Zero;
            try
            {
                if (configJson != null)
                    configPtr = Marshal.StringToCoTaskMemUTF8(configJson);

                var ptr = NativeMethods.hush_sanitize_output(text, configPtr);
                HushException.ThrowIfNull(ptr);
                using var ns = new NativeString(ptr);
                return ns.ToString()!;
            }
            finally
            {
                if (configPtr != IntPtr.Zero)
                    Marshal.FreeCoTaskMem(configPtr);
            }
        }
    }
}
