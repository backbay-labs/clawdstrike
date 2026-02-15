using System;
using System.Runtime.InteropServices;
using Hush.Internal;

namespace Hush.Security
{
    /// <summary>
    /// Jailbreak detection backed by clawdstrike's 4-layer detection pipeline.
    /// </summary>
    public static class JailbreakDetector
    {
        /// <summary>
        /// Detect potential jailbreak attempts in the given text.
        /// </summary>
        /// <param name="text">The text to analyze.</param>
        /// <param name="sessionId">Optional session ID for stateful detection.</param>
        /// <param name="configJson">Optional JSON configuration string.</param>
        /// <returns>Detection result as a JSON string.</returns>
        public static string Detect(string text, string? sessionId = null, string? configJson = null)
        {
            if (text == null) throw new ArgumentNullException(nameof(text));
            Utf8Validation.RejectEmbeddedNul(text, nameof(text));
            if (sessionId != null)
                Utf8Validation.RejectEmbeddedNul(sessionId, nameof(sessionId));
            if (configJson != null)
                Utf8Validation.RejectEmbeddedNul(configJson, nameof(configJson));

            IntPtr sessionPtr = IntPtr.Zero;
            IntPtr configPtr = IntPtr.Zero;

            try
            {
                if (sessionId != null)
                    sessionPtr = Marshal.StringToCoTaskMemUTF8(sessionId);
                if (configJson != null)
                    configPtr = Marshal.StringToCoTaskMemUTF8(configJson);

                var ptr = NativeMethods.hush_detect_jailbreak(text, sessionPtr, configPtr);
                HushException.ThrowIfNull(ptr);
                using var ns = new NativeString(ptr);
                return ns.ToString()!;
            }
            finally
            {
                if (sessionPtr != IntPtr.Zero)
                    Marshal.FreeCoTaskMem(sessionPtr);
                if (configPtr != IntPtr.Zero)
                    Marshal.FreeCoTaskMem(configPtr);
            }
        }
    }
}
