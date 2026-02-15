using System;
using System.Runtime.InteropServices;
using Hush.Internal;

namespace Hush.Watermark
{
    /// <summary>
    /// Prompt watermarking for AI-generated content attribution.
    /// </summary>
    public static class Watermarker
    {
        /// <summary>
        /// Retrieve the watermark public key for the given configuration.
        /// </summary>
        /// <param name="configJson">Watermark configuration as a JSON string.</param>
        /// <returns>The public key as a JSON string.</returns>
        public static string PublicKey(string configJson)
        {
            if (configJson == null) throw new ArgumentNullException(nameof(configJson));
            Utf8Validation.RejectEmbeddedNul(configJson, nameof(configJson));
            var ptr = NativeMethods.hush_watermark_public_key(configJson);
            HushException.ThrowIfNull(ptr);
            using var ns = new NativeString(ptr);
            return ns.ToString()!;
        }

        /// <summary>
        /// Apply a watermark to a prompt.
        /// </summary>
        /// <param name="prompt">The prompt text to watermark.</param>
        /// <param name="configJson">Watermark configuration as a JSON string.</param>
        /// <param name="appId">Optional application ID.</param>
        /// <param name="sessionId">Optional session ID.</param>
        /// <returns>The watermarked prompt as a JSON string.</returns>
        public static string WatermarkPrompt(string prompt, string configJson, string? appId = null, string? sessionId = null)
        {
            if (prompt == null) throw new ArgumentNullException(nameof(prompt));
            if (configJson == null) throw new ArgumentNullException(nameof(configJson));
            Utf8Validation.RejectEmbeddedNul(prompt, nameof(prompt));
            Utf8Validation.RejectEmbeddedNul(configJson, nameof(configJson));
            if (appId != null)
                Utf8Validation.RejectEmbeddedNul(appId, nameof(appId));
            if (sessionId != null)
                Utf8Validation.RejectEmbeddedNul(sessionId, nameof(sessionId));

            IntPtr appIdPtr = IntPtr.Zero;
            IntPtr sessionIdPtr = IntPtr.Zero;

            try
            {
                if (appId != null)
                    appIdPtr = Marshal.StringToCoTaskMemUTF8(appId);
                if (sessionId != null)
                    sessionIdPtr = Marshal.StringToCoTaskMemUTF8(sessionId);

                var ptr = NativeMethods.hush_watermark_prompt(
                    prompt, configJson, appIdPtr, sessionIdPtr);
                HushException.ThrowIfNull(ptr);
                using var ns = new NativeString(ptr);
                return ns.ToString()!;
            }
            finally
            {
                if (appIdPtr != IntPtr.Zero)
                    Marshal.FreeCoTaskMem(appIdPtr);
                if (sessionIdPtr != IntPtr.Zero)
                    Marshal.FreeCoTaskMem(sessionIdPtr);
            }
        }

        /// <summary>
        /// Extract a watermark from text.
        /// </summary>
        /// <param name="text">The text to analyze.</param>
        /// <param name="configJson">Watermark configuration as a JSON string.</param>
        /// <returns>Extraction result as a JSON string.</returns>
        public static string Extract(string text, string configJson)
        {
            if (text == null) throw new ArgumentNullException(nameof(text));
            if (configJson == null) throw new ArgumentNullException(nameof(configJson));
            Utf8Validation.RejectEmbeddedNul(text, nameof(text));
            Utf8Validation.RejectEmbeddedNul(configJson, nameof(configJson));

            var ptr = NativeMethods.hush_extract_watermark(text, configJson);
            HushException.ThrowIfNull(ptr);
            using var ns = new NativeString(ptr);
            return ns.ToString()!;
        }
    }
}
