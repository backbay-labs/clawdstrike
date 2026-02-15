using System;
using Hush.Internal;

namespace Hush.Crypto
{
    /// <summary>
    /// RFC 8785 (JCS) canonical JSON serialization.
    /// </summary>
    public static class CanonicalJson
    {
        /// <summary>
        /// Canonicalize a JSON string according to RFC 8785.
        /// </summary>
        /// <param name="json">The JSON string to canonicalize.</param>
        /// <returns>The canonicalized JSON string.</returns>
        public static string Canonicalize(string json)
        {
            if (json == null) throw new ArgumentNullException(nameof(json));
            Utf8Validation.RejectEmbeddedNul(json, nameof(json));
            var ptr = NativeMethods.hush_canonicalize_json(json);
            HushException.ThrowIfNull(ptr);
            using var ns = new NativeString(ptr);
            return ns.ToString()!;
        }
    }
}
