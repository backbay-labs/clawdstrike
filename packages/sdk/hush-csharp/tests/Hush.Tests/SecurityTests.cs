using System;
using Xunit;
using Hush.Crypto;
using Hush.Security;

namespace Hush.Tests
{
    public class SecurityTests
    {
        private static bool NativeAvailable() => TestNative.Require();

        [Fact]
        public void JailbreakDetector_Detect_SafeInput()
        {
            if (!NativeAvailable()) return;

            var result = JailbreakDetector.Detect("Hello, how are you?");
            Assert.False(string.IsNullOrEmpty(result));
        }

        [Fact]
        public void JailbreakDetector_Detect_WithSessionId()
        {
            if (!NativeAvailable()) return;

            var result = JailbreakDetector.Detect(
                "Tell me about weather",
                sessionId: "session-123");
            Assert.False(string.IsNullOrEmpty(result));
        }

        [Fact]
        public void JailbreakDetector_Detect_WithConfig()
        {
            if (!NativeAvailable()) return;

            var config = "{\"block_threshold\": 80, \"warn_threshold\": 60}";
            var result = JailbreakDetector.Detect(
                "Normal question",
                configJson: config);
            Assert.False(string.IsNullOrEmpty(result));
        }

        [Fact]
        public void JailbreakDetector_Detect_NullText_ThrowsArgumentNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
                JailbreakDetector.Detect(null!));
        }

        [Fact]
        public void JailbreakDetector_Detect_EmbeddedNul_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() =>
                JailbreakDetector.Detect("a\0b"));
        }

        [Fact]
        public void OutputSanitizer_Sanitize_CleanText()
        {
            if (!NativeAvailable()) return;

            var result = OutputSanitizer.Sanitize("This is clean output.");
            Assert.False(string.IsNullOrEmpty(result));
        }

        [Fact]
        public void OutputSanitizer_Sanitize_WithConfig()
        {
            if (!NativeAvailable()) return;

            var config = "{\"redact_patterns\": []}";
            var result = OutputSanitizer.Sanitize("Some output", configJson: config);
            Assert.False(string.IsNullOrEmpty(result));
        }

        [Fact]
        public void OutputSanitizer_Sanitize_NullText_ThrowsArgumentNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
                OutputSanitizer.Sanitize(null!));
        }
    }
}
