using System;
using Xunit;
using Hush.Crypto;
using Hush.Watermark;

namespace Hush.Tests
{
    public class WatermarkTests
    {
        private static bool NativeAvailable() => TestNative.Require();

        private const string SampleConfig = "{\"generate_keypair\": true}";
        private const string SampleVerifierConfig = "{\"trusted_public_keys\": []}";

        [Fact]
        public void Watermarker_PublicKey_ReturnsJson()
        {
            if (!NativeAvailable()) return;

            var result = Watermarker.PublicKey(SampleConfig);
            Assert.False(string.IsNullOrEmpty(result));
        }

        [Fact]
        public void Watermarker_Watermark_BasicPrompt()
        {
            if (!NativeAvailable()) return;

            var result = Watermarker.WatermarkPrompt(
                "Write a poem about the ocean",
                SampleConfig);
            Assert.False(string.IsNullOrEmpty(result));
        }

        [Fact]
        public void Watermarker_Watermark_WithAppAndSession()
        {
            if (!NativeAvailable()) return;

            var result = Watermarker.WatermarkPrompt(
                "Write a poem about the ocean",
                SampleConfig,
                appId: "my-app",
                sessionId: "session-456");
            Assert.False(string.IsNullOrEmpty(result));
        }

        [Fact]
        public void Watermarker_Extract_ReturnsJson()
        {
            if (!NativeAvailable()) return;

            var result = Watermarker.Extract(
                "The ocean waves crash upon the shore.",
                SampleVerifierConfig);
            Assert.False(string.IsNullOrEmpty(result));
        }

        [Fact]
        public void Watermarker_PublicKey_NullConfig_ThrowsArgumentNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
                Watermarker.PublicKey(null!));
        }

        [Fact]
        public void Watermarker_WatermarkPrompt_NullPrompt_ThrowsArgumentNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
                Watermarker.WatermarkPrompt(null!, SampleConfig));
        }

        [Fact]
        public void Watermarker_WatermarkPrompt_NullConfig_ThrowsArgumentNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
                Watermarker.WatermarkPrompt("prompt", null!));
        }

        [Fact]
        public void Watermarker_WatermarkPrompt_EmbeddedNul_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() =>
                Watermarker.WatermarkPrompt("a\0b", SampleConfig));
        }

        [Fact]
        public void Watermarker_Extract_NullText_ThrowsArgumentNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
                Watermarker.Extract(null!, SampleConfig));
        }

        [Fact]
        public void Watermarker_Extract_NullConfig_ThrowsArgumentNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
                Watermarker.Extract("text", null!));
        }
    }
}
