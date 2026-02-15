using System;
using System.Text;
using Xunit;
using Hush.Crypto;
using Hush.Receipts;

namespace Hush.Tests
{
    public class ReceiptTests
    {
        private static bool NativeAvailable() => TestNative.Require();

        private const string SampleReceipt = @"{
            ""version"": ""1.0.0"",
            ""timestamp"": ""2025-01-01T00:00:00Z"",
            ""content_hash"": ""0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"",
            ""verdict"": {""passed"": true}
        }";

        [Fact]
        public void Receipt_Sign_ReturnsJson()
        {
            if (!NativeAvailable()) return;

            using var kp = Keypair.Generate();
            var signed = Receipt.Sign(SampleReceipt, kp);
            Assert.False(string.IsNullOrEmpty(signed));
            Assert.Contains("signature", signed);
        }

        [Fact]
        public void Receipt_SignAndVerify_RoundTrip()
        {
            if (!NativeAvailable()) return;

            using var kp = Keypair.Generate();
            var signed = Receipt.Sign(SampleReceipt, kp);
            var result = Receipt.Verify(signed, kp.PublicKeyHex);
            Assert.False(string.IsNullOrEmpty(result));
        }

        [Fact]
        public void Receipt_Hash_Sha256_Returns64CharHex()
        {
            if (!NativeAvailable()) return;

            var hash = Receipt.Hash(SampleReceipt, "sha256");
            Assert.Equal(66, hash.Length);
            Assert.True(hash.StartsWith("0x"));
        }

        [Fact]
        public void Receipt_Hash_Keccak256_Returns64CharHex()
        {
            if (!NativeAvailable()) return;

            var hash = Receipt.Hash(SampleReceipt, "keccak256");
            Assert.Equal(66, hash.Length);
            Assert.True(hash.StartsWith("0x"));
        }

        [Fact]
        public void Receipt_CanonicalJson_Deterministic()
        {
            if (!NativeAvailable()) return;

            var c1 = Receipt.CanonicalJson(SampleReceipt);
            var c2 = Receipt.CanonicalJson(SampleReceipt);
            Assert.Equal(c1, c2);
            Assert.False(string.IsNullOrEmpty(c1));
        }

        [Fact]
        public void Receipt_Verify_WithCosigner()
        {
            if (!NativeAvailable()) return;

            using var signer = Keypair.Generate();
            using var cosigner = Keypair.Generate();
            var signed = Receipt.Sign(SampleReceipt, signer);
            // Verify with optional cosigner parameter
            var result = Receipt.Verify(signed, signer.PublicKeyHex, cosigner.PublicKeyHex);
            Assert.False(string.IsNullOrEmpty(result));
        }

        [Fact]
        public void Receipt_Sign_NullJson_ThrowsArgumentNull()
        {
            if (!NativeAvailable()) return;

            using var kp = Keypair.Generate();
            Assert.Throws<ArgumentNullException>(() => Receipt.Sign(null!, kp));
        }

        [Fact]
        public void Receipt_Verify_NullJson_ThrowsArgumentNull()
        {
            Assert.Throws<ArgumentNullException>(() => Receipt.Verify(null!, "abc"));
        }

        [Fact]
        public void Receipt_Verify_EmbeddedNul_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() =>
                Receipt.Verify("{\"a\":1}\0", "abc"));
        }

        [Fact]
        public void Receipt_Hash_NullAlgorithm_ThrowsArgumentNull()
        {
            Assert.Throws<ArgumentNullException>(() => Receipt.Hash("{}", null!));
        }
    }
}
