using System;
using System.Text;
using Xunit;
using Hush.Crypto;
using Hush.Receipts;

namespace Hush.Tests
{
    public class ReceiptTests
    {
        private static bool NativeAvailable()
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

        private const string SampleReceipt = @"{
            ""version"": ""1.0"",
            ""action"": ""file_read"",
            ""target"": ""/etc/hosts"",
            ""decision"": ""allow"",
            ""timestamp"": ""2025-01-01T00:00:00Z""
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
            Assert.Equal(64, hash.Length);
        }

        [Fact]
        public void Receipt_Hash_Keccak256_Returns64CharHex()
        {
            if (!NativeAvailable()) return;

            var hash = Receipt.Hash(SampleReceipt, "keccak256");
            Assert.Equal(64, hash.Length);
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
        public void Receipt_Hash_NullAlgorithm_ThrowsArgumentNull()
        {
            Assert.Throws<ArgumentNullException>(() => Receipt.Hash("{}", null!));
        }
    }
}
