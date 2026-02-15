using System;
using System.Text;
using Xunit;
using Hush.Crypto;

namespace Hush.Tests
{
    public class CryptoTests
    {
        private static bool NativeAvailable() => TestNative.Require();

        [Fact]
        public void Sha256_EmptyInput_Returns32Bytes()
        {
            if (!NativeAvailable()) return;

            var hash = Hash.Sha256(Array.Empty<byte>());
            Assert.Equal(32, hash.Length);
        }

        [Fact]
        public void Sha256Hex_EmptyInput_Returns64CharHex()
        {
            if (!NativeAvailable()) return;

            var hex = Hash.Sha256Hex(Array.Empty<byte>());
            Assert.Equal(64, hex.Length);
            // SHA-256 of empty input is well-known
            Assert.Equal(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                hex);
        }

        [Fact]
        public void Sha256_HelloWorld_Deterministic()
        {
            if (!NativeAvailable()) return;

            var data = Encoding.UTF8.GetBytes("hello world");
            var h1 = Hash.Sha256Hex(data);
            var h2 = Hash.Sha256Hex(data);
            Assert.Equal(h1, h2);
        }

        [Fact]
        public void Keccak256_EmptyInput_Returns32Bytes()
        {
            if (!NativeAvailable()) return;

            var hash = Hash.Keccak256(Array.Empty<byte>());
            Assert.Equal(32, hash.Length);
        }

        [Fact]
        public void Keccak256Hex_EmptyInput_Returns64CharHex()
        {
            if (!NativeAvailable()) return;

            var hex = Hash.Keccak256Hex(Array.Empty<byte>());
            Assert.Equal(64, hex.Length);
            // Keccak-256 of empty input
            Assert.Equal(
                "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                hex);
        }

        [Fact]
        public void Sha256_NullInput_ThrowsArgumentNull()
        {
            Assert.Throws<ArgumentNullException>(() => Hash.Sha256(null!));
        }

        [Fact]
        public void Keypair_Generate_HasPublicKey()
        {
            if (!NativeAvailable()) return;

            using var kp = Keypair.Generate();
            var hex = kp.PublicKeyHex;
            Assert.Equal(64, hex.Length); // 32 bytes = 64 hex chars
        }

        [Fact]
        public void Keypair_FromSeed_Deterministic()
        {
            if (!NativeAvailable()) return;

            var seed = new byte[32];
            for (int i = 0; i < 32; i++) seed[i] = (byte)i;

            using var kp1 = Keypair.FromSeed(seed);
            using var kp2 = Keypair.FromSeed(seed);
            Assert.Equal(kp1.PublicKeyHex, kp2.PublicKeyHex);
        }

        [Fact]
        public void Keypair_PublicKeyBytes_Is32Bytes()
        {
            if (!NativeAvailable()) return;

            using var kp = Keypair.Generate();
            var bytes = kp.PublicKeyBytes;
            Assert.Equal(32, bytes.Length);
        }

        [Fact]
        public void Keypair_SignAndVerify_RoundTrip()
        {
            if (!NativeAvailable()) return;

            using var kp = Keypair.Generate();
            var message = Encoding.UTF8.GetBytes("test message");
            var sigHex = kp.SignHex(message);
            Assert.Equal(128, sigHex.Length); // 64 bytes = 128 hex chars

            var valid = Ed25519.Verify(kp.PublicKeyHex, message, sigHex);
            Assert.True(valid);
        }

        [Fact]
        public void Keypair_SignBytes_RoundTrip()
        {
            if (!NativeAvailable()) return;

            using var kp = Keypair.Generate();
            var message = Encoding.UTF8.GetBytes("test message");
            var sig = kp.Sign(message);
            Assert.Equal(64, sig.Length);

            var valid = Ed25519.VerifyBytes(kp.PublicKeyBytes, message, sig);
            Assert.True(valid);
        }

        [Fact]
        public void Ed25519_Verify_InvalidSig_ReturnsFalse()
        {
            if (!NativeAvailable()) return;

            using var kp = Keypair.Generate();
            var message = Encoding.UTF8.GetBytes("test message");
            var sigHex = kp.SignHex(message);

            // Tamper with message
            var tampered = Encoding.UTF8.GetBytes("tampered message");
            var valid = Ed25519.Verify(kp.PublicKeyHex, tampered, sigHex);
            Assert.False(valid);
        }

        [Fact]
        public void Keypair_ToHex_NotEmpty()
        {
            if (!NativeAvailable()) return;

            using var kp = Keypair.Generate();
            var hex = kp.ToHex();
            Assert.False(string.IsNullOrEmpty(hex));
        }

        [Fact]
        public void Keypair_FromHex_RoundTrip()
        {
            if (!NativeAvailable()) return;

            using var kp = Keypair.Generate();
            var hex = kp.ToHex();
            using var kp2 = Keypair.FromHex(hex);
            Assert.Equal(kp.PublicKeyHex, kp2.PublicKeyHex);
        }

        [Fact]
        public void Keypair_FromSeed_WrongLength_Throws()
        {
            Assert.Throws<ArgumentException>(() => Keypair.FromSeed(new byte[16]));
        }

        [Fact]
        public void Ed25519_VerifyBytes_WrongLengths_Throws()
        {
            Assert.Throws<ArgumentException>(() =>
                Ed25519.VerifyBytes(new byte[16], new byte[0], new byte[64]));
            Assert.Throws<ArgumentException>(() =>
                Ed25519.VerifyBytes(new byte[32], new byte[0], new byte[32]));
        }

        [Fact]
        public void CanonicalJson_Reorders_Keys()
        {
            if (!NativeAvailable()) return;

            var input = "{\"z\":1,\"a\":2}";
            var result = CanonicalJson.Canonicalize(input);
            Assert.Equal("{\"a\":2,\"z\":1}", result);
        }

        [Fact]
        public void CanonicalJson_Null_ThrowsArgumentNull()
        {
            Assert.Throws<ArgumentNullException>(() => CanonicalJson.Canonicalize(null!));
        }

        [Fact]
        public void CanonicalJson_EmbeddedNul_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => CanonicalJson.Canonicalize("a\0b"));
        }

        [Fact]
        public void Ed25519_Verify_EmbeddedNul_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() =>
                Ed25519.Verify("aa\0bb", Array.Empty<byte>(), "cc"));
        }

        [Fact]
        public void Keypair_FromHex_EmbeddedNul_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => Keypair.FromHex("0x00\0ff"));
        }

        [Fact]
        public void Keypair_Dispose_Twice_NoThrow()
        {
            if (!NativeAvailable()) return;

            var kp = Keypair.Generate();
            kp.Dispose();
            kp.Dispose(); // should not throw
        }

        [Fact]
        public void Keypair_UseAfterDispose_Throws()
        {
            if (!NativeAvailable()) return;

            var kp = Keypair.Generate();
            kp.Dispose();
            Assert.Throws<ObjectDisposedException>(() => kp.PublicKeyHex);
        }
    }
}
