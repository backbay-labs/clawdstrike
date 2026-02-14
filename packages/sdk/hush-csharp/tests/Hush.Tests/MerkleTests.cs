using System;
using System.Text;
using Xunit;
using Hush.Crypto;

namespace Hush.Tests
{
    public class MerkleTests
    {
        private static bool NativeAvailable() => TestNative.Require();

        [Fact]
        public void Merkle_ComputeRoot_SingleLeaf()
        {
            if (!NativeAvailable()) return;

            var leafHash = Hash.Sha256Hex(Encoding.UTF8.GetBytes("leaf1"));
            var json = $"[\"{leafHash}\"]";
            var root = Hush.Merkle.Merkle.ComputeRoot(json);
            Assert.Equal(66, root.Length);
            Assert.True(root.StartsWith("0x"));
            // Single leaf: root == leaf hash
            Assert.Equal("0x" + leafHash, root);
        }

        [Fact]
        public void Merkle_ComputeRoot_MultipleLeaves()
        {
            if (!NativeAvailable()) return;

            var h1 = Hash.Sha256Hex(Encoding.UTF8.GetBytes("leaf1"));
            var h2 = Hash.Sha256Hex(Encoding.UTF8.GetBytes("leaf2"));
            var json = $"[\"{h1}\",\"{h2}\"]";
            var root = Hush.Merkle.Merkle.ComputeRoot(json);
            Assert.Equal(66, root.Length);
        }

        [Fact]
        public void Merkle_ComputeRoot_Deterministic()
        {
            if (!NativeAvailable()) return;

            var h1 = Hash.Sha256Hex(Encoding.UTF8.GetBytes("a"));
            var h2 = Hash.Sha256Hex(Encoding.UTF8.GetBytes("b"));
            var json = $"[\"{h1}\",\"{h2}\"]";
            var r1 = Hush.Merkle.Merkle.ComputeRoot(json);
            var r2 = Hush.Merkle.Merkle.ComputeRoot(json);
            Assert.Equal(r1, r2);
        }

        [Fact]
        public void Merkle_GenerateAndVerifyProof()
        {
            if (!NativeAvailable()) return;

            var h1 = Hash.Sha256Hex(Encoding.UTF8.GetBytes("leaf1"));
            var h2 = Hash.Sha256Hex(Encoding.UTF8.GetBytes("leaf2"));
            var h3 = Hash.Sha256Hex(Encoding.UTF8.GetBytes("leaf3"));
            var json = $"[\"{h1}\",\"{h2}\",\"{h3}\"]";

            var root = Hush.Merkle.Merkle.ComputeRoot(json);
            var proof = Hush.Merkle.Merkle.GenerateProof(json, 1);
            Assert.False(string.IsNullOrEmpty(proof));

            var valid = Hush.Merkle.Merkle.VerifyProof(h2, proof, root);
            Assert.True(valid);
        }

        [Fact]
        public void Merkle_VerifyProof_WrongLeaf_ReturnsFalse()
        {
            if (!NativeAvailable()) return;

            var h1 = Hash.Sha256Hex(Encoding.UTF8.GetBytes("leaf1"));
            var h2 = Hash.Sha256Hex(Encoding.UTF8.GetBytes("leaf2"));
            var json = $"[\"{h1}\",\"{h2}\"]";

            var root = Hush.Merkle.Merkle.ComputeRoot(json);
            var proof = Hush.Merkle.Merkle.GenerateProof(json, 0);

            // Use wrong leaf hash
            var wrongLeaf = Hash.Sha256Hex(Encoding.UTF8.GetBytes("wrong"));
            var valid = Hush.Merkle.Merkle.VerifyProof(wrongLeaf, proof, root);
            Assert.False(valid);
        }

        [Fact]
        public void Merkle_ComputeRoot_NullInput_ThrowsArgumentNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
                Hush.Merkle.Merkle.ComputeRoot(null!));
        }

        [Fact]
        public void Merkle_GenerateProof_NegativeIndex_ThrowsArgumentOutOfRange()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                Hush.Merkle.Merkle.GenerateProof("[]", -1));
        }
    }
}
