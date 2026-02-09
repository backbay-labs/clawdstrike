# keccak-asm

Simple wrappers for SHA-3 algorithms written in assembly.

Forked from OpenSSL, [Cryptogams](https://github.com/dot-asm/cryptogams), and [RustCrypto's `sha3`](https://github.com/RustCrypto/hashes/tree/master/sha3).

> [!WARNING]
> Code is somewhat [tested](./tests/test.rs) and [benchmarked](https://github.com/DaniPopes/bench-keccak256).
> Use at your own risk.

## Support

| Architecture | Linux | macOS | Windows |
|:------------:|:-----:|:-----:|:-------:|
|      x86     |   ❌   |   ❌   |    ❌    |
|    x86_64    |   ✅   |   ✅   |    ✅    |
|    aarch64   |   ✅   |   ✅   |    🟨    |
| powerpc{,64} |   ✅   |  N/A  |   N/A   |
| powerpc64le  |   ❌   |  N/A  |   N/A   |
|    riscv32   |   ✅   |  N/A  |   N/A   |
|    riscv64   |   ✅   |  N/A  |   N/A   |
|   mips{,el}  |   ✅   |  N/A  |   N/A   |

- ❌: Currently not supported.
- 🟨: Compiles, but is only built, not tested in CI. Should still work normally.
- ✅: Fully supported, with full CI coverage for the most popular target triples, e.g. `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`.

## License

Cryptogams is either licensed under [BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html) (the "new" BSD license, as specified [here](https://www.openssl.org/~appro/cryptogams/)), or the Linux Kernel's license [GPL-2.0-only](https://spdx.org/licenses/GPL-2.0-only.html).
See the [LICENSE](./LICENSE) file for more information.
