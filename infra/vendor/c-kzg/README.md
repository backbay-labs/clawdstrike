# C-KZG-4844

A minimal implementation of the Polynomial Commitments API for
[EIP-4844](https://eips.ethereum.org/EIPS/eip-4844) and
[EIP-7594](https://eips.ethereum.org/EIPS/eip-7594), written in C.

## Bindings

While the core implementation is in C, bindings are available for various
high-level languages, providing convenient wrappers around C functions. These
bindings are intended to be used by Ethereum clients to avoid re-implementation
of crucial cryptographic functions.

| Language | Link                                 |
| -------- | ------------------------------------ |
| C#       | [README](bindings/csharp/README.md)  |
| Elixir   | [README](bindings/elixir/README.md)  |
| Go       | [README](bindings/go/README.md)      |
| Java     | [README](bindings/java/README.md)    |
| Nim      | [README](bindings/nim/README.md)     |
| Node.js  | [README](bindings/node.js/README.md) |
| Python   | [README](bindings/python/README.md)  |
| Rust     | [README](bindings/rust/README.md)    |

## Interface functions

The C-KZG-4844 library provides implementations of the public KZG functions
that are specified in the Polynomial Commitments API for
[Deneb](https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md)
and
[Fulu](https://github.com/ethereum/consensus-specs/blob/dev/specs/fulu/polynomial-commitments-sampling.md).
The aim is to align these functions as closely as possible with the
specifications.

For EIP-4844:

- `blob_to_kzg_commitment`
- `compute_kzg_proof`
- `compute_blob_kzg_proof`
- `verify_kzg_proof`
- `verify_blob_kzg_proof`
- `verify_blob_kzg_proof_batch`

For EIP-7594:

- `compute_cells`
- `compute_cells_and_kzg_proofs`
- `recover_cells_and_kzg_proofs`
- `verify_cell_kzg_proof_batch`

This library also provides functions for loading and freeing the trusted setup,
which are not defined in the API. The loading functions are intended to be
executed once during the initialization process. As the name suggests, the
[trusted setup file](src/trusted_setup.txt) is considered to be trustworthy.

- `load_trusted_setup`
- `load_trusted_setup_file`
- `free_trusted_setup`

## Remarks

### Tests

All bindings are tested against the KZG reference tests, which are defined in
the [consensus-spec-tests](https://github.com/ethereum/consensus-spec-tests)
repository. Additionally, a suite of unit tests for internal C functions is
located [here](src/test/tests.c).

### Parallelization

The interface functions in C-KZG-4844 are single-threaded for simplicity, as
implementing multi-threading across multiple platforms can be complex. While
performance is important, these functions are already quite fast and efficient.
For instance, `verify_blob_kzg_proof` is expected to finish in under 3ms on most
systems.

### Batched verification

When processing multiple blobs, `verify_blob_kzg_proof_batch` is more efficient
than calling `verify_blob_kzg_proof` individually. In CI tests, verifying 64
blobs in batch is 53% faster per blob than verifying them individually. For a
single blob, `verify_blob_kzg_proof_batch` calls `verify_blob_kzg_proof`, and
the overhead is negligible.

### Benchmarks

C-KZG-4844 provides benchmarks in the Go bindings. It is easier to write
benchmarks in a high-level language and doing benchmarks in the bindings offers
a more realistic performance overview, including FFI overhead. Additionally,
C-KZG-4844 is not expected to be used outside the bindings.

### Audits

C-KZG-4844's implementation for EIP-4844 was audited by [Sigma
Prime](https://sigmaprime.io/) in 2023 and its implementation for EIP-7594 was
audited by [zkSecurity](https://www.zksecurity.xyz) in 2025. You can find the
corresponding audit reports in the [`audits`](./audits/) directory.

### Why C?

The primary reason for choosing C is that
[blst](https://github.com/supranational/blst), the BLS12-381 signature library
we wanted to use, is mostly written in C. Rust was a viable alternative, but it
has some disadvantages. The C toolchain is ubiquitous, and it would be somewhat
awkward for all the bindings to depend on another toolchain, such as Rust.
Compared to Rust, C offers a lighter memory and binary footprint. Furthermore, C
serves as the de facto language for
[FFI](https://en.wikipedia.org/wiki/Foreign_function_interface), so we could not
have completely avoided using C anyway.

### Precompute

Introduced in v2.0.0, a `precompute` parameter was added to the functions which
load the trusted setup. When a non-zero value is provided, a fixed-base
multi-scalar multiplication function (instead of Pippenger's algorithm) is used
to compute cell KZG proofs. Note that the `precompute` parameter only affects
the performance of `compute_cells_and_kzg_proofs` and
`recover_cells_and_kzg_proofs`. If your application does not use these
functions, we recommend using `precompute=0`. For applications that do, we
recommend using `precompute=8` or `precompute=9`, which offer an optimal balance
between performance and memory usage.

For reference, benchmarks from a system with an Apple M1 CPU:

| Precompute | Load Time | Compute Time | Memory Size |
| ---------: | --------: | -----------: | ----------: |
|          0 |    1.69 s |    311.15 ms |       0 KiB |
|          1 |    1.70 s |    891.29 ms |     768 KiB |
|          2 |    1.69 s |    480.85 ms |    1536 KiB |
|          3 |    1.71 s |    344.99 ms |       3 MiB |
|          4 |    1.74 s |    277.46 ms |       6 MiB |
|          5 |    1.77 s |    239.71 ms |      12 MiB |
|          6 |    1.82 s |    212.18 ms |      24 MiB |
|          7 |    1.97 s |    196.78 ms |      48 MiB |
|          8 |    2.26 s |    180.71 ms |      96 MiB |
|          9 |    2.82 s |    169.72 ms |     192 MiB |
|         10 |    3.95 s |    159.83 ms |     384 MiB |
|         11 |    6.19 s |    155.72 ms |     768 MiB |
|         12 |   10.78 s |    148.54 ms |    1536 MiB |
|         13 |   19.66 s |    141.83 ms |       3 GiB |
|         14 |   37.83 s |    135.94 ms |       6 GiB |
|         15 |   74.95 s |    134.50 ms |      12 GiB |
