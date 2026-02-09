# wasmtimer-rs

An implementation of `time` based functionalities from `std::time`, `tokio::time`,
`tokio_util::time` for WASM targets. This crate tries to closely
replicate above APIs. Users only have to change their `use` scripts by
using a `cfg` macro.

```rust
#[cfg(not(target_family="wasm"))]
use tokio::time::*;
#[cfg(target_family="wasm")]
use wasmtimer::tokio::*;
```

Check the [API Documentation](https://docs.rs/wasmtimer) for more
details.

## Story

Core idea and core modules in `src/timer` folder were copied from
[this](https://github.com/tomaka/wasm-timer) crate. This crate is
abandoned now due to lack of maintainability. I've hard forked it,
added some additional features and released to use for
[this](https://github.com/google/tarpc/pull/388) PR.

## `tokio::time` vs `wasmtimer`

- `wasmtimer` is only running on WASM browser targets and not using any
`tokio` feature as a dependency.
- This timer crate not supporting
[Auto-advance](https://docs.rs/tokio/latest/tokio/time/fn.pause.html#auto-advance)
like in the tokio crate. Because we can not track the background
tasks(`Promise`) in browser scope. If we implemented such without caring
about background tasks, then this implementation will not match with the
tokio's original implementation.

## Features

- Serde Support (`serde` feature flag)
- Worker and NodeJS Support
- Test Utilities
