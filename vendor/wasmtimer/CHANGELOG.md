# CHANGELOG

## 0.4.3

- Update Instant derives [#29](https://github.com/whizsid/wasmtimer-rs/pull/29).

## 0.4.2

- Fixed 'sleep_until() does not wake up until 5 seconds' issue [#22](https://github.com/whizsid/wasmtimer-rs/issues/22), [#27](https://github.com/whizsid/wasmtimer-rs/pull/27).

## 0.4.1

- Fixing the `set_timeout` failure on dev profile [#18](https://github.com/whizsid/wasmtimer-rs/issues/18), [#23](https://github.com/whizsid/wasmtimer-rs/pull/23).

## 0.4.0

- Added a NodeJS example project [#19](https://github.com/whizsid/wasmtimer-rs/pull/19).
- Changed the behavior of `tokio::interval` to do the first tick immediately as in the original `tokio` crate [#20](https://github.com/whizsid/wasmtimer-rs/pull/20), [#12](https://github.com/whizsid/wasmtimer-rs/issues/12).

## 0.3.0

- Added new methods (`checked_duration_since`, `saturating_duration_since`, `checked_add` and `checked_sub`) to `std::time::Instant`. [#16](https://github.com/whizsid/wasmtimer-rs/pull/16), [#9](https://github.com/whizsid/wasmtimer-rs/issues/9).
- Fixed micro seconds precision lost issue. [#10](https://github.com/whizsid/wasmtimer-rs/issues/10)

## 0.2.1

- Fixed the clippy warnings [#14](https://github.com/whizsid/wasmtimer-rs/pull/14).
- Implemented the `Debug`, `Copy`, `Clone` and `Display` traits for `std::time::SystemTime` [#13](https://github.com/whizsid/wasmtimer-rs/pull/13).
- Fixed the example on README file [#11](https://github.com/whizsid/wasmtimer-rs/pull/11).

## 0.2.0

- Used `performance.now()` and `setTimeout` from global scope instead of window [#7](https://github.com/whizsid/wasmtimer-rs/pull/7).
- NodeJS Support [#3](https://github.com/whizsid/wasmtimer-rs/issues/3).
- Web Worker Support [#5](https://github.com/whizsid/wasmtimer-rs/issues/5).

## 0.1.0

- Added serde support under a feature flag `serde` [#6](https://github.com/whizsid/wasmtimer-rs/pull/6), [#1](https://github.com/whizsid/wasmtimer-rs/issues/1).
- Changed the version requirements of dependencies to match future versions.

## 0.0.1

- Initial version with tokio, tokio_util, std APIs
