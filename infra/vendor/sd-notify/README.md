# `sd-notify`

[![Actions Status]][github actions] [![Latest Version]][crates.io] [![API docs]][docs.rs]

[Actions Status]: https://github.com/lnicola/sd-notify/workflows/ci/badge.svg
[github actions]: https://github.com/lnicola/sd-notify/actions
[Latest Version]: https://img.shields.io/crates/v/sd-notify.svg
[crates.io]: https://crates.io/crates/sd-notify
[API docs]: https://docs.rs/sd-notify/badge.svg
[docs.rs]: https://docs.rs/sd-notify/

A lightweight crate for sending `systemd` service state notifications.

## Quick start

```rust
let _ = sd_notify::notify(true, &[NotifyState::Ready]);
```

## Releases

Release notes are available in [CHANGELOG.md](CHANGELOG.md).

## License

This project is licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   [http://www.apache.org/licenses/LICENSE-2.0][LICENSE-APACHE])
* MIT license ([LICENSE-MIT](LICENSE-MIT) or
   [http://opensource.org/licenses/MIT][LICENSE-MIT])

at your option.

[LICENSE-APACHE]: http://www.apache.org/licenses/LICENSE-2.0
[LICENSE-MIT]: http://opensource.org/licenses/MIT
