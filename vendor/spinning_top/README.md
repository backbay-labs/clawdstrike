# spinning_top

<img alt="image of a spinning top" align="right" src="img/top.png" height=120px>

[![Build Status](https://github.com/rust-osdev/spinning_top/workflows/Build/badge.svg)](https://github.com/rust-osdev/spinning_top/actions?query=workflow%3ABuild) [![Docs.rs Badge](https://docs.rs/spinning_top/badge.svg)](https://docs.rs/spinning_top/)

A simple spinlock crate based on the abstractions provided by [`lock_api`].

[`lock_api`]: https://docs.rs/lock_api/

## Example

First, import the crate as a dependency in your `Cargo.toml`. Then you can use it in the following way:

```rust
use spinning_top::Spinlock;

fn main() {
    // Wrap some data in a spinlock
    let data = String::from("Hello");
    let spinlock = Spinlock::new(data);
    make_uppercase(&spinlock); // only pass a shared reference
    // We have ownership of the spinlock, so we can extract the data without locking
    // Note: this consumes the spinlock
    let data = spinlock.into_inner();
    assert_eq!(data.as_str(), "HELLO");
}

fn make_uppercase(spinlock: &Spinlock<String>) {
    // Lock the spinlock to get a mutable reference to the data
    let mut locked_data = spinlock.lock();
    assert_eq!(locked_data.as_str(), "Hello");
    locked_data.make_ascii_uppercase();

    // the lock is automatically freed at the end of the scope
}
```

`Spinlock::new` is a `const` function. This makes the `Spinlock` type
usable in statics:

```rust
use spinning_top::Spinlock;

static DATA: Spinlock<u32> = Spinlock::new(0);

fn main() {
    let mut data = DATA.lock();
    *data += 1;
    assert_eq!(*data, 1);
}
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
