# Unreleased

# 0.3.0 – 2023-10-19

## Breaking

* [feat: add backoff feature](https://github.com/rust-osdev/spinning_top/pull/16)
* [chore: remove `const_spinlock` function](https://github.com/rust-osdev/spinning_top/pull/20)
* [chore: remove deprecated `nightly` feature](https://github.com/rust-osdev/spinning_top/pull/21)

## Improvements

* [feat: add `RwSpinlock` readers-writer lock](https://github.com/rust-osdev/spinning_top/pull/18)
* [feat: add `arc_lock` feature and typedefs](https://github.com/rust-osdev/spinning_top/pull/25)
* [perf: inline everything](https://github.com/rust-osdev/spinning_top/pull/17)
* [docs: fix typo](https://github.com/rust-osdev/spinning_top/pull/23)

## Other

* [ci: build with all features](https://github.com/rust-osdev/spinning_top/pull/19)
* [test: don't ignore statics example](https://github.com/rust-osdev/spinning_top/pull/22)

# 0.2.5 – 2023-02-24

- Upgrade `lock_api` to 0.4.7. This makes `Spinlock::new` a `const` function without needing nightly rust.

# 0.2.4 – 2021-05-13

- Define `MappedSpinlockGuard` alias [#12](https://github.com/rust-osdev/spinning_top/pull/12)
  - makes use of `SpinlockGuard::map` easier

# 0.2.3 – 2021-04-01

- Fix `spin_loop_hint` warning on Rust 1.51

# 0.2.2 – 2020-08-24

- Add owning_ref support ([#7](https://github.com/rust-osdev/spinning_top/pull/7))

# 0.2.1 – 2020-07-07

- Implement `const_spinlock` convenience function ([#5](https://github.com/rust-osdev/spinning_top/pull/5))

# 0.2.0 – 2020-07-06

- **Breaking:** Upgrade `lock_api` to 0.4.0 ([#3](https://github.com/rust-osdev/spinning_top/pull/3))

# 0.1.1

- Implement `try_lock_weak` for use in `lock` loop ([#4](https://github.com/rust-osdev/spinning_top/pull/4))

# 0.1.0

- Initial Commit
