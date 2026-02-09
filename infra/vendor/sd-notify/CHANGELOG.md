# Changelog

## [0.4.5] - 2025-01-18

### Fixed

 - fixed a dubious transmute between different slice types

## [0.4.4] - 2025-01-16

### Added

 - added `NotifyState::MonotonicUsec`, for use with `Type=notify-reload`

## [0.4.3] - 2024-10-05

### Added

 - added `notify_with_fds` and `listen_fds_with_names`, for storing and retrieving file descriptors

## [0.4.2] - 2024-07-03

### Fixed

- fixed `listen_fds` to use the right value of `FD_CLOEXEC`

## [0.4.1] - 2022-08-31

### Changed

- added `watchdog_enabled` (similar to [`sd_watchdog_enabled`](https://www.freedesktop.org/software/systemd/man/sd_watchdog_enabled.html))

## [0.4.0] - 2022-01-12

### Changed

- (breaking) `NotifyState::Status`, `NotifyState::BusError` and `NotifyState::Custom` now contain a `&str` instead of a `String`
- the crate is now using the 2021 edition

## [0.3.0] - 2021-02-25

### Changed

- (breaking) `listen_fds` now returns an iterator over `RawFd` values
- (breaking) `SD_LISTEN_FDS_START` is gone

## [0.2.0] - 2021-02-18

### Changed

- (breaking) changed the `NotifyState::MainPid` and `NotifyState::Error` data from `i32` to `u32`
- (breaking) changed `listen_fds` to return `Result<u32>` instead of `Result<i32>`

### Fixed

- fixed `Display` implementation for `NotifyState::WatchdogUsec` and `NotifyState::ExtendTimeoutUsec`
- removed a stray debug print

## [0.1.1] - 2019-10-20

### Added

- `listen_fds` function for file descriptor retrieval when using socket activation

## [0.1.0] - 2019-09-22

### Added

- initial release
