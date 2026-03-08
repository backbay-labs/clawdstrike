#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::unnecessary_cast)]

#[cfg(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "emscripten",
            target_os = "hurd",
            target_os = "l4re",
            target_os = "linux",
            target_os = "nto"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "android",
        target_pointer_width = "32",
        not(target_env = "newlib")
    ),
    all(
        target_os = "android",
        target_pointer_width = "64",
        not(target_env = "newlib")
    )
))]
pub use libc::rlimit64 as rlimit;

#[cfg(all(
    any(
        target_os = "vxworks",
        all(target_os = "qurt", not(target_vendor = "apple")),
        all(
            unix,
            not(any(target_os = "qurt", target_os = "solid_asp3", target_os = "switch"))
        )
    ),
    not(any(
        target_os = "fuchsia",
        all(
            any(
                target_os = "aix",
                target_os = "emscripten",
                target_os = "hurd",
                target_os = "l4re",
                target_os = "linux",
                target_os = "nto"
            ),
            not(target_env = "newlib")
        ),
        all(
            target_os = "android",
            target_pointer_width = "32",
            not(target_env = "newlib")
        ),
        all(
            target_os = "android",
            target_pointer_width = "64",
            not(target_env = "newlib")
        )
    ))
))]
pub use libc::rlimit;

#[cfg(any(
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "emscripten",
            target_os = "hurd"
        ),
        not(target_env = "newlib")
    ),
    all(target_env = "uclibc", target_os = "l4re"),
    all(target_env = "gnu", target_os = "linux"),
    all(target_os = "linux", any(target_env = "musl", target_env = "ohos")),
    all(target_env = "uclibc", target_os = "linux")
))]
pub use libc::getrlimit64 as getrlimit;

#[cfg(all(
    any(
        all(
            any(
                target_os = "aix",
                target_os = "android",
                target_os = "cygwin",
                target_os = "dragonfly",
                target_os = "emscripten",
                target_os = "freebsd",
                target_os = "haiku",
                target_os = "hurd",
                target_os = "illumos",
                target_os = "ios",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "nto",
                target_os = "openbsd",
                target_os = "redox",
                target_os = "solaris",
                target_os = "tvos",
                target_os = "visionos",
                target_os = "watchos"
            ),
            not(target_env = "newlib")
        ),
        all(
            unix,
            target_env = "newlib",
            not(any(
                target_os = "fuchsia",
                target_os = "qurt",
                target_os = "solid_asp3",
                target_os = "switch",
                target_os = "vxworks"
            ))
        )
    ),
    not(any(
        all(
            any(
                target_os = "aix",
                target_os = "android",
                target_os = "emscripten",
                target_os = "hurd"
            ),
            not(target_env = "newlib")
        ),
        all(target_env = "uclibc", target_os = "l4re"),
        all(target_env = "gnu", target_os = "linux"),
        all(target_os = "linux", any(target_env = "musl", target_env = "ohos")),
        all(target_env = "uclibc", target_os = "linux")
    ))
))]
pub use libc::getrlimit;

#[cfg(any(
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "emscripten",
            target_os = "hurd"
        ),
        not(target_env = "newlib")
    ),
    all(target_env = "uclibc", target_os = "l4re"),
    all(target_env = "gnu", target_os = "linux"),
    all(target_os = "linux", any(target_env = "musl", target_env = "ohos")),
    all(target_env = "uclibc", target_os = "linux")
))]
pub use libc::setrlimit64 as setrlimit;

#[cfg(all(
    any(
        all(
            any(
                target_os = "aix",
                target_os = "android",
                target_os = "cygwin",
                target_os = "dragonfly",
                target_os = "emscripten",
                target_os = "freebsd",
                target_os = "haiku",
                target_os = "hurd",
                target_os = "illumos",
                target_os = "ios",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "nto",
                target_os = "openbsd",
                target_os = "redox",
                target_os = "solaris",
                target_os = "tvos",
                target_os = "visionos",
                target_os = "watchos"
            ),
            not(target_env = "newlib")
        ),
        all(
            unix,
            target_env = "newlib",
            not(any(
                target_os = "fuchsia",
                target_os = "qurt",
                target_os = "solid_asp3",
                target_os = "switch",
                target_os = "vxworks"
            ))
        )
    ),
    not(any(
        all(
            any(
                target_os = "aix",
                target_os = "android",
                target_os = "emscripten",
                target_os = "hurd"
            ),
            not(target_env = "newlib")
        ),
        all(target_env = "uclibc", target_os = "l4re"),
        all(target_env = "gnu", target_os = "linux"),
        all(target_os = "linux", any(target_env = "musl", target_env = "ohos")),
        all(target_env = "uclibc", target_os = "linux")
    ))
))]
pub use libc::setrlimit;

#[cfg(any(
    all(target_os = "android", not(target_env = "newlib")),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "musl", target_env = "ohos")
    )
))]
pub use libc::prlimit64 as prlimit;

#[cfg(any(
    target_os = "fuchsia",
    all(
        target_arch = "powerpc64",
        target_os = "aix",
        not(target_env = "newlib")
    ),
    all(
        any(
            target_os = "android",
            target_os = "cygwin",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(target_env = "uclibc", target_os = "l4re"),
    all(
        target_os = "linux",
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64",
            target_env = "newlib"
        ))
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_os = "linux",
        any(target_arch = "mips64", target_arch = "mips64r6"),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_os = "linux",
        any(target_arch = "mips", target_arch = "mips32r6"),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64"),
        not(target_env = "newlib")
    ),
    all(
        target_arch = "sparc64",
        target_os = "linux",
        not(target_env = "newlib")
    ),
    all(target_arch = "sparc", target_os = "linux", not(target_env = "newlib"))
))]
pub const RLIM_INFINITY: u64 = libc::RLIM_INFINITY as u64;

#[cfg(not(any(
    target_os = "fuchsia",
    all(
        target_arch = "powerpc64",
        target_os = "aix",
        not(target_env = "newlib")
    ),
    all(
        any(
            target_os = "android",
            target_os = "cygwin",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(target_env = "uclibc", target_os = "l4re"),
    all(
        target_os = "linux",
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64",
            target_env = "newlib"
        ))
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_os = "linux",
        any(target_arch = "mips64", target_arch = "mips64r6"),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_os = "linux",
        any(target_arch = "mips", target_arch = "mips32r6"),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64"),
        not(target_env = "newlib")
    ),
    all(
        target_arch = "sparc64",
        target_os = "linux",
        not(target_env = "newlib")
    ),
    all(target_arch = "sparc", target_os = "linux", not(target_env = "newlib"))
)))]
pub const RLIM_INFINITY: u64 = u64::MAX;

#[cfg(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "cygwin",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "redox",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
))]
pub const RLIMIT_AS: u8 = libc::RLIMIT_AS as u8;

#[cfg(not(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "cygwin",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "redox",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
)))]
pub const RLIMIT_AS: u8 = u8::MAX;

#[cfg(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "cygwin",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
))]
pub const RLIMIT_CORE: u8 = libc::RLIMIT_CORE as u8;

#[cfg(not(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "cygwin",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
)))]
pub const RLIMIT_CORE: u8 = u8::MAX;

#[cfg(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "cygwin",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
))]
pub const RLIMIT_CPU: u8 = libc::RLIMIT_CPU as u8;

#[cfg(not(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "cygwin",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
)))]
pub const RLIMIT_CPU: u8 = u8::MAX;

#[cfg(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "cygwin",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
))]
pub const RLIMIT_DATA: u8 = libc::RLIMIT_DATA as u8;

#[cfg(not(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "cygwin",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
)))]
pub const RLIMIT_DATA: u8 = u8::MAX;

#[cfg(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "cygwin",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
))]
pub const RLIMIT_FSIZE: u8 = libc::RLIMIT_FSIZE as u8;

#[cfg(not(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "cygwin",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
)))]
pub const RLIMIT_FSIZE: u8 = u8::MAX;

#[cfg(all(target_os = "freebsd", not(target_env = "newlib")))]
pub const RLIMIT_KQUEUES: u8 = libc::RLIMIT_KQUEUES as u8;

#[cfg(not(all(target_os = "freebsd", not(target_env = "newlib"))))]
pub const RLIMIT_KQUEUES: u8 = u8::MAX;

#[cfg(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "android",
            target_os = "emscripten",
            target_os = "l4re",
            target_os = "redox"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
))]
pub const RLIMIT_LOCKS: u8 = libc::RLIMIT_LOCKS as u8;

#[cfg(not(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "android",
            target_os = "emscripten",
            target_os = "l4re",
            target_os = "redox"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
)))]
pub const RLIMIT_LOCKS: u8 = u8::MAX;

#[cfg(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "hurd",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
))]
pub const RLIMIT_MEMLOCK: u8 = libc::RLIMIT_MEMLOCK as u8;

#[cfg(not(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "hurd",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
)))]
pub const RLIMIT_MEMLOCK: u8 = u8::MAX;

#[cfg(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "android",
            target_os = "emscripten",
            target_os = "l4re",
            target_os = "redox"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
))]
pub const RLIMIT_MSGQUEUE: u8 = libc::RLIMIT_MSGQUEUE as u8;

#[cfg(not(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "android",
            target_os = "emscripten",
            target_os = "l4re",
            target_os = "redox"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
)))]
pub const RLIMIT_MSGQUEUE: u8 = u8::MAX;

#[cfg(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "android",
            target_os = "emscripten",
            target_os = "l4re",
            target_os = "redox"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
))]
pub const RLIMIT_NICE: u8 = libc::RLIMIT_NICE as u8;

#[cfg(not(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "android",
            target_os = "emscripten",
            target_os = "l4re",
            target_os = "redox"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
)))]
pub const RLIMIT_NICE: u8 = u8::MAX;

#[cfg(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "cygwin",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
))]
pub const RLIMIT_NOFILE: u8 = libc::RLIMIT_NOFILE as u8;

#[cfg(not(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "cygwin",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
)))]
pub const RLIMIT_NOFILE: u8 = u8::MAX;

#[cfg(all(target_os = "haiku", not(target_env = "newlib")))]
pub const RLIMIT_NOVMON: u8 = libc::RLIMIT_NOVMON as u8;

#[cfg(not(all(target_os = "haiku", not(target_env = "newlib"))))]
pub const RLIMIT_NOVMON: u8 = u8::MAX;

#[cfg(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "hurd",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
))]
pub const RLIMIT_NPROC: u8 = libc::RLIMIT_NPROC as u8;

#[cfg(not(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "hurd",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
)))]
pub const RLIMIT_NPROC: u8 = u8::MAX;

#[cfg(all(target_os = "freebsd", not(target_env = "newlib")))]
pub const RLIMIT_NPTS: u8 = libc::RLIMIT_NPTS as u8;

#[cfg(not(all(target_os = "freebsd", not(target_env = "newlib"))))]
pub const RLIMIT_NPTS: u8 = u8::MAX;

#[cfg(all(target_os = "netbsd", not(target_env = "newlib")))]
pub const RLIMIT_NTHR: u8 = libc::RLIMIT_NTHR as u8;

#[cfg(not(all(target_os = "netbsd", not(target_env = "newlib"))))]
pub const RLIMIT_NTHR: u8 = u8::MAX;

#[cfg(all(target_os = "dragonfly", not(target_env = "newlib")))]
pub const RLIMIT_POSIXLOCKS: u8 = libc::RLIMIT_POSIXLOCKS as u8;

#[cfg(not(all(target_os = "dragonfly", not(target_env = "newlib"))))]
pub const RLIMIT_POSIXLOCKS: u8 = u8::MAX;

#[cfg(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "hurd",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
))]
pub const RLIMIT_RSS: u8 = libc::RLIMIT_RSS as u8;

#[cfg(not(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "hurd",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
)))]
pub const RLIMIT_RSS: u8 = u8::MAX;

#[cfg(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "android",
            target_os = "emscripten",
            target_os = "l4re",
            target_os = "redox"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
))]
pub const RLIMIT_RTPRIO: u8 = libc::RLIMIT_RTPRIO as u8;

#[cfg(not(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "android",
            target_os = "emscripten",
            target_os = "l4re",
            target_os = "redox"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
)))]
pub const RLIMIT_RTPRIO: u8 = u8::MAX;

#[cfg(any(
    target_os = "fuchsia",
    all(target_os = "l4re", not(target_env = "newlib")),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
))]
pub const RLIMIT_RTTIME: u8 = libc::RLIMIT_RTTIME as u8;

#[cfg(not(any(
    target_os = "fuchsia",
    all(target_os = "l4re", not(target_env = "newlib")),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
)))]
pub const RLIMIT_RTTIME: u8 = u8::MAX;

#[cfg(all(
    any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "hurd",
        target_os = "netbsd"
    ),
    not(target_env = "newlib")
))]
pub const RLIMIT_SBSIZE: u8 = libc::RLIMIT_SBSIZE as u8;

#[cfg(not(all(
    any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "hurd",
        target_os = "netbsd"
    ),
    not(target_env = "newlib")
)))]
pub const RLIMIT_SBSIZE: u8 = u8::MAX;

#[cfg(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "android",
            target_os = "emscripten",
            target_os = "l4re",
            target_os = "redox"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
))]
pub const RLIMIT_SIGPENDING: u8 = libc::RLIMIT_SIGPENDING as u8;

#[cfg(not(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "android",
            target_os = "emscripten",
            target_os = "l4re",
            target_os = "redox"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
)))]
pub const RLIMIT_SIGPENDING: u8 = u8::MAX;

#[cfg(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "cygwin",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
))]
pub const RLIMIT_STACK: u8 = libc::RLIMIT_STACK as u8;

#[cfg(not(any(
    target_os = "fuchsia",
    all(
        any(
            target_os = "aix",
            target_os = "android",
            target_os = "cygwin",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "l4re",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "nto",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ),
        not(target_env = "newlib")
    ),
    all(
        target_os = "linux",
        any(target_env = "gnu", target_env = "uclibc"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(target_env = "musl", target_env = "ohos"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ),
    all(
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        ),
        any(target_env = "gnu", target_env = "uclibc")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ),
    all(
        target_env = "gnu",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_env = "musl",
        target_os = "linux",
        any(target_arch = "powerpc", target_arch = "powerpc64")
    ),
    all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64"),
        not(target_env = "newlib")
    )
)))]
pub const RLIMIT_STACK: u8 = u8::MAX;

#[cfg(all(target_os = "freebsd", not(target_env = "newlib")))]
pub const RLIMIT_SWAP: u8 = libc::RLIMIT_SWAP as u8;

#[cfg(not(all(target_os = "freebsd", not(target_env = "newlib"))))]
pub const RLIMIT_SWAP: u8 = u8::MAX;

#[cfg(all(target_os = "aix", not(target_env = "newlib")))]
pub const RLIMIT_THREADS: u8 = libc::RLIMIT_THREADS as u8;

#[cfg(not(all(target_os = "aix", not(target_env = "newlib"))))]
pub const RLIMIT_THREADS: u8 = u8::MAX;

#[cfg(all(target_os = "freebsd", not(target_env = "newlib")))]
pub const RLIMIT_UMTXP: u8 = libc::RLIMIT_UMTXP as u8;

#[cfg(not(all(target_os = "freebsd", not(target_env = "newlib"))))]
pub const RLIMIT_UMTXP: u8 = u8::MAX;

#[cfg(all(
    any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "hurd",
        target_os = "illumos",
        target_os = "nto",
        target_os = "solaris"
    ),
    not(target_env = "newlib")
))]
pub const RLIMIT_VMEM: u8 = libc::RLIMIT_VMEM as u8;

#[cfg(not(all(
    any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "hurd",
        target_os = "illumos",
        target_os = "nto",
        target_os = "solaris"
    ),
    not(target_env = "newlib")
)))]
pub const RLIMIT_VMEM: u8 = u8::MAX;

#[cfg(test)]
mod tests {
    #[allow(clippy::too_many_lines)]
    #[test]
    fn resource_range() {
        #[cfg(any(
            target_os = "fuchsia",
            all(
                any(
                    target_os = "aix",
                    target_os = "android",
                    target_os = "cygwin",
                    target_os = "dragonfly",
                    target_os = "emscripten",
                    target_os = "freebsd",
                    target_os = "haiku",
                    target_os = "hurd",
                    target_os = "illumos",
                    target_os = "ios",
                    target_os = "l4re",
                    target_os = "macos",
                    target_os = "netbsd",
                    target_os = "nto",
                    target_os = "redox",
                    target_os = "solaris",
                    target_os = "tvos",
                    target_os = "visionos",
                    target_os = "watchos"
                ),
                not(target_env = "newlib")
            ),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "uclibc"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(target_env = "musl", target_env = "ohos"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ),
                any(target_env = "gnu", target_env = "uclibc")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                )
            ),
            all(
                target_env = "gnu",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_os = "linux",
                any(target_arch = "sparc", target_arch = "sparc64"),
                not(target_env = "newlib")
            )
        ))]
        assert!((0..128).contains(&libc::RLIMIT_AS));

        #[cfg(any(
            target_os = "fuchsia",
            all(
                any(
                    target_os = "aix",
                    target_os = "android",
                    target_os = "cygwin",
                    target_os = "dragonfly",
                    target_os = "emscripten",
                    target_os = "freebsd",
                    target_os = "haiku",
                    target_os = "hurd",
                    target_os = "illumos",
                    target_os = "ios",
                    target_os = "l4re",
                    target_os = "macos",
                    target_os = "netbsd",
                    target_os = "nto",
                    target_os = "openbsd",
                    target_os = "redox",
                    target_os = "solaris",
                    target_os = "tvos",
                    target_os = "visionos",
                    target_os = "watchos"
                ),
                not(target_env = "newlib")
            ),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "uclibc"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(target_env = "musl", target_env = "ohos"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ),
                any(target_env = "gnu", target_env = "uclibc")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                )
            ),
            all(
                target_env = "gnu",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_os = "linux",
                any(target_arch = "sparc", target_arch = "sparc64"),
                not(target_env = "newlib")
            )
        ))]
        assert!((0..128).contains(&libc::RLIMIT_CORE));

        #[cfg(any(
            target_os = "fuchsia",
            all(
                any(
                    target_os = "aix",
                    target_os = "android",
                    target_os = "cygwin",
                    target_os = "dragonfly",
                    target_os = "emscripten",
                    target_os = "freebsd",
                    target_os = "haiku",
                    target_os = "hurd",
                    target_os = "illumos",
                    target_os = "ios",
                    target_os = "l4re",
                    target_os = "macos",
                    target_os = "netbsd",
                    target_os = "nto",
                    target_os = "openbsd",
                    target_os = "redox",
                    target_os = "solaris",
                    target_os = "tvos",
                    target_os = "visionos",
                    target_os = "watchos"
                ),
                not(target_env = "newlib")
            ),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "uclibc"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(target_env = "musl", target_env = "ohos"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ),
                any(target_env = "gnu", target_env = "uclibc")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                )
            ),
            all(
                target_env = "gnu",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_os = "linux",
                any(target_arch = "sparc", target_arch = "sparc64"),
                not(target_env = "newlib")
            )
        ))]
        assert!((0..128).contains(&libc::RLIMIT_CPU));

        #[cfg(any(
            target_os = "fuchsia",
            all(
                any(
                    target_os = "aix",
                    target_os = "android",
                    target_os = "cygwin",
                    target_os = "dragonfly",
                    target_os = "emscripten",
                    target_os = "freebsd",
                    target_os = "haiku",
                    target_os = "hurd",
                    target_os = "illumos",
                    target_os = "ios",
                    target_os = "l4re",
                    target_os = "macos",
                    target_os = "netbsd",
                    target_os = "nto",
                    target_os = "openbsd",
                    target_os = "redox",
                    target_os = "solaris",
                    target_os = "tvos",
                    target_os = "visionos",
                    target_os = "watchos"
                ),
                not(target_env = "newlib")
            ),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "uclibc"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(target_env = "musl", target_env = "ohos"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ),
                any(target_env = "gnu", target_env = "uclibc")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                )
            ),
            all(
                target_env = "gnu",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_os = "linux",
                any(target_arch = "sparc", target_arch = "sparc64"),
                not(target_env = "newlib")
            )
        ))]
        assert!((0..128).contains(&libc::RLIMIT_DATA));

        #[cfg(any(
            target_os = "fuchsia",
            all(
                any(
                    target_os = "aix",
                    target_os = "android",
                    target_os = "cygwin",
                    target_os = "dragonfly",
                    target_os = "emscripten",
                    target_os = "freebsd",
                    target_os = "haiku",
                    target_os = "hurd",
                    target_os = "illumos",
                    target_os = "ios",
                    target_os = "l4re",
                    target_os = "macos",
                    target_os = "netbsd",
                    target_os = "nto",
                    target_os = "openbsd",
                    target_os = "redox",
                    target_os = "solaris",
                    target_os = "tvos",
                    target_os = "visionos",
                    target_os = "watchos"
                ),
                not(target_env = "newlib")
            ),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "uclibc"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(target_env = "musl", target_env = "ohos"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ),
                any(target_env = "gnu", target_env = "uclibc")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                )
            ),
            all(
                target_env = "gnu",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_os = "linux",
                any(target_arch = "sparc", target_arch = "sparc64"),
                not(target_env = "newlib")
            )
        ))]
        assert!((0..128).contains(&libc::RLIMIT_FSIZE));

        #[cfg(all(target_os = "freebsd", not(target_env = "newlib")))]
        assert!((0..128).contains(&libc::RLIMIT_KQUEUES));

        #[cfg(any(
            target_os = "fuchsia",
            all(
                any(
                    target_os = "android",
                    target_os = "emscripten",
                    target_os = "l4re",
                    target_os = "redox"
                ),
                not(target_env = "newlib")
            ),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "uclibc"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(target_env = "musl", target_env = "ohos"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ),
                any(target_env = "gnu", target_env = "uclibc")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                )
            ),
            all(
                target_env = "gnu",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_os = "linux",
                any(target_arch = "sparc", target_arch = "sparc64"),
                not(target_env = "newlib")
            )
        ))]
        assert!((0..128).contains(&libc::RLIMIT_LOCKS));

        #[cfg(any(
            target_os = "fuchsia",
            all(
                any(
                    target_os = "android",
                    target_os = "dragonfly",
                    target_os = "emscripten",
                    target_os = "freebsd",
                    target_os = "hurd",
                    target_os = "ios",
                    target_os = "l4re",
                    target_os = "macos",
                    target_os = "netbsd",
                    target_os = "nto",
                    target_os = "openbsd",
                    target_os = "redox",
                    target_os = "tvos",
                    target_os = "visionos",
                    target_os = "watchos"
                ),
                not(target_env = "newlib")
            ),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "uclibc"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(target_env = "musl", target_env = "ohos"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ),
                any(target_env = "gnu", target_env = "uclibc")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                )
            ),
            all(
                target_env = "gnu",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_os = "linux",
                any(target_arch = "sparc", target_arch = "sparc64"),
                not(target_env = "newlib")
            )
        ))]
        assert!((0..128).contains(&libc::RLIMIT_MEMLOCK));

        #[cfg(any(
            target_os = "fuchsia",
            all(
                any(
                    target_os = "android",
                    target_os = "emscripten",
                    target_os = "l4re",
                    target_os = "redox"
                ),
                not(target_env = "newlib")
            ),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "uclibc"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(target_env = "musl", target_env = "ohos"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ),
                any(target_env = "gnu", target_env = "uclibc")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                )
            ),
            all(
                target_env = "gnu",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_os = "linux",
                any(target_arch = "sparc", target_arch = "sparc64"),
                not(target_env = "newlib")
            )
        ))]
        assert!((0..128).contains(&libc::RLIMIT_MSGQUEUE));

        #[cfg(any(
            target_os = "fuchsia",
            all(
                any(
                    target_os = "android",
                    target_os = "emscripten",
                    target_os = "l4re",
                    target_os = "redox"
                ),
                not(target_env = "newlib")
            ),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "uclibc"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(target_env = "musl", target_env = "ohos"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ),
                any(target_env = "gnu", target_env = "uclibc")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                )
            ),
            all(
                target_env = "gnu",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_os = "linux",
                any(target_arch = "sparc", target_arch = "sparc64"),
                not(target_env = "newlib")
            )
        ))]
        assert!((0..128).contains(&libc::RLIMIT_NICE));

        #[cfg(any(
            target_os = "fuchsia",
            all(
                any(
                    target_os = "aix",
                    target_os = "android",
                    target_os = "cygwin",
                    target_os = "dragonfly",
                    target_os = "emscripten",
                    target_os = "freebsd",
                    target_os = "haiku",
                    target_os = "hurd",
                    target_os = "illumos",
                    target_os = "ios",
                    target_os = "l4re",
                    target_os = "macos",
                    target_os = "netbsd",
                    target_os = "nto",
                    target_os = "openbsd",
                    target_os = "redox",
                    target_os = "solaris",
                    target_os = "tvos",
                    target_os = "visionos",
                    target_os = "watchos"
                ),
                not(target_env = "newlib")
            ),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "uclibc"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(target_env = "musl", target_env = "ohos"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ),
                any(target_env = "gnu", target_env = "uclibc")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                )
            ),
            all(
                target_env = "gnu",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_os = "linux",
                any(target_arch = "sparc", target_arch = "sparc64"),
                not(target_env = "newlib")
            )
        ))]
        assert!((0..128).contains(&libc::RLIMIT_NOFILE));

        #[cfg(all(target_os = "haiku", not(target_env = "newlib")))]
        assert!((0..128).contains(&libc::RLIMIT_NOVMON));

        #[cfg(any(
            target_os = "fuchsia",
            all(
                any(
                    target_os = "aix",
                    target_os = "android",
                    target_os = "dragonfly",
                    target_os = "emscripten",
                    target_os = "freebsd",
                    target_os = "hurd",
                    target_os = "ios",
                    target_os = "l4re",
                    target_os = "macos",
                    target_os = "netbsd",
                    target_os = "nto",
                    target_os = "openbsd",
                    target_os = "redox",
                    target_os = "tvos",
                    target_os = "visionos",
                    target_os = "watchos"
                ),
                not(target_env = "newlib")
            ),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "uclibc"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(target_env = "musl", target_env = "ohos"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ),
                any(target_env = "gnu", target_env = "uclibc")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                )
            ),
            all(
                target_env = "gnu",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_os = "linux",
                any(target_arch = "sparc", target_arch = "sparc64"),
                not(target_env = "newlib")
            )
        ))]
        assert!((0..128).contains(&libc::RLIMIT_NPROC));

        #[cfg(all(target_os = "freebsd", not(target_env = "newlib")))]
        assert!((0..128).contains(&libc::RLIMIT_NPTS));

        #[cfg(all(target_os = "netbsd", not(target_env = "newlib")))]
        assert!((0..128).contains(&libc::RLIMIT_NTHR));

        #[cfg(all(target_os = "dragonfly", not(target_env = "newlib")))]
        assert!((0..128).contains(&libc::RLIMIT_POSIXLOCKS));

        #[cfg(any(
            target_os = "fuchsia",
            all(
                any(
                    target_os = "aix",
                    target_os = "android",
                    target_os = "dragonfly",
                    target_os = "emscripten",
                    target_os = "freebsd",
                    target_os = "hurd",
                    target_os = "ios",
                    target_os = "l4re",
                    target_os = "macos",
                    target_os = "netbsd",
                    target_os = "nto",
                    target_os = "openbsd",
                    target_os = "redox",
                    target_os = "tvos",
                    target_os = "visionos",
                    target_os = "watchos"
                ),
                not(target_env = "newlib")
            ),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "uclibc"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(target_env = "musl", target_env = "ohos"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ),
                any(target_env = "gnu", target_env = "uclibc")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                )
            ),
            all(
                target_env = "gnu",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_os = "linux",
                any(target_arch = "sparc", target_arch = "sparc64"),
                not(target_env = "newlib")
            )
        ))]
        assert!((0..128).contains(&libc::RLIMIT_RSS));

        #[cfg(any(
            target_os = "fuchsia",
            all(
                any(
                    target_os = "android",
                    target_os = "emscripten",
                    target_os = "l4re",
                    target_os = "redox"
                ),
                not(target_env = "newlib")
            ),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "uclibc"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(target_env = "musl", target_env = "ohos"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ),
                any(target_env = "gnu", target_env = "uclibc")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                )
            ),
            all(
                target_env = "gnu",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_os = "linux",
                any(target_arch = "sparc", target_arch = "sparc64"),
                not(target_env = "newlib")
            )
        ))]
        assert!((0..128).contains(&libc::RLIMIT_RTPRIO));

        #[cfg(any(
            target_os = "fuchsia",
            all(target_os = "l4re", not(target_env = "newlib")),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "uclibc"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(target_env = "musl", target_env = "ohos"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ),
                any(target_env = "gnu", target_env = "uclibc")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                )
            ),
            all(
                target_env = "gnu",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_os = "linux",
                any(target_arch = "sparc", target_arch = "sparc64"),
                not(target_env = "newlib")
            )
        ))]
        assert!((0..128).contains(&libc::RLIMIT_RTTIME));

        #[cfg(all(
            any(
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "hurd",
                target_os = "netbsd"
            ),
            not(target_env = "newlib")
        ))]
        assert!((0..128).contains(&libc::RLIMIT_SBSIZE));

        #[cfg(any(
            target_os = "fuchsia",
            all(
                any(
                    target_os = "android",
                    target_os = "emscripten",
                    target_os = "l4re",
                    target_os = "redox"
                ),
                not(target_env = "newlib")
            ),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "uclibc"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(target_env = "musl", target_env = "ohos"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ),
                any(target_env = "gnu", target_env = "uclibc")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                )
            ),
            all(
                target_env = "gnu",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_os = "linux",
                any(target_arch = "sparc", target_arch = "sparc64"),
                not(target_env = "newlib")
            )
        ))]
        assert!((0..128).contains(&libc::RLIMIT_SIGPENDING));

        #[cfg(any(
            target_os = "fuchsia",
            all(
                any(
                    target_os = "aix",
                    target_os = "android",
                    target_os = "cygwin",
                    target_os = "dragonfly",
                    target_os = "emscripten",
                    target_os = "freebsd",
                    target_os = "haiku",
                    target_os = "hurd",
                    target_os = "illumos",
                    target_os = "ios",
                    target_os = "l4re",
                    target_os = "macos",
                    target_os = "netbsd",
                    target_os = "nto",
                    target_os = "openbsd",
                    target_os = "redox",
                    target_os = "solaris",
                    target_os = "tvos",
                    target_os = "visionos",
                    target_os = "watchos"
                ),
                not(target_env = "newlib")
            ),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "uclibc"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(target_env = "musl", target_env = "ohos"),
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64"
                ))
            ),
            all(
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ),
                any(target_env = "gnu", target_env = "uclibc")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                )
            ),
            all(
                target_env = "gnu",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_env = "musl",
                target_os = "linux",
                any(target_arch = "powerpc", target_arch = "powerpc64")
            ),
            all(
                target_os = "linux",
                any(target_arch = "sparc", target_arch = "sparc64"),
                not(target_env = "newlib")
            )
        ))]
        assert!((0..128).contains(&libc::RLIMIT_STACK));

        #[cfg(all(target_os = "freebsd", not(target_env = "newlib")))]
        assert!((0..128).contains(&libc::RLIMIT_SWAP));

        #[cfg(all(target_os = "aix", not(target_env = "newlib")))]
        assert!((0..128).contains(&libc::RLIMIT_THREADS));

        #[cfg(all(target_os = "freebsd", not(target_env = "newlib")))]
        assert!((0..128).contains(&libc::RLIMIT_UMTXP));

        #[cfg(all(
            any(
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "hurd",
                target_os = "illumos",
                target_os = "nto",
                target_os = "solaris"
            ),
            not(target_env = "newlib")
        ))]
        assert!((0..128).contains(&libc::RLIMIT_VMEM));
    }
}
