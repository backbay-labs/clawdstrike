fn main() {
    // No-op. The hush.h header is checked into the repo and regenerated
    // manually with cbindgen when the C API surface changes:
    //
    //   cargo install cbindgen
    //   cbindgen --crate hush-ffi -o crates/libs/hush-ffi/hush.h
}
