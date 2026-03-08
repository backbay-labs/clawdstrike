#!/bin/bash -e
./scripts/download-libc.sh
cargo run -p rlimit-codegen
rustfmt src/bindings.rs \
        src/resource/generated.rs \
        build.rs
cargo fmt
echo "done"
