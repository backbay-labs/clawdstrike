#!/bin/bash -ex

if [ ! -d "temp/libc" ]; then
    mkdir -p temp

    pushd temp
        git clone https://github.com/rust-lang/libc.git -b main --depth=1
    popd
fi
