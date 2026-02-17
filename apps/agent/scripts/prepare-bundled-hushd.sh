#!/usr/bin/env sh
set -eu

profile="${1:-release}"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/../../.." && pwd)
src_tauri_dir=$(CDPATH= cd -- "${script_dir}/../src-tauri" && pwd)

case "$profile" in
  dev)
    cargo build -p hushd --manifest-path "${repo_root}/Cargo.toml"
    src_bin="${repo_root}/target/debug/hushd"
    ;;
  release)
    cargo build -p hushd --release --manifest-path "${repo_root}/Cargo.toml"
    src_bin="${repo_root}/target/release/hushd"
    ;;
  *)
    echo "Unsupported profile '${profile}'. Use 'dev' or 'release'." >&2
    exit 1
    ;;
esac

dst_bin="${src_tauri_dir}/resources/bin/hushd"
mkdir -p "$(dirname "${dst_bin}")"
install -m 0755 "${src_bin}" "${dst_bin}"
echo "Prepared bundled hushd at ${dst_bin}"
