#!/usr/bin/env sh
set -eu

profile="${1:-release}"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/../../.." && pwd)
src_tauri_dir=$(CDPATH= cd -- "${script_dir}/../src-tauri" && pwd)
control_console_dir="${repo_root}/apps/control-console"
case "${OS:-}" in
  Windows_NT)
    hushd_bin="hushd.exe"
    brokerd_bin="clawdstrike-brokerd.exe"
    ;;
  *)
    hushd_bin="hushd"
    brokerd_bin="clawdstrike-brokerd"
    ;;
esac

case "$(uname -s 2>/dev/null || true)" in
  MINGW*|MSYS*|CYGWIN*)
    hushd_bin="hushd.exe"
    brokerd_bin="clawdstrike-brokerd.exe"
    ;;
esac

case "$profile" in
  dev)
    cargo build -p hushd --manifest-path "${repo_root}/Cargo.toml"
    cargo build -p clawdstrike-brokerd --manifest-path "${repo_root}/Cargo.toml"
    hushd_src_bin="${repo_root}/target/debug/${hushd_bin}"
    brokerd_src_bin="${repo_root}/target/debug/${brokerd_bin}"
    ;;
  release)
    cargo build -p hushd --release --manifest-path "${repo_root}/Cargo.toml"
    cargo build -p clawdstrike-brokerd --release --manifest-path "${repo_root}/Cargo.toml"
    hushd_src_bin="${repo_root}/target/release/${hushd_bin}"
    brokerd_src_bin="${repo_root}/target/release/${brokerd_bin}"
    ;;
  *)
    echo "Unsupported profile '${profile}'. Use 'dev' or 'release'." >&2
    exit 1
    ;;
esac

resources_bin_dir="${src_tauri_dir}/resources/bin"
mkdir -p "${resources_bin_dir}"

install -m 0755 "${hushd_src_bin}" "${resources_bin_dir}/${hushd_bin}"
echo "Prepared bundled hushd at ${resources_bin_dir}/${hushd_bin}"

install -m 0755 "${brokerd_src_bin}" "${resources_bin_dir}/${brokerd_bin}"
echo "Prepared bundled brokerd at ${resources_bin_dir}/${brokerd_bin}"

if [ ! -d "${control_console_dir}/node_modules" ]; then
  npm --prefix "${control_console_dir}" ci
fi

VITE_BASE_PATH="/ui/" npm --prefix "${control_console_dir}" run build

dashboard_src="${control_console_dir}/dist"
dashboard_dst="${src_tauri_dir}/resources/control-console"
rm -rf "${dashboard_dst}"
mkdir -p "${dashboard_dst}"
cp -R "${dashboard_src}/." "${dashboard_dst}/"
echo "Prepared bundled control console at ${dashboard_dst}"
