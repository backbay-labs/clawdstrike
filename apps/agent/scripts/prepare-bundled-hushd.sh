#!/usr/bin/env sh
set -eu

profile="${1:-release}"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/../../.." && pwd)
src_tauri_dir=$(CDPATH= cd -- "${script_dir}/../src-tauri" && pwd)
cloud_dashboard_dir="${repo_root}/apps/cloud-dashboard"
bin_name="hushd"

case "${OS:-}" in
  Windows_NT)
    bin_name="hushd.exe"
    ;;
esac

case "$(uname -s 2>/dev/null || true)" in
  MINGW*|MSYS*|CYGWIN*)
    bin_name="hushd.exe"
    ;;
esac

case "$profile" in
  dev)
    cargo build -p hushd --manifest-path "${repo_root}/Cargo.toml"
    src_bin="${repo_root}/target/debug/${bin_name}"
    ;;
  release)
    cargo build -p hushd --release --manifest-path "${repo_root}/Cargo.toml"
    src_bin="${repo_root}/target/release/${bin_name}"
    ;;
  *)
    echo "Unsupported profile '${profile}'. Use 'dev' or 'release'." >&2
    exit 1
    ;;
esac

dst_bin="${src_tauri_dir}/resources/bin/${bin_name}"
mkdir -p "$(dirname "${dst_bin}")"
install -m 0755 "${src_bin}" "${dst_bin}"
echo "Prepared bundled hushd at ${dst_bin}"

if [ ! -d "${cloud_dashboard_dir}/node_modules" ]; then
  npm --prefix "${cloud_dashboard_dir}" ci
fi

VITE_BASE_PATH="/ui/" npm --prefix "${cloud_dashboard_dir}" run build

dashboard_src="${cloud_dashboard_dir}/dist"
dashboard_dst="${src_tauri_dir}/resources/cloud-dashboard"
rm -rf "${dashboard_dst}"
mkdir -p "${dashboard_dst}"
cp -R "${dashboard_src}/." "${dashboard_dst}/"
echo "Prepared bundled cloud dashboard at ${dashboard_dst}"
