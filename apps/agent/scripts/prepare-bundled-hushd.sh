#!/usr/bin/env sh
set -eu

profile="${1:-release}"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/../../.." && pwd)
src_tauri_dir=$(CDPATH= cd -- "${script_dir}/../src-tauri" && pwd)
control_console_dir="${repo_root}/apps/control-console"
endpoint_security_package_dir="${src_tauri_dir}/macos/system-extension/endpoint-security"
network_extension_package_dir="${src_tauri_dir}/macos/system-extension/network-extension"
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
    swift_configuration="debug"
    ;;
  release)
    cargo build -p hushd --release --manifest-path "${repo_root}/Cargo.toml"
    cargo build -p clawdstrike-brokerd --release --manifest-path "${repo_root}/Cargo.toml"
    hushd_src_bin="${repo_root}/target/release/${hushd_bin}"
    brokerd_src_bin="${repo_root}/target/release/${brokerd_bin}"
    swift_configuration="release"
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

prepare_swift_status_tool() {
  package_dir="$1"
  executable="$2"

  if [ "$(uname -s 2>/dev/null || true)" != "Darwin" ]; then
    echo "Skipping ${executable}: Swift status helpers are bundled only on macOS"
    return
  fi
  if ! command -v swift >/dev/null 2>&1; then
    echo "Missing swift toolchain; cannot build ${executable}" >&2
    exit 1
  fi

  swift build \
    --disable-sandbox \
    --configuration "${swift_configuration}" \
    --package-path "${package_dir}" \
    --product "${executable}"
  swift_bin_dir=$(
    swift build \
      --disable-sandbox \
      --configuration "${swift_configuration}" \
      --package-path "${package_dir}" \
      --show-bin-path
  )
  mkdir -p "${package_dir}/bin"
  install -m 0755 "${swift_bin_dir}/${executable}" "${package_dir}/bin/${executable}"
  echo "Prepared bundled ${executable} at ${package_dir}/bin/${executable}"
}

prepare_swift_status_tool "${endpoint_security_package_dir}" "endpoint-security-status-tool"
prepare_swift_status_tool "${network_extension_package_dir}" "network-extension-status-tool"

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
