#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/sign-hushd-ota-manifest.sh \
    --input <manifest.json> \
    --output <signed-manifest.json> \
    [--private-key-file <ed25519-private-key.pem>] \
    [--public-key <hex32>]

Private key resolution (first non-empty wins):
  1) --private-key-file
  2) $HUSHD_OTA_SIGNING_PRIVATE_KEY_FILE
  3) $HUSHD_OTA_SIGNING_PRIVATE_KEY_PEM (inline PEM)

If --public-key is omitted, the script derives it from the private key.
USAGE
}

input_path=""
output_path=""
private_key_file="${HUSHD_OTA_SIGNING_PRIVATE_KEY_FILE:-}"
public_key_hex=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input)
      input_path="${2:-}"
      shift 2
      ;;
    --output)
      output_path="${2:-}"
      shift 2
      ;;
    --private-key-file)
      private_key_file="${2:-}"
      shift 2
      ;;
    --public-key)
      public_key_hex="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$input_path" || -z "$output_path" ]]; then
  echo "--input and --output are required" >&2
  usage
  exit 1
fi

if [[ ! -f "$input_path" ]]; then
  echo "Input manifest not found: $input_path" >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

resolved_key_file="$private_key_file"
if [[ -z "$resolved_key_file" ]]; then
  if [[ -n "${HUSHD_OTA_SIGNING_PRIVATE_KEY_PEM:-}" ]]; then
    resolved_key_file="${tmp_dir}/ota_signing_key.pem"
    printf '%s\n' "${HUSHD_OTA_SIGNING_PRIVATE_KEY_PEM}" > "${resolved_key_file}"
    chmod 600 "${resolved_key_file}"
  else
    echo "No private key configured. Provide --private-key-file or HUSHD_OTA_SIGNING_PRIVATE_KEY_PEM." >&2
    exit 1
  fi
fi

if [[ ! -f "$resolved_key_file" ]]; then
  echo "Private key file not found: $resolved_key_file" >&2
  exit 1
fi

derived_public_key_hex="$(openssl pkey -in "$resolved_key_file" -pubout -outform DER \
  | xxd -p -c 1000 | tr -d '\n' | awk '
BEGIN { prefix="302a300506032b6570032100" }
{
  if (index($0, prefix) != 1) {
    print "invalid_ed25519_spki_der" > "/dev/stderr";
    exit 2;
  }
  print substr($0, length(prefix) + 1);
}')"

if [[ -z "$public_key_hex" ]]; then
  public_key_hex="$derived_public_key_hex"
fi

if [[ "${#public_key_hex}" -ne 64 ]]; then
  echo "Public key must be 32-byte hex (64 chars), got length ${#public_key_hex}" >&2
  exit 1
fi

canonical_path="${tmp_dir}/manifest.canonical.json"
export OTA_SIGN_INPUT_PATH="$input_path"
export OTA_SIGN_CANONICAL_PATH="$canonical_path"
export OTA_SIGN_PUBLIC_KEY_HEX="$public_key_hex"
python3 - <<'PY'
import json
import os
import pathlib

input_path = pathlib.Path(os.environ["OTA_SIGN_INPUT_PATH"])
canonical_path = pathlib.Path(os.environ["OTA_SIGN_CANONICAL_PATH"])
public_key_hex = os.environ["OTA_SIGN_PUBLIC_KEY_HEX"]

manifest = json.loads(input_path.read_text(encoding="utf-8"))
if not isinstance(manifest, dict):
    raise SystemExit("manifest must be a JSON object")
manifest["public_key"] = public_key_hex
manifest.pop("signature", None)
canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
canonical_path.write_text(canonical, encoding="utf-8")
PY

signature_bin="${tmp_dir}/manifest.sig.bin"
openssl pkeyutl -sign -inkey "$resolved_key_file" -rawin -in "$canonical_path" -out "$signature_bin"
signature_hex="$(xxd -p "$signature_bin" | tr -d '\n')"

if [[ "${#signature_hex}" -ne 128 ]]; then
  echo "Unexpected signature length: ${#signature_hex} hex chars" >&2
  exit 1
fi

export OTA_SIGN_OUTPUT_PATH="$output_path"
export OTA_SIGN_SIGNATURE_HEX="$signature_hex"
python3 - <<'PY'
import json
import os
import pathlib

input_path = pathlib.Path(os.environ["OTA_SIGN_INPUT_PATH"])
output_path = pathlib.Path(os.environ["OTA_SIGN_OUTPUT_PATH"])
public_key_hex = os.environ["OTA_SIGN_PUBLIC_KEY_HEX"]
signature_hex = os.environ["OTA_SIGN_SIGNATURE_HEX"]

manifest = json.loads(input_path.read_text(encoding="utf-8"))
if not isinstance(manifest, dict):
    raise SystemExit("manifest must be a JSON object")

manifest["public_key"] = public_key_hex
manifest["signature"] = signature_hex

output_path.parent.mkdir(parents=True, exist_ok=True)
with output_path.open("w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
PY

echo "Signed OTA manifest: ${output_path}"
echo "Signer public key: ${public_key_hex}"
