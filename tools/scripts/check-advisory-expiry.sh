#!/usr/bin/env bash
set -euo pipefail

DOC_PATH="docs/security/dependency-advisories.md"

if [[ ! -f "${DOC_PATH}" ]]; then
  echo "Missing advisory policy doc: ${DOC_PATH}" >&2
  exit 1
fi

today="$(date -u +%F)"
status=0

while IFS='|' read -r _ advisory crate disposition owner expiry tracking _; do
  advisory="$(echo "${advisory}" | xargs)"
  owner="$(echo "${owner}" | xargs)"
  expiry="$(echo "${expiry}" | xargs)"
  tracking="$(echo "${tracking}" | xargs)"

  [[ "${advisory}" =~ ^RUSTSEC- ]] || continue

  if [[ -z "${owner}" || "${owner}" == "-" ]]; then
    echo "Advisory ${advisory} is missing owner in ${DOC_PATH}" >&2
    status=1
  fi

  if [[ -z "${tracking}" || "${tracking}" == "-" ]]; then
    echo "Advisory ${advisory} is missing tracking reference in ${DOC_PATH}" >&2
    status=1
  fi

  if ! [[ "${expiry}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    echo "Advisory ${advisory} has invalid expiry '${expiry}' in ${DOC_PATH}" >&2
    status=1
    continue
  fi

  if [[ "${expiry}" < "${today}" ]]; then
    echo "Advisory ${advisory} expired on ${expiry} (today=${today})" >&2
    status=1
  fi
done < "${DOC_PATH}"

exit "${status}"
