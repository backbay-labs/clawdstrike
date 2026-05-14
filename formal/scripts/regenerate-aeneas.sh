#!/usr/bin/env bash
# Regenerate Aeneas Lean output from Rust source.
#
# Usage: ./formal/scripts/regenerate-aeneas.sh [--check]
#   --check : compare freshly generated output against committed Impl/ files,
#             exit 1 if they differ (useful in CI)
#   (no flag): regenerate in-place, overwriting committed Impl/ files
#
# Prerequisites (install once):
#   - Charon: install a pinned prerelease from
#       https://github.com/AeneasVerif/charon/releases/tag/build-2026.03.13.163309-923e13bfe090916ec9384508e1c1b73bb3b7f4ed
#   - Aeneas: see https://github.com/AeneasVerif/aeneas#installation
#
# The script is idempotent and safe to run multiple times.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMPL_DIR="$REPO_ROOT/formal/lean4/ClawdStrike/ClawdStrike/Impl"
CRATE_DIR="$REPO_ROOT/crates/libs/clawdstrike"
WORK_DIR="$(mktemp -d)"
CHARON_RELEASE_TAG="build-2026.03.13.163309-923e13bfe090916ec9384508e1c1b73bb3b7f4ed"
CHARON_RELEASE_URL="https://github.com/AeneasVerif/charon/releases/tag/${CHARON_RELEASE_TAG}"
trap 'rm -rf "$WORK_DIR"' EXIT

CHECK_MODE=false
if [[ "${1:-}" == "--check" ]]; then
    CHECK_MODE=true
fi

# ---------------------------------------------------------------------------
# Locate binaries
# ---------------------------------------------------------------------------

find_binary() {
    local name="$1"
    shift
    # Check fallback locations
    for fallback in "$@"; do
        if [[ -x "$fallback" ]] && "$fallback" --help >/dev/null 2>&1; then
            echo "$fallback"
            return 0
        fi
    done
    # Check PATH last so pinned/toolchain-managed fallbacks win over bundled
    # wrapper scripts that may appear earlier in PATH.
    if command -v "$name" &>/dev/null; then
        command -v "$name"
        return 0
    fi
    return 1
}

CHARON=${CHARON_BIN:-}
if [[ -n "$CHARON" && ! -x "$CHARON" ]]; then
    echo "error: CHARON_BIN points to a non-executable path: $CHARON"
    exit 1
fi
if [[ -z "$CHARON" ]]; then
    CHARON=$(find_binary charon "/tmp/charon-bin/charon" "$HOME/.cargo/bin/charon") || {
        echo "error: charon not found in /tmp/charon-bin/charon, PATH, or ~/.cargo/bin/charon"
        echo ""
        echo "Install a pinned prerelease from:"
        echo "  ${CHARON_RELEASE_URL}"
        exit 1
    }
fi

AENEAS=${AENEAS_BIN:-}
if [[ -n "$AENEAS" && ! -x "$AENEAS" ]]; then
    echo "error: AENEAS_BIN points to a non-executable path: $AENEAS"
    exit 1
fi
if [[ -z "$AENEAS" ]]; then
    AENEAS=$(find_binary aeneas "/tmp/aeneas-bin/aeneas" "/tmp/aeneas/bin/aeneas" "$HOME/.local/bin/aeneas") || {
        echo "error: aeneas not found in /tmp/aeneas-bin/aeneas, /tmp/aeneas/bin/aeneas, PATH, or ~/.local/bin/aeneas"
        echo ""
        echo "Install from: https://github.com/AeneasVerif/aeneas#installation"
        exit 1
    }
fi

echo "Using charon: $CHARON"
echo "Using aeneas: $AENEAS"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Extract LLBC with Charon
# ---------------------------------------------------------------------------

echo "==> Running Charon to extract LLBC..."

LLBC_FILE="$WORK_DIR/clawdstrike.llbc"

# Run charon from the crate directory, outputting LLBC to a stable file path.
# Current Charon releases expose extraction options on the `cargo` subcommand.
# `--preset=aeneas` produces Aeneas-compatible output and `--start-from`
# restricts extraction to the core module. `merge_keyed_vec` is intentionally
# excluded because the formal pipeline uses `merge_keyed_vec_pure`; the generic
# callback-based helper is part of the runtime API but not currently supported
# by Aeneas' function-signature translator.
(
    cd "$CRATE_DIR"
    "$CHARON" cargo \
        --preset=aeneas \
        --start-from 'crate::core' \
        --exclude 'crate::core::merge::merge_keyed_vec' \
        --dest-file "$LLBC_FILE" \
        -- --lib --quiet
)

if [[ ! -f "$LLBC_FILE" ]]; then
    echo "error: Charon did not produce $LLBC_FILE"
    echo "Files in work dir:"
    ls -la "$WORK_DIR"
    exit 1
fi

echo "   LLBC extracted: $(du -h "$LLBC_FILE" | cut -f1)"

# ---------------------------------------------------------------------------
# Step 2: Translate LLBC to Lean 4 with Aeneas
# ---------------------------------------------------------------------------

echo "==> Running Aeneas to generate Lean 4 files..."

AENEAS_OUT="$WORK_DIR/lean_out"
mkdir -p "$AENEAS_OUT"

"$AENEAS" \
    -backend lean \
    -dest "$AENEAS_OUT" \
    -split-files \
    -gen-lib-entry \
    "$LLBC_FILE"

echo "   Lean files generated in $AENEAS_OUT"

# ---------------------------------------------------------------------------
# Step 3: Either check or copy
# ---------------------------------------------------------------------------

# Find the generated files. Aeneas typically outputs into a subdirectory
# matching the crate name. Locate the actual .lean files.
GENERATED_DIR=""
if [[ -d "$AENEAS_OUT/Clawdstrike" ]]; then
    GENERATED_DIR="$AENEAS_OUT/Clawdstrike"
elif [[ -d "$AENEAS_OUT/clawdstrike" ]]; then
    GENERATED_DIR="$AENEAS_OUT/clawdstrike"
else
    # Fall back to whatever directory contains .lean files
    GENERATED_DIR=$(dirname "$(find "$AENEAS_OUT" -name '*.lean' -print -quit 2>/dev/null)")
    if [[ -z "$GENERATED_DIR" || "$GENERATED_DIR" == "." ]]; then
        echo "error: Aeneas did not produce any .lean files"
        echo "Contents of output dir:"
        find "$AENEAS_OUT" -type f
        exit 1
    fi
fi

echo "   Generated directory: $GENERATED_DIR"
echo "   Files:"
find "$GENERATED_DIR" -name '*.lean' | sort | while read -r f; do
    echo "     $(basename "$f")"
done

if $CHECK_MODE; then
    echo ""
    echo "==> Checking for drift against committed Impl/ files..."

    # We compare only the Aeneas-generated files (Types.lean, Funs.lean, etc.)
    # but NOT the *External.lean or *External_Template.lean files, which are
    # hand-written glue. Aeneas generates *_Template.lean files as scaffolds;
    # only compare those and the auto-generated Types.lean / Funs.lean.
    DRIFT_FOUND=false

    for gen_file in "$GENERATED_DIR"/*.lean; do
        basename_file="$(basename "$gen_file")"
        committed_file="$IMPL_DIR/$basename_file"

        # Skip files that are hand-maintained (non-template External files)
        case "$basename_file" in
            *External.lean)
                # These are hand-written -- only compare if a _Template version exists
                continue
                ;;
        esac

        if [[ ! -f "$committed_file" ]]; then
            echo "  NEW: $basename_file (not yet committed)"
            DRIFT_FOUND=true
            continue
        fi

        if ! diff -u "$committed_file" "$gen_file" > "$WORK_DIR/diff_$basename_file" 2>&1; then
            echo ""
            echo "  CHANGED: $basename_file"
            cat "$WORK_DIR/diff_$basename_file"
            DRIFT_FOUND=true
        else
            echo "  OK: $basename_file"
        fi
    done

    # Also check for Merkle subdirectory if present
    if [[ -d "$GENERATED_DIR/Merkle" ]]; then
        for gen_file in "$GENERATED_DIR/Merkle"/*.lean; do
            basename_file="$(basename "$gen_file")"
            committed_file="$IMPL_DIR/Merkle/$basename_file"

            case "$basename_file" in
                *External.lean) continue ;;
            esac

            if [[ ! -f "$committed_file" ]]; then
                echo "  NEW: Merkle/$basename_file (not yet committed)"
                DRIFT_FOUND=true
                continue
            fi

            if ! diff -u "$committed_file" "$gen_file" > "$WORK_DIR/diff_merkle_$basename_file" 2>&1; then
                echo ""
                echo "  CHANGED: Merkle/$basename_file"
                cat "$WORK_DIR/diff_merkle_$basename_file"
                DRIFT_FOUND=true
            else
                echo "  OK: Merkle/$basename_file"
            fi
        done
    fi

    echo ""
    if $DRIFT_FOUND; then
        echo "FAIL: Aeneas output has drifted from committed Impl/ files."
        echo ""
        echo "The Rust core module has changed but the Lean translations are stale."
        echo "To fix:"
        echo "  1. Run: ./formal/scripts/regenerate-aeneas.sh"
        echo "  2. Run: cd formal/lean4/ClawdStrike && lake build"
        echo "  3. Fix any proof breakages"
        echo "  4. Commit the updated Impl/ files"
        exit 1
    else
        echo "OK: Aeneas output matches committed Impl/ files."
        exit 0
    fi
else
    echo ""
    echo "==> Copying generated files to $IMPL_DIR ..."

    # Copy auto-generated files (Types.lean, Funs.lean, *_Template.lean)
    for gen_file in "$GENERATED_DIR"/*.lean; do
        basename_file="$(basename "$gen_file")"

        # Don't overwrite hand-written External files
        case "$basename_file" in
            *External.lean)
                continue
                ;;
        esac

        cp -v "$gen_file" "$IMPL_DIR/$basename_file"
    done

    # Handle Merkle subdirectory if present
    if [[ -d "$GENERATED_DIR/Merkle" ]]; then
        mkdir -p "$IMPL_DIR/Merkle"
        for gen_file in "$GENERATED_DIR/Merkle"/*.lean; do
            basename_file="$(basename "$gen_file")"
            case "$basename_file" in
                *External.lean) continue ;;
            esac
            cp -v "$gen_file" "$IMPL_DIR/Merkle/$basename_file"
        done
    fi

    echo ""
    echo "Done. Next steps:"
    echo "  1. cd formal/lean4/ClawdStrike && lake build"
    echo "  2. Fix any proof breakages in Spec/Properties.lean"
    echo "  3. Commit the updated Impl/ files"
fi
