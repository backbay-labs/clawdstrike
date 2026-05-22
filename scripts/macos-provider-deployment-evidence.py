#!/usr/bin/env python3
"""Collect and verify macOS provider deployment evidence for dogfood runs."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import plistlib
import subprocess
import sys
import tempfile
from typing import Any


DEFAULT_TEAM_ID = "JB6682CJY9"
DEFAULT_APP_BUNDLE_ID = "dev.clawdstrike.agent"
DEFAULT_SYSTEM_EXTENSION_BUNDLE_ID = "dev.clawdstrike.agent.system-extension"
REQUIRED_EXTENSION_POINTS = ("endpoint_security", "network_extension_content_filter")
NETWORK_EXTENSION_ENTITLEMENT = "content-filter-provider-systemextension"


def _write_json_artifact(path: pathlib.Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def _run_command(argv: list[str], timeout_seconds: int = 30) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout_seconds,
        )
        return {
            "argv": argv,
            "exitCode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    except FileNotFoundError as exc:
        return {"argv": argv, "exitCode": 127, "stdout": "", "stderr": str(exc)}
    except subprocess.TimeoutExpired as exc:
        return {
            "argv": argv,
            "exitCode": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or f"timed out after {timeout_seconds} seconds",
        }


def _command_text(command: dict[str, Any]) -> str:
    return f"{command.get('stdout', '')}\n{command.get('stderr', '')}"


def _has_exact_line(text: str, expected: str) -> bool:
    return any(line.strip() == expected for line in text.splitlines())


def _read_plist(path: pathlib.Path) -> dict[str, Any] | None:
    try:
        with path.open("rb") as handle:
            payload = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException):
        return None
    return payload if isinstance(payload, dict) else None


def _bundle_info(bundle_path: pathlib.Path, system_extension_bundle_id: str) -> dict[str, Any]:
    app_info_path = bundle_path / "Contents" / "Info.plist"
    app_info = _read_plist(app_info_path) or {}
    extension_info_path: pathlib.Path | None = None
    extension_info: dict[str, Any] = {}

    search_roots = [
        bundle_path / "Contents" / "Library" / "SystemExtensions",
        bundle_path.parent if bundle_path.suffix == ".systemextension" else pathlib.Path(),
    ]
    for root in search_roots:
        if not root or not root.is_dir():
            continue
        for candidate in sorted(root.glob("*.systemextension/Contents/Info.plist")):
            payload = _read_plist(candidate) or {}
            if payload.get("CFBundleIdentifier") == system_extension_bundle_id:
                extension_info_path = candidate
                extension_info = payload
                break
        if extension_info_path is not None:
            break

    return {
        "bundlePath": str(bundle_path),
        "app": {
            "infoPlist": str(app_info_path),
            "bundleIdentifier": app_info.get("CFBundleIdentifier"),
            "displayName": app_info.get("CFBundleDisplayName") or app_info.get("CFBundleName"),
        },
        "systemExtension": {
            "path": str(extension_info_path.parent.parent) if extension_info_path is not None else None,
            "infoPlist": str(extension_info_path) if extension_info_path is not None else None,
            "bundleIdentifier": extension_info.get("CFBundleIdentifier"),
            "displayName": extension_info.get("CFBundleDisplayName")
            or extension_info.get("CFBundleName"),
            "extensionPoints": extension_info.get("ClawdStrikeExtensionPoints", []),
        },
    }


def _system_extension_path(bundle_info: dict[str, Any]) -> pathlib.Path | None:
    system_extension = bundle_info.get("systemExtension")
    if not isinstance(system_extension, dict):
        return None
    path = system_extension.get("path")
    if not isinstance(path, str) or not path.strip():
        return None
    return pathlib.Path(path)


def collect_evidence(
    output_dir: pathlib.Path,
    run_id: str,
    host_id: str,
    user_id: str,
    bundle_path: pathlib.Path,
    team_id: str,
    app_bundle_id: str,
    system_extension_bundle_id: str,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_info = _bundle_info(bundle_path, system_extension_bundle_id)
    system_extension_path = _system_extension_path(bundle_info)
    host_info = {
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "commands": {
            "swVers": _run_command(["sw_vers"]),
            "uname": _run_command(["uname", "-a"]),
        },
    }
    summary = {
        "runId": run_id,
        "outputDir": str(output_dir),
        "hostId": host_id,
        "userId": user_id,
        "teamId": team_id,
        "appBundleId": app_bundle_id,
        "systemExtensionBundleId": system_extension_bundle_id,
        "bundlePath": str(bundle_path),
        "requiredExtensionPoints": list(REQUIRED_EXTENSION_POINTS),
        "hostInfo": _write_json_artifact(output_dir / "host-info.json", host_info),
        "bundleInfo": _write_json_artifact(
            output_dir / "bundle-info.json",
            bundle_info,
        ),
        "systemExtensionsCtl": _write_json_artifact(
            output_dir / "systemextensionsctl-list.json",
            _run_command(["systemextensionsctl", "list"]),
        ),
        "codesign": _write_json_artifact(
            output_dir / "codesign-display.json",
            _run_command(["codesign", "-dv", "--verbose=4", str(bundle_path)]),
        ),
        "codesignVerify": _write_json_artifact(
            output_dir / "codesign-verify.json",
            _run_command(["codesign", "--verify", "--strict", "--verbose=4", str(bundle_path)]),
        ),
        "codesignDeepVerify": _write_json_artifact(
            output_dir / "codesign-deep-verify.json",
            _run_command(["codesign", "--verify", "--deep", "--strict", "--verbose=4", str(bundle_path)]),
        ),
        "appEntitlements": _write_json_artifact(
            output_dir / "app-entitlements.json",
            _run_command(["codesign", "-d", "--entitlements", ":-", str(bundle_path)]),
        ),
        "systemExtensionCodesign": _write_json_artifact(
            output_dir / "system-extension-codesign-display.json",
            _run_command(
                ["codesign", "-dv", "--verbose=4", str(system_extension_path)]
                if system_extension_path is not None
                else ["codesign", "-dv", "--verbose=4", ""]
            ),
        ),
        "systemExtensionCodesignVerify": _write_json_artifact(
            output_dir / "system-extension-codesign-verify.json",
            _run_command(
                ["codesign", "--verify", "--strict", "--verbose=4", str(system_extension_path)]
                if system_extension_path is not None
                else ["codesign", "--verify", "--strict", "--verbose=4", ""]
            ),
        ),
        "systemExtensionEntitlements": _write_json_artifact(
            output_dir / "system-extension-entitlements.json",
            _run_command(
                ["codesign", "-d", "--entitlements", ":-", str(system_extension_path)]
                if system_extension_path is not None
                else ["codesign", "-d", "--entitlements", ":-", ""]
            ),
        ),
        "spctl": _write_json_artifact(
            output_dir / "spctl-assess.json",
            _run_command(["spctl", "-a", "-vv", "-t", "exec", str(bundle_path)]),
        ),
        "stapler": _write_json_artifact(
            output_dir / "stapler-validate.json",
            _run_command(["xcrun", "stapler", "validate", str(bundle_path)], timeout_seconds=60),
        ),
    }
    _write_json_artifact(output_dir / "summary.json", summary)
    return summary


def _load_json_object(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _artifact_object(summary: dict[str, Any], field: str, output_dir: pathlib.Path, failures: list[str]) -> dict[str, Any]:
    value = summary.get(field)
    if not isinstance(value, str) or not value.strip():
        failures.append(f"{field} artifact path is required")
        return {}
    path = pathlib.Path(value)
    if not path.is_absolute():
        path = output_dir / path
    try:
        resolved = path.resolve()
        resolved.relative_to(output_dir.resolve())
    except ValueError:
        failures.append(f"{field} artifact must live under outputDir")
        return {}
    if not resolved.is_file():
        failures.append(f"{field} artifact is missing")
        return {}
    try:
        return _load_json_object(resolved)
    except Exception as exc:  # noqa: BLE001 - verification output should preserve parse failure.
        failures.append(f"{field} artifact must be valid JSON: {exc}")
        return {}


def _summary_string(summary: dict[str, Any], field: str, failures: list[str]) -> str:
    value = summary.get(field)
    if isinstance(value, str) and value.strip():
        return value
    failures.append(f"{field} must be a non-empty string")
    return ""


def _require_command_success(command: dict[str, Any], label: str, failures: list[str]) -> str:
    if command.get("exitCode") != 0:
        failures.append(f"{label} command must exit 0")
    return _command_text(command)


def _require_command(
    command: dict[str, Any],
    label: str,
    expected_argv: list[str],
    failures: list[str],
) -> str:
    argv = command.get("argv")
    if argv != expected_argv:
        failures.append(f"{label} argv must be {expected_argv}")
    return _require_command_success(command, label, failures)


def _plist_from_command_stdout(command: dict[str, Any], label: str, failures: list[str]) -> dict[str, Any]:
    stdout = command.get("stdout")
    if not isinstance(stdout, str) or not stdout.strip():
        failures.append(f"{label} stdout must contain a plist")
        return {}
    try:
        payload = plistlib.loads(stdout.encode("utf-8"))
    except (plistlib.InvalidFileException, ValueError) as exc:
        failures.append(f"{label} stdout must be a valid plist: {exc}")
        return {}
    if not isinstance(payload, dict):
        failures.append(f"{label} stdout plist must be a dictionary")
        return {}
    return payload


def _require_bool_entitlement(
    entitlements: dict[str, Any],
    key: str,
    label: str,
    failures: list[str],
) -> None:
    if entitlements.get(key) is not True:
        failures.append(f"{label} must include true entitlement {key}")


def _require_network_extension_entitlement(
    entitlements: dict[str, Any],
    label: str,
    failures: list[str],
) -> None:
    values = entitlements.get("com.apple.developer.networking.networkextension")
    if not isinstance(values, list) or NETWORK_EXTENSION_ENTITLEMENT not in values:
        failures.append(
            f"{label} must include NetworkExtension entitlement {NETWORK_EXTENSION_ENTITLEMENT}"
        )


def _matching_system_extension_lines(text: str, team_id: str, bundle_id: str) -> list[str]:
    matches: list[str] = []
    for line in text.splitlines():
        tokens = line.split()
        for index, token in enumerate(tokens[:-1]):
            if token == team_id and tokens[index + 1] == bundle_id:
                matches.append(line)
                break
    return matches


def _system_extension_status_tokens(line: str | None) -> set[str]:
    if line is None:
        return set()
    start = line.rfind("[")
    end = line.rfind("]")
    if start == -1 or end <= start:
        return set()
    return {token.strip().lower() for token in line[start + 1 : end].split() if token.strip()}


def verify_summary(summary: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    warnings: list[str] = []
    run_id = _summary_string(summary, "runId", failures)
    host_id = _summary_string(summary, "hostId", failures)
    user_id = _summary_string(summary, "userId", failures)
    team_id = _summary_string(summary, "teamId", failures)
    app_bundle_id = _summary_string(summary, "appBundleId", failures)
    system_extension_bundle_id = _summary_string(summary, "systemExtensionBundleId", failures)
    bundle_path = _summary_string(summary, "bundlePath", failures)
    output_dir_value = _summary_string(summary, "outputDir", failures)
    output_dir = pathlib.Path(output_dir_value) if output_dir_value else pathlib.Path()

    if run_id:
        try:
            dt.datetime.strptime(run_id, "%Y%m%dT%H%M%SZ")
        except ValueError:
            failures.append("runId must use YYYYMMDDTHHMMSSZ")

    host_info = _artifact_object(summary, "hostInfo", output_dir, failures)
    bundle_info = _artifact_object(summary, "bundleInfo", output_dir, failures)
    systemextensionsctl = _artifact_object(summary, "systemExtensionsCtl", output_dir, failures)
    codesign = _artifact_object(summary, "codesign", output_dir, failures)
    codesign_verify = _artifact_object(summary, "codesignVerify", output_dir, failures)
    codesign_deep_verify = _artifact_object(summary, "codesignDeepVerify", output_dir, failures)
    app_entitlements = _artifact_object(summary, "appEntitlements", output_dir, failures)
    system_extension_codesign = _artifact_object(
        summary,
        "systemExtensionCodesign",
        output_dir,
        failures,
    )
    system_extension_codesign_verify = _artifact_object(
        summary,
        "systemExtensionCodesignVerify",
        output_dir,
        failures,
    )
    system_extension_entitlements = _artifact_object(
        summary,
        "systemExtensionEntitlements",
        output_dir,
        failures,
    )
    spctl = _artifact_object(summary, "spctl", output_dir, failures)
    stapler = _artifact_object(summary, "stapler", output_dir, failures)

    commands = host_info.get("commands")
    if isinstance(commands, dict):
        for name in ("swVers", "uname"):
            command = commands.get(name)
            if isinstance(command, dict):
                expected = ["sw_vers"] if name == "swVers" else ["uname", "-a"]
                _require_command(command, f"hostInfo.{name}", expected, failures)
            else:
                failures.append(f"hostInfo.{name} command artifact is required")
    elif host_info:
        failures.append("hostInfo.commands must be an object")

    systemextensions_text = _require_command(
        systemextensionsctl,
        "systemextensionsctl list",
        ["systemextensionsctl", "list"],
        failures,
    )
    extension_lines = _matching_system_extension_lines(
        systemextensions_text,
        team_id,
        system_extension_bundle_id,
    )
    extension_line = extension_lines[0] if len(extension_lines) == 1 else None
    if not extension_lines:
        failures.append("systemextensionsctl output must include the expected team and system extension ID")
    elif len(extension_lines) > 1:
        failures.append("systemextensionsctl output must include exactly one expected system extension row")
    else:
        status_tokens = _system_extension_status_tokens(extension_line)
        if "activated" not in status_tokens or "enabled" not in status_tokens:
            failures.append("system extension must be activated and enabled")

    bundle_path_obj = pathlib.Path(bundle_path) if bundle_path else pathlib.Path()
    if bundle_path_obj.suffix != ".app":
        failures.append("bundlePath must reference a .app bundle")

    codesign_text = _require_command(
        codesign,
        "codesign",
        ["codesign", "-dv", "--verbose=4", bundle_path],
        failures,
    )
    if team_id and not _has_exact_line(codesign_text, f"TeamIdentifier={team_id}"):
        failures.append("codesign output must bind the expected TeamIdentifier")
    if app_bundle_id and not _has_exact_line(codesign_text, f"Identifier={app_bundle_id}"):
        failures.append("codesign output must bind the expected app bundle identifier")

    _require_command(
        codesign_verify,
        "codesign verify",
        ["codesign", "--verify", "--strict", "--verbose=4", bundle_path],
        failures,
    )
    _require_command(
        codesign_deep_verify,
        "codesign deep verify",
        ["codesign", "--verify", "--deep", "--strict", "--verbose=4", bundle_path],
        failures,
    )
    _require_command(
        app_entitlements,
        "app entitlements",
        ["codesign", "-d", "--entitlements", ":-", bundle_path],
        failures,
    )
    app_entitlements_payload = _plist_from_command_stdout(
        app_entitlements,
        "app entitlements",
        failures,
    )
    _require_bool_entitlement(
        app_entitlements_payload,
        "com.apple.developer.system-extension.install",
        "app entitlements",
        failures,
    )
    _require_network_extension_entitlement(app_entitlements_payload, "app entitlements", failures)

    app_info = bundle_info.get("app") if isinstance(bundle_info.get("app"), dict) else {}
    extension_info = (
        bundle_info.get("systemExtension")
        if isinstance(bundle_info.get("systemExtension"), dict)
        else {}
    )
    system_extension_path = extension_info.get("path")
    if not isinstance(system_extension_path, str) or not system_extension_path.strip():
        failures.append("bundleInfo.systemExtension.path must be a non-empty string")
        system_extension_path = ""
    elif bundle_path:
        expected_root = (bundle_path_obj / "Contents" / "Library" / "SystemExtensions").resolve()
        try:
            pathlib.Path(system_extension_path).resolve().relative_to(expected_root)
        except ValueError:
            failures.append("bundleInfo.systemExtension.path must be embedded under bundlePath")

    system_extension_codesign_text = _require_command(
        system_extension_codesign,
        "system extension codesign",
        ["codesign", "-dv", "--verbose=4", system_extension_path],
        failures,
    )
    if team_id and not _has_exact_line(
        system_extension_codesign_text,
        f"TeamIdentifier={team_id}",
    ):
        failures.append("system extension codesign output must bind the expected TeamIdentifier")
    if system_extension_bundle_id and not _has_exact_line(
        system_extension_codesign_text,
        f"Identifier={system_extension_bundle_id}",
    ):
        failures.append("system extension codesign output must bind the expected bundle identifier")
    _require_command(
        system_extension_codesign_verify,
        "system extension codesign verify",
        ["codesign", "--verify", "--strict", "--verbose=4", system_extension_path],
        failures,
    )
    _require_command(
        system_extension_entitlements,
        "system extension entitlements",
        ["codesign", "-d", "--entitlements", ":-", system_extension_path],
        failures,
    )
    system_extension_entitlements_payload = _plist_from_command_stdout(
        system_extension_entitlements,
        "system extension entitlements",
        failures,
    )
    _require_bool_entitlement(
        system_extension_entitlements_payload,
        "com.apple.developer.endpoint-security.client",
        "system extension entitlements",
        failures,
    )
    _require_network_extension_entitlement(
        system_extension_entitlements_payload,
        "system extension entitlements",
        failures,
    )

    spctl_text = _require_command(
        spctl,
        "spctl",
        ["spctl", "-a", "-vv", "-t", "exec", bundle_path],
        failures,
    )
    if "accepted" not in spctl_text.lower():
        failures.append("spctl output must show an accepted Developer ID assessment")
    if "notarized" not in spctl_text.lower():
        warnings.append("spctl output did not explicitly include notarized source text")

    stapler_text = _require_command(
        stapler,
        "stapler validate",
        ["xcrun", "stapler", "validate", bundle_path],
        failures,
    )
    if "validate action worked" not in stapler_text.lower():
        failures.append("stapler output must show notarization ticket validation")

    if bundle_info.get("bundlePath") != bundle_path:
        failures.append("bundleInfo.bundlePath must match bundlePath")
    if app_info.get("bundleIdentifier") != app_bundle_id:
        failures.append("bundleInfo.app.bundleIdentifier must match appBundleId")
    if extension_info.get("bundleIdentifier") != system_extension_bundle_id:
        failures.append("bundleInfo.systemExtension.bundleIdentifier must match systemExtensionBundleId")
    extension_points = extension_info.get("extensionPoints")
    if not isinstance(extension_points, list):
        failures.append("bundleInfo.systemExtension.extensionPoints must be a list")
        extension_points = []
    for point in REQUIRED_EXTENSION_POINTS:
        if point not in extension_points:
            failures.append(f"bundleInfo.systemExtension.extensionPoints must include {point}")
    summary_extension_points = summary.get("requiredExtensionPoints")
    if summary_extension_points != list(REQUIRED_EXTENSION_POINTS):
        failures.append("requiredExtensionPoints must match the deployment verifier contract")

    return {
        "verified": not failures,
        "failureCount": len(failures),
        "failures": failures,
        "warnings": warnings,
        "runId": run_id,
        "hostId": host_id,
        "userId": user_id,
        "teamId": team_id,
        "appBundleId": app_bundle_id,
        "systemExtensionBundleId": system_extension_bundle_id,
        "bundlePath": bundle_path,
        "systemExtensionPath": system_extension_path or None,
        "extensionPoints": extension_points,
        "systemExtensionStatusLine": extension_line,
    }


def fixture_summary(output_dir: pathlib.Path) -> dict[str, Any]:
    bundle_path = pathlib.Path("/Applications/ClawdStrike Agent.app")
    app_entitlements = plistlib.dumps(
        {
            "com.apple.developer.system-extension.install": True,
            "com.apple.developer.networking.networkextension": [
                NETWORK_EXTENSION_ENTITLEMENT,
            ],
        }
    ).decode("utf-8")
    system_extension_entitlements = plistlib.dumps(
        {
            "com.apple.developer.endpoint-security.client": True,
            "com.apple.developer.networking.networkextension": [
                NETWORK_EXTENSION_ENTITLEMENT,
            ],
        }
    ).decode("utf-8")
    host_info = {
        "commands": {
            "swVers": {
                "argv": ["sw_vers"],
                "exitCode": 0,
                "stdout": "ProductName:\t\tmacOS\nProductVersion:\t\t15.5\n",
                "stderr": "",
            },
            "uname": {
                "argv": ["uname", "-a"],
                "exitCode": 0,
                "stdout": "Darwin qa-mac-1.local 24.5.0 Darwin Kernel Version\n",
                "stderr": "",
            },
        }
    }
    bundle_info = {
        "bundlePath": str(bundle_path),
        "app": {
            "infoPlist": f"{bundle_path}/Contents/Info.plist",
            "bundleIdentifier": DEFAULT_APP_BUNDLE_ID,
            "displayName": "ClawdStrike Agent",
        },
        "systemExtension": {
            "path": f"{bundle_path}/Contents/Library/SystemExtensions/{DEFAULT_SYSTEM_EXTENSION_BUNDLE_ID}.systemextension",
            "infoPlist": (
                f"{bundle_path}/Contents/Library/SystemExtensions/"
                f"{DEFAULT_SYSTEM_EXTENSION_BUNDLE_ID}.systemextension/Contents/Info.plist"
            ),
            "bundleIdentifier": DEFAULT_SYSTEM_EXTENSION_BUNDLE_ID,
            "displayName": "ClawdStrike Security Extension",
            "extensionPoints": list(REQUIRED_EXTENSION_POINTS),
        },
    }
    system_extension_path = bundle_info["systemExtension"]["path"]
    summary = {
        "runId": "20260519T010203Z",
        "outputDir": str(output_dir),
        "hostId": "qa-mac-1",
        "userId": "operator",
        "teamId": DEFAULT_TEAM_ID,
        "appBundleId": DEFAULT_APP_BUNDLE_ID,
        "systemExtensionBundleId": DEFAULT_SYSTEM_EXTENSION_BUNDLE_ID,
        "bundlePath": str(bundle_path),
        "requiredExtensionPoints": list(REQUIRED_EXTENSION_POINTS),
        "hostInfo": _write_json_artifact(output_dir / "host-info.json", host_info),
        "bundleInfo": _write_json_artifact(output_dir / "bundle-info.json", bundle_info),
        "systemExtensionsCtl": _write_json_artifact(
            output_dir / "systemextensionsctl-list.json",
            {
                "argv": ["systemextensionsctl", "list"],
                "exitCode": 0,
                "stdout": (
                    "1 extension(s)\n"
                    f"* * {DEFAULT_TEAM_ID} {DEFAULT_SYSTEM_EXTENSION_BUNDLE_ID} "
                    "(0.2.5/0.2.5) ClawdStrike Security Extension [activated enabled]\n"
                ),
                "stderr": "",
            },
        ),
        "codesign": _write_json_artifact(
            output_dir / "codesign-display.json",
            {
                "argv": ["codesign", "-dv", "--verbose=4", str(bundle_path)],
                "exitCode": 0,
                "stdout": "",
                "stderr": (
                    f"Executable={bundle_path}/Contents/MacOS/ClawdStrike Agent\n"
                    f"Identifier={DEFAULT_APP_BUNDLE_ID}\n"
                    f"TeamIdentifier={DEFAULT_TEAM_ID}\n"
                    "Authority=Developer ID Application: ClawdStrike\n"
                ),
            },
        ),
        "codesignVerify": _write_json_artifact(
            output_dir / "codesign-verify.json",
            {
                "argv": ["codesign", "--verify", "--strict", "--verbose=4", str(bundle_path)],
                "exitCode": 0,
                "stdout": "",
                "stderr": (
                    f"{bundle_path}: valid on disk\n"
                    f"{bundle_path}: satisfies its Designated Requirement\n"
                ),
            },
        ),
        "codesignDeepVerify": _write_json_artifact(
            output_dir / "codesign-deep-verify.json",
            {
                "argv": ["codesign", "--verify", "--deep", "--strict", "--verbose=4", str(bundle_path)],
                "exitCode": 0,
                "stdout": "",
                "stderr": (
                    f"{bundle_path}: valid on disk\n"
                    f"{bundle_path}: satisfies its Designated Requirement\n"
                ),
            },
        ),
        "appEntitlements": _write_json_artifact(
            output_dir / "app-entitlements.json",
            {
                "argv": ["codesign", "-d", "--entitlements", ":-", str(bundle_path)],
                "exitCode": 0,
                "stdout": app_entitlements,
                "stderr": f"Executable={bundle_path}/Contents/MacOS/ClawdStrike Agent\n",
            },
        ),
        "systemExtensionCodesign": _write_json_artifact(
            output_dir / "system-extension-codesign-display.json",
            {
                "argv": ["codesign", "-dv", "--verbose=4", system_extension_path],
                "exitCode": 0,
                "stdout": "",
                "stderr": (
                    f"Executable={system_extension_path}/Contents/MacOS/ClawdStrike Security Extension\n"
                    f"Identifier={DEFAULT_SYSTEM_EXTENSION_BUNDLE_ID}\n"
                    f"TeamIdentifier={DEFAULT_TEAM_ID}\n"
                    "Authority=Developer ID Application: ClawdStrike\n"
                ),
            },
        ),
        "systemExtensionCodesignVerify": _write_json_artifact(
            output_dir / "system-extension-codesign-verify.json",
            {
                "argv": [
                    "codesign",
                    "--verify",
                    "--strict",
                    "--verbose=4",
                    system_extension_path,
                ],
                "exitCode": 0,
                "stdout": "",
                "stderr": (
                    f"{system_extension_path}: valid on disk\n"
                    f"{system_extension_path}: satisfies its Designated Requirement\n"
                ),
            },
        ),
        "systemExtensionEntitlements": _write_json_artifact(
            output_dir / "system-extension-entitlements.json",
            {
                "argv": ["codesign", "-d", "--entitlements", ":-", system_extension_path],
                "exitCode": 0,
                "stdout": system_extension_entitlements,
                "stderr": (
                    f"Executable={system_extension_path}/Contents/MacOS/"
                    "ClawdStrike Security Extension\n"
                ),
            },
        ),
        "spctl": _write_json_artifact(
            output_dir / "spctl-assess.json",
            {
                "argv": ["spctl", "-a", "-vv", "-t", "exec", str(bundle_path)],
                "exitCode": 0,
                "stdout": "",
                "stderr": f"{bundle_path}: accepted\nsource=Notarized Developer ID\n",
            },
        ),
        "stapler": _write_json_artifact(
            output_dir / "stapler-validate.json",
            {
                "argv": ["xcrun", "stapler", "validate", str(bundle_path)],
                "exitCode": 0,
                "stdout": "The validate action worked!\n",
                "stderr": "",
            },
        ),
    }
    result = verify_summary(summary)
    if result["verified"] is not True:
        raise AssertionError(f"fixture deployment evidence no longer verifies: {result}")
    return summary


def run_self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="clawdstrike-macos-provider-deploy-") as temp_dir:
        output_dir = pathlib.Path(temp_dir)
        summary = fixture_summary(output_dir)
        valid = verify_summary(summary)
        if valid["verified"] is not True:
            print(json.dumps(valid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        systemextensions = _load_json_object(pathlib.Path(summary["systemExtensionsCtl"]))
        systemextensions["stdout"] = systemextensions["stdout"].replace("activated enabled", "activated")
        pathlib.Path(summary["systemExtensionsCtl"]).write_text(
            json.dumps(systemextensions),
            encoding="utf-8",
        )
        invalid = verify_summary(summary)
        if invalid["verified"] is True or not any("activated and enabled" in item for item in invalid["failures"]):
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        summary = fixture_summary(output_dir)
        systemextensions = _load_json_object(pathlib.Path(summary["systemExtensionsCtl"]))
        systemextensions["stdout"] = systemextensions["stdout"].replace(
            DEFAULT_SYSTEM_EXTENSION_BUNDLE_ID,
            f"{DEFAULT_SYSTEM_EXTENSION_BUNDLE_ID}.other",
        )
        pathlib.Path(summary["systemExtensionsCtl"]).write_text(
            json.dumps(systemextensions),
            encoding="utf-8",
        )
        invalid = verify_summary(summary)
        expected_system_extension_failure = (
            "systemextensionsctl output must include the expected team and system extension ID"
        )
        if invalid["verified"] is True or expected_system_extension_failure not in invalid["failures"]:
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        summary = fixture_summary(output_dir)
        systemextensions = _load_json_object(pathlib.Path(summary["systemExtensionsCtl"]))
        systemextensions["stdout"] = systemextensions["stdout"].replace(
            DEFAULT_TEAM_ID,
            f"{DEFAULT_TEAM_ID}9",
        )
        pathlib.Path(summary["systemExtensionsCtl"]).write_text(
            json.dumps(systemextensions),
            encoding="utf-8",
        )
        invalid = verify_summary(summary)
        if invalid["verified"] is True or expected_system_extension_failure not in invalid["failures"]:
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        summary = fixture_summary(output_dir)
        systemextensions = _load_json_object(pathlib.Path(summary["systemExtensionsCtl"]))
        matching_line = (
            f"* * {DEFAULT_TEAM_ID} {DEFAULT_SYSTEM_EXTENSION_BUNDLE_ID} "
            "(0.2.5/0.2.5) ClawdStrike Security Extension [activated enabled]\n"
        )
        stale_line = (
            f"* * {DEFAULT_TEAM_ID} {DEFAULT_SYSTEM_EXTENSION_BUNDLE_ID} "
            "(0.2.4/0.2.4) ClawdStrike Security Extension [terminated waiting for user]\n"
        )
        systemextensions["stdout"] = f"2 extension(s)\n{matching_line}{stale_line}"
        pathlib.Path(summary["systemExtensionsCtl"]).write_text(
            json.dumps(systemextensions),
            encoding="utf-8",
        )
        invalid = verify_summary(summary)
        expected_duplicate_failure = (
            "systemextensionsctl output must include exactly one expected system extension row"
        )
        if invalid["verified"] is True or expected_duplicate_failure not in invalid["failures"]:
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        summary = fixture_summary(output_dir)
        spctl = _load_json_object(pathlib.Path(summary["spctl"]))
        spctl["stderr"] = f"{summary['bundlePath']}: rejected\n"
        pathlib.Path(summary["spctl"]).write_text(json.dumps(spctl), encoding="utf-8")
        invalid = verify_summary(summary)
        if invalid["verified"] is True or not any("accepted" in item for item in invalid["failures"]):
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        summary = fixture_summary(output_dir)
        bundle_info = _load_json_object(pathlib.Path(summary["bundleInfo"]))
        bundle_info["systemExtension"]["extensionPoints"] = ["endpoint_security"]
        pathlib.Path(summary["bundleInfo"]).write_text(json.dumps(bundle_info), encoding="utf-8")
        invalid = verify_summary(summary)
        if invalid["verified"] is True or not any("network_extension_content_filter" in item for item in invalid["failures"]):
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        summary = fixture_summary(output_dir)
        bundle_info = _load_json_object(pathlib.Path(summary["bundleInfo"]))
        bundle_info["systemExtension"]["path"] = (
            f"/Library/SystemExtensions/{DEFAULT_SYSTEM_EXTENSION_BUNDLE_ID}.systemextension"
        )
        pathlib.Path(summary["bundleInfo"]).write_text(json.dumps(bundle_info), encoding="utf-8")
        system_extension_codesign = _load_json_object(pathlib.Path(summary["systemExtensionCodesign"]))
        system_extension_codesign["argv"] = [
            "codesign",
            "-dv",
            "--verbose=4",
            bundle_info["systemExtension"]["path"],
        ]
        pathlib.Path(summary["systemExtensionCodesign"]).write_text(
            json.dumps(system_extension_codesign),
            encoding="utf-8",
        )
        system_extension_codesign_verify = _load_json_object(
            pathlib.Path(summary["systemExtensionCodesignVerify"])
        )
        system_extension_codesign_verify["argv"] = [
            "codesign",
            "--verify",
            "--strict",
            "--verbose=4",
            bundle_info["systemExtension"]["path"],
        ]
        pathlib.Path(summary["systemExtensionCodesignVerify"]).write_text(
            json.dumps(system_extension_codesign_verify),
            encoding="utf-8",
        )
        system_extension_entitlements = _load_json_object(
            pathlib.Path(summary["systemExtensionEntitlements"])
        )
        system_extension_entitlements["argv"] = [
            "codesign",
            "-d",
            "--entitlements",
            ":-",
            bundle_info["systemExtension"]["path"],
        ]
        pathlib.Path(summary["systemExtensionEntitlements"]).write_text(
            json.dumps(system_extension_entitlements),
            encoding="utf-8",
        )
        invalid = verify_summary(summary)
        if invalid["verified"] is True or not any("embedded under bundlePath" in item for item in invalid["failures"]):
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        summary = fixture_summary(output_dir)
        codesign = _load_json_object(pathlib.Path(summary["codesign"]))
        codesign["stderr"] = codesign["stderr"].replace(
            f"Identifier={DEFAULT_APP_BUNDLE_ID}",
            f"Identifier={DEFAULT_SYSTEM_EXTENSION_BUNDLE_ID}",
        )
        pathlib.Path(summary["codesign"]).write_text(json.dumps(codesign), encoding="utf-8")
        invalid = verify_summary(summary)
        if invalid["verified"] is True or not any("expected app bundle identifier" in item for item in invalid["failures"]):
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        summary = fixture_summary(output_dir)
        codesign_verify = _load_json_object(pathlib.Path(summary["codesignVerify"]))
        codesign_verify["argv"] = ["codesign", "--verify", str(summary["bundlePath"])]
        pathlib.Path(summary["codesignVerify"]).write_text(json.dumps(codesign_verify), encoding="utf-8")
        invalid = verify_summary(summary)
        if invalid["verified"] is True or not any("codesign verify argv" in item for item in invalid["failures"]):
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        summary = fixture_summary(output_dir)
        codesign_deep_verify = _load_json_object(pathlib.Path(summary["codesignDeepVerify"]))
        codesign_deep_verify["exitCode"] = 1
        codesign_deep_verify["stderr"] = "a sealed resource is missing or invalid\n"
        pathlib.Path(summary["codesignDeepVerify"]).write_text(
            json.dumps(codesign_deep_verify),
            encoding="utf-8",
        )
        invalid = verify_summary(summary)
        if invalid["verified"] is True or not any("codesign deep verify command must exit 0" in item for item in invalid["failures"]):
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        summary = fixture_summary(output_dir)
        system_extension_codesign = _load_json_object(pathlib.Path(summary["systemExtensionCodesign"]))
        system_extension_codesign["stderr"] = system_extension_codesign["stderr"].replace(
            f"Identifier={DEFAULT_SYSTEM_EXTENSION_BUNDLE_ID}",
            "Identifier=dev.clawdstrike.agent.other-extension",
        )
        pathlib.Path(summary["systemExtensionCodesign"]).write_text(
            json.dumps(system_extension_codesign),
            encoding="utf-8",
        )
        invalid = verify_summary(summary)
        if invalid["verified"] is True or not any("system extension codesign output" in item for item in invalid["failures"]):
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        summary = fixture_summary(output_dir)
        system_extension_entitlements = _load_json_object(
            pathlib.Path(summary["systemExtensionEntitlements"])
        )
        system_extension_entitlements["stdout"] = plistlib.dumps(
            {
                "com.apple.developer.endpoint-security.client": True,
                "com.apple.developer.networking.networkextension": [],
            }
        ).decode("utf-8")
        pathlib.Path(summary["systemExtensionEntitlements"]).write_text(
            json.dumps(system_extension_entitlements),
            encoding="utf-8",
        )
        invalid = verify_summary(summary)
        if invalid["verified"] is True or not any("NetworkExtension entitlement" in item for item in invalid["failures"]):
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

    print("macos provider deployment evidence self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collect", action="store_true", help="Collect deployment evidence")
    parser.add_argument("--verify", action="store_true", help="Verify an existing summary")
    parser.add_argument("--self-test", action="store_true", help="Run built-in verifier checks")
    parser.add_argument("--summary", type=pathlib.Path, help="Path to summary.json")
    parser.add_argument("--output-dir", type=pathlib.Path)
    parser.add_argument("--run-id")
    parser.add_argument("--host-id")
    parser.add_argument("--user-id")
    parser.add_argument("--bundle-path", type=pathlib.Path)
    parser.add_argument("--team-id", default=DEFAULT_TEAM_ID)
    parser.add_argument("--app-bundle-id", default=DEFAULT_APP_BUNDLE_ID)
    parser.add_argument("--system-extension-bundle-id", default=DEFAULT_SYSTEM_EXTENSION_BUNDLE_ID)
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()
    if args.verify:
        if args.summary is None:
            parser.error("--summary is required with --verify")
        result = verify_summary(_load_json_object(args.summary))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["verified"] else 1
    if args.collect:
        missing = [
            name
            for name in ("output_dir", "run_id", "host_id", "user_id", "bundle_path")
            if getattr(args, name) is None
        ]
        if missing:
            parser.error("missing required arguments: " + ", ".join("--" + name.replace("_", "-") for name in missing))
        summary = collect_evidence(
            output_dir=args.output_dir,
            run_id=args.run_id,
            host_id=args.host_id,
            user_id=args.user_id,
            bundle_path=args.bundle_path,
            team_id=args.team_id,
            app_bundle_id=args.app_bundle_id,
            system_extension_bundle_id=args.system_extension_bundle_id,
        )
        result = verify_summary(summary)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["verified"] else 1

    parser.error("one of --collect, --verify, or --self-test is required")


if __name__ == "__main__":
    raise SystemExit(main())
