"""Backend dispatch layer for Clawdstrike policy evaluation.

Provides an EngineBackend protocol with two implementations:
- NativeEngineBackend: Delegates to Rust HushEngine via clawdstrike._native
- PurePythonBackend: Uses pure Python policy engine and guards (fallback)
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request
from uuid import uuid4

from clawdstrike.exceptions import UnsupportedOriginFeatureError

logger = logging.getLogger("clawdstrike")

_UNTRUSTED_TEXT_CUSTOM_TYPES = frozenset({"untrusted_text", "hushclaw.untrusted_text"})


@runtime_checkable
class EngineBackend(Protocol):
    """Backend protocol for policy evaluation."""

    name: str

    def check_file_access(self, path: str, ctx: dict[str, Any]) -> dict: pass
    def check_file_write(self, path: str, content: bytes, ctx: dict[str, Any]) -> dict: pass
    def check_shell(self, command: str, ctx: dict[str, Any]) -> dict: pass
    def check_network(self, host: str, port: int, ctx: dict[str, Any]) -> dict: pass
    def check_mcp_tool(self, tool: str, args: dict[str, Any], ctx: dict[str, Any]) -> dict: pass
    def check_patch(self, path: str, diff: str, ctx: dict[str, Any]) -> dict: pass
    def check_untrusted_text(
        self, source: str | None, text: str, ctx: dict[str, Any],
    ) -> dict: pass
    def check_custom(
        self, custom_type: str, custom_data: dict[str, Any], ctx: dict[str, Any],
    ) -> dict: pass
    def policy_yaml(self) -> str: pass


class NativeEngineBackend:
    """Backend that delegates to the Rust HushEngine via clawdstrike._native."""

    name = "native"

    def __init__(self, engine: Any) -> None:
        self._engine = engine  # clawdstrike._native.NativeEngine instance

    def check_file_access(self, path: str, ctx: dict[str, Any]) -> dict:
        return self._engine.check_file_access(path, ctx)

    def check_file_write(self, path: str, content: bytes, ctx: dict[str, Any]) -> dict:
        return self._engine.check_file_write(path, content, ctx)

    def check_shell(self, command: str, ctx: dict[str, Any]) -> dict:
        return self._engine.check_shell(command, ctx)

    def check_network(self, host: str, port: int, ctx: dict[str, Any]) -> dict:
        return self._engine.check_network(host, port, ctx)

    def check_mcp_tool(self, tool: str, args: dict[str, Any], ctx: dict[str, Any]) -> dict:
        args_json = json.dumps(args)
        return self._engine.check_mcp_tool(tool, args_json, ctx)

    def check_patch(self, path: str, diff: str, ctx: dict[str, Any]) -> dict:
        return self._engine.check_patch(path, diff, ctx)

    def check_untrusted_text(
        self, source: str | None, text: str, ctx: dict[str, Any],
    ) -> dict:
        return self._engine.check_untrusted_text(source, text, ctx)

    def check_custom(
        self, custom_type: str, custom_data: dict[str, Any], ctx: dict[str, Any],
    ) -> dict:
        data_json = json.dumps(custom_data)
        return self._engine.check_custom(custom_type, data_json, ctx)

    def policy_yaml(self) -> str:
        return self._engine.policy_yaml()

    @classmethod
    def from_yaml(
        cls, yaml_str: str, *, base_path: str | None = None,
    ) -> NativeEngineBackend:
        from clawdstrike.native import get_native_module

        mod = get_native_module()
        engine = mod.NativeEngine.from_yaml(yaml_str, base_path)
        return cls(engine)

    @classmethod
    def from_ruleset(cls, name: str) -> NativeEngineBackend:
        from clawdstrike.native import get_native_module

        mod = get_native_module()
        engine = mod.NativeEngine.from_ruleset(name)
        return cls(engine)


def _origin_runtime_error(backend_name: str) -> UnsupportedOriginFeatureError:
    return UnsupportedOriginFeatureError(
        f"Origin-aware runtime checks are not supported by {backend_name}; "
        "use the native or daemon-backed backend for origin enforcement."
    )


def _pure_python_origin_guard(ctx: dict[str, Any], *, custom_type: str | None = None) -> None:
    if ctx.get("origin") is not None or custom_type == "origin.output_send":
        raise _origin_runtime_error("the pure-Python backend")


def _single_result_report(
    *,
    allowed: bool,
    guard: str,
    severity: str,
    message: str,
    details: Any = None,
) -> dict[str, Any]:
    entry = {
        "allowed": allowed,
        "guard": guard,
        "severity": severity,
        "message": message,
        "details": details,
    }
    return {"overall": dict(entry), "per_guard": [entry]}


class DaemonEngineBackend:
    """Backend that delegates checks to hushd over HTTP."""

    name = "daemon"

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        trimmed = base_url.rstrip("/")
        parsed = urllib_parse.urlparse(trimmed)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"invalid daemon URL {base_url!r}: expected absolute URL")
        self._check_url = f"{trimmed}/api/v1/check"
        self._eval_url = f"{trimmed}/api/v1/eval"
        self._api_key = api_key
        self._timeout = timeout

    def check_file_access(self, path: str, ctx: dict[str, Any]) -> dict[str, Any]:
        return self._request({"action_type": "file_access", "target": path}, ctx)

    def check_file_write(self, path: str, content: bytes, ctx: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            {
                "action_type": "file_write",
                "target": path,
                "content": content.decode("utf-8", errors="replace"),
            },
            ctx,
        )

    def check_shell(self, command: str, ctx: dict[str, Any]) -> dict[str, Any]:
        return self._request({"action_type": "shell", "target": command}, ctx)

    def check_network(self, host: str, port: int, ctx: dict[str, Any]) -> dict[str, Any]:
        return self._request({"action_type": "egress", "target": f"{host}:{port}"}, ctx)

    def check_mcp_tool(
        self,
        tool: str,
        args: dict[str, Any],
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        return self._request(
            {
                "action_type": "mcp_tool",
                "target": tool,
                "args": args,
            },
            ctx,
        )

    def check_patch(self, path: str, diff: str, ctx: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            {
                "action_type": "patch",
                "target": path,
                "content": diff,
            },
            ctx,
        )

    def check_untrusted_text(
        self, source: str | None, text: str, ctx: dict[str, Any],
    ) -> dict[str, Any]:
        return self._eval_untrusted_text_event(
            custom_type="untrusted_text",
            source=source,
            text=text,
            ctx=ctx,
        )

    def _eval_untrusted_text_event(
        self,
        *,
        custom_type: str,
        source: str | None,
        text: str,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        event: dict[str, Any] = {
            "eventId": f"py-origin-{uuid4()}",
            "eventType": "custom",
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "data": {
                "type": "custom",
                "customType": custom_type,
                "text": text,
            },
        }
        if source is not None:
            event["data"]["source"] = source
        if ctx.get("session_id") is not None:
            event["sessionId"] = ctx["session_id"]

        metadata: dict[str, Any] = {}
        if isinstance(ctx.get("metadata"), Mapping):
            metadata.update(dict(ctx["metadata"]))
        if ctx.get("origin") is not None:
            metadata["origin"] = ctx["origin"]
        if ctx.get("agent_id") is not None:
            metadata["endpointAgentId"] = ctx["agent_id"]
        if metadata:
            event["metadata"] = metadata

        return self._eval(event)

    def check_custom(
        self, custom_type: str, custom_data: dict[str, Any], ctx: dict[str, Any],
    ) -> dict[str, Any]:
        if custom_type in _UNTRUSTED_TEXT_CUSTOM_TYPES:
            if not isinstance(custom_data, Mapping):
                return self._daemon_failure(f"{custom_type} payload must be a mapping")
            text = custom_data.get("text")
            if not isinstance(text, str):
                return self._daemon_failure(f"{custom_type} requires a text string")
            source = custom_data.get("source")
            if source is not None and not isinstance(source, str):
                return self._daemon_failure(f"{custom_type} source must be a string")
            return self._eval_untrusted_text_event(
                custom_type=custom_type,
                source=source,
                text=text,
                ctx=ctx,
            )

        if custom_type != "origin.output_send":
            return self._daemon_failure(
                f"unsupported daemon custom action: {custom_type}",
            )

        if not isinstance(custom_data, Mapping):
            return self._daemon_failure("origin.output_send payload must be a mapping")

        text = custom_data.get("text")
        if not isinstance(text, str) or not text:
            return self._daemon_failure("origin.output_send requires a non-empty text field")

        request: dict[str, Any] = {
            "action_type": "output_send",
            "target": custom_data.get("target", ""),
            "content": text,
        }
        args: dict[str, Any] = {}
        if "mime_type" in custom_data:
            args["mime_type"] = custom_data["mime_type"]
        if "metadata" in custom_data:
            metadata = custom_data["metadata"]
            if not isinstance(metadata, Mapping):
                return self._daemon_failure("origin.output_send metadata must be a mapping")
            args["metadata"] = dict(metadata)
        if args:
            request["args"] = args
        return self._request(request, ctx)

    def policy_yaml(self) -> str:
        return ""

    def _request(self, payload: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        request_payload = dict(payload)
        for key in ("session_id", "agent_id", "metadata", "origin"):
            if ctx.get(key) is not None:
                request_payload[key] = ctx[key]

        return self._post_report(self._check_url, request_payload)

    def _eval(self, event: dict[str, Any]) -> dict[str, Any]:
        parsed = self._post_json(self._eval_url, event)
        if "overall" in parsed and "per_guard" in parsed:
            return parsed

        report = parsed.get("report")
        if isinstance(report, dict) and "overall" in report and "per_guard" in report:
            return report

        message = parsed.get("message")
        if isinstance(message, str) and message:
            return self._daemon_failure(message)
        return self._daemon_failure("Daemon returned malformed eval payload")

    def _post_report(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        parsed = self._post_json(url, payload)
        if "overall" in parsed and "per_guard" in parsed:
            return parsed

        return _single_result_report(
            allowed=bool(parsed.get("allowed", False)),
            guard=str(parsed.get("guard") or "daemon"),
            severity=str(parsed.get("severity") or "error"),
            message=str(parsed.get("message") or "Malformed daemon response"),
            details=parsed.get("details"),
        )

    def _post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "content-type": "application/json",
            "accept": "application/json",
        }
        if self._api_key:
            headers["authorization"] = f"Bearer {self._api_key}"

        req = urllib_request.Request(
            url,
            data=body,
            headers=headers,
            method="POST",
        )

        try:
            with urllib_request.urlopen(req, timeout=self._timeout) as response:
                raw = response.read().decode("utf-8")
        except urllib_error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace").strip()
            suffix = f": {detail}" if detail else ""
            return self._daemon_failure(
                f"Daemon check failed with HTTP {exc.code}{suffix}",
            )
        except urllib_error.URLError as exc:
            return self._daemon_failure(f"Daemon check failed: {exc.reason}")

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return self._daemon_failure("Daemon returned invalid JSON")

        if not isinstance(parsed, dict):
            return self._daemon_failure("Daemon returned malformed decision payload")
        return parsed

    def _daemon_failure(self, message: str) -> dict[str, Any]:
        return _single_result_report(
            allowed=False,
            guard="daemon",
            severity="critical",
            message=message,
        )


def _results_to_report_dict(results: list) -> dict:
    """Convert a list of GuardResult objects to a GuardReport-like dict.

    This produces the same shape as the native GuardReport serialization so that
    Decision.from_report_dict() can consume either backend's output uniformly.
    """
    from clawdstrike.guards.base import Severity

    per_guard = []
    for r in results:
        per_guard.append({
            "allowed": r.allowed,
            "guard": r.guard,
            "severity": r.severity.value if isinstance(r.severity, Severity) else str(r.severity),
            "message": r.message,
            "details": r.details,
        })

    # Determine overall result (same aggregation logic as Decision.from_guard_results)
    severity_order = {
        Severity.CRITICAL: 4,
        Severity.ERROR: 3,
        Severity.WARNING: 2,
        Severity.INFO: 1,
    }
    denies = [r for r in results if not r.allowed]
    warns = [r for r in results if r.allowed and r.severity == Severity.WARNING]

    def _sev_value(sev: Any) -> str:
        return sev.value if isinstance(sev, Severity) else str(sev)

    if denies:
        worst = max(denies, key=lambda r: severity_order.get(r.severity, 0))
        overall = {
            "allowed": False,
            "guard": worst.guard,
            "severity": _sev_value(worst.severity),
            "message": worst.message,
            "details": worst.details,
        }
    elif warns:
        worst = max(warns, key=lambda r: severity_order.get(r.severity, 0))
        overall = {
            "allowed": True,
            "guard": worst.guard,
            "severity": "warning",
            "message": worst.message,
            "details": worst.details,
        }
    elif results:
        overall = {
            "allowed": True,
            "guard": results[0].guard,
            "severity": "info",
            "message": "Action allowed",
            "details": None,
        }
    else:
        overall = {
            "allowed": True,
            "guard": None,
            "severity": "info",
            "message": "No guards evaluated",
            "details": None,
        }

    return {"overall": overall, "per_guard": per_guard}


class PurePythonBackend:
    """Fallback backend using pure Python policy engine and guards."""

    name = "pure_python"

    def __init__(self, engine: Any) -> None:
        # engine is a PolicyEngine instance
        self._engine = engine

    def check_file_access(self, path: str, ctx: dict[str, Any]) -> dict:
        _pure_python_origin_guard(ctx)
        from clawdstrike.guards.base import FileAccessAction, GuardContext

        action = FileAccessAction(path=path)
        context = GuardContext(**ctx)
        results = self._engine.check(action, context)
        return _results_to_report_dict(results)

    def check_file_write(self, path: str, content: bytes, ctx: dict[str, Any]) -> dict:
        _pure_python_origin_guard(ctx)
        from clawdstrike.guards.base import FileWriteAction, GuardContext

        action = FileWriteAction(path=path, content=content)
        context = GuardContext(**ctx)
        results = self._engine.check(action, context)
        return _results_to_report_dict(results)

    def check_shell(self, command: str, ctx: dict[str, Any]) -> dict:
        _pure_python_origin_guard(ctx)
        from clawdstrike.guards.base import GuardContext, ShellCommandAction

        action = ShellCommandAction(command=command)
        context = GuardContext(**ctx)
        results = self._engine.check(action, context)
        return _results_to_report_dict(results)

    def check_network(self, host: str, port: int, ctx: dict[str, Any]) -> dict:
        _pure_python_origin_guard(ctx)
        from clawdstrike.guards.base import GuardContext, NetworkEgressAction

        action = NetworkEgressAction(host=host, port=port)
        context = GuardContext(**ctx)
        results = self._engine.check(action, context)
        return _results_to_report_dict(results)

    def check_mcp_tool(self, tool: str, args: dict[str, Any], ctx: dict[str, Any]) -> dict:
        _pure_python_origin_guard(ctx)
        from clawdstrike.guards.base import GuardContext, McpToolAction

        action = McpToolAction(tool=tool, args=args)
        context = GuardContext(**ctx)
        results = self._engine.check(action, context)
        return _results_to_report_dict(results)

    def check_patch(self, path: str, diff: str, ctx: dict[str, Any]) -> dict:
        _pure_python_origin_guard(ctx)
        from clawdstrike.guards.base import GuardContext, PatchAction

        action = PatchAction(path=path, diff=diff)
        context = GuardContext(**ctx)
        results = self._engine.check(action, context)
        return _results_to_report_dict(results)

    def check_untrusted_text(
        self, source: str | None, text: str, ctx: dict[str, Any],
    ) -> dict:
        _pure_python_origin_guard(ctx)
        from clawdstrike.guards.base import CustomAction, GuardContext

        action = CustomAction(
            custom_type="untrusted_text",
            custom_data={"source": source, "text": text},
        )
        context = GuardContext(**ctx)
        results = self._engine.check(action, context)
        return _results_to_report_dict(results)

    def check_custom(
        self, custom_type: str, custom_data: dict[str, Any], ctx: dict[str, Any],
    ) -> dict:
        _pure_python_origin_guard(ctx, custom_type=custom_type)
        from clawdstrike.guards.base import CustomAction, GuardContext

        action = CustomAction(custom_type=custom_type, custom_data=custom_data)
        context = GuardContext(**ctx)
        results = self._engine.check(action, context)
        return _results_to_report_dict(results)

    def policy_yaml(self) -> str:
        return self._engine.policy.to_yaml()
