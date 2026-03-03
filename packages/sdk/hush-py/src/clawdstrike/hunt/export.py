"""Export adapters for Hunt SDK -- webhook, Splunk HEC, Elasticsearch, STIX, CSV."""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Coroutine, Protocol, Union, runtime_checkable

from clawdstrike.hunt.errors import ExportError
from clawdstrike.hunt.types import Alert, IocEntry, IocMatch, TimelineEvent


@dataclass
class RetryConfig:
    """Configuration for retry behaviour on export adapters."""

    max_retries: int = 0
    base_delay: float = 1.0


async def _with_retry(
    fn: Callable[..., Coroutine[Any, Any, Any]],
    retry: RetryConfig,
) -> Any:
    """Execute *fn* with exponential back-off on 5xx / connection errors.

    4xx errors are **not** retried (they indicate a client-side problem).
    """
    last_exc: Exception | None = None
    for attempt in range(1 + retry.max_retries):
        try:
            return await fn()
        except ExportError as exc:
            msg = str(exc)
            # Only retry on 5xx status codes
            status = _extract_status(msg)
            if status is not None and status < 500:
                raise
            last_exc = exc
        except Exception as exc:
            # Connection / transport errors are retryable
            last_exc = exc
        if attempt < retry.max_retries:
            await asyncio.sleep(retry.base_delay * (2 ** attempt))
    if last_exc is not None:
        raise last_exc
    raise ExportError("retry exhausted with no result")  # pragma: no cover


def _extract_status(msg: str) -> int | None:
    """Best-effort extraction of HTTP status code from an ExportError message."""
    # Messages look like "Webhook export failed: 503"
    parts = msg.rsplit(":", 1)
    if len(parts) == 2:
        try:
            return int(parts[1].strip())
        except ValueError:
            pass
    return None


@runtime_checkable
class ExportAdapter(Protocol):
    """Protocol for export adapters."""

    async def export(self, items: list[Union[Alert, TimelineEvent]]) -> None:
        pass


class WebhookAdapter:
    """Export items via HTTP POST to a webhook URL."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        retry: RetryConfig | None = None,
    ) -> None:
        self.url = url
        self.headers = headers or {}
        self.retry = retry or RetryConfig()

    async def export(self, items: list[Union[Alert, TimelineEvent]]) -> None:
        try:
            import httpx
        except ImportError:
            raise ImportError(
                "httpx is required for WebhookAdapter: pip install httpx"
            )

        async def _do() -> None:
            body = json.dumps([_item_to_json(item) for item in items])
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    self.url,
                    content=body,
                    headers={"Content-Type": "application/json", **self.headers},
                )
                if resp.status_code >= 400:
                    raise ExportError(f"Webhook export failed: {resp.status_code}")

        await _with_retry(_do, self.retry)


class SplunkHECAdapter:
    """Export items to Splunk via the HTTP Event Collector."""

    def __init__(
        self,
        url: str,
        token: str,
        index: str | None = None,
        retry: RetryConfig | None = None,
    ) -> None:
        self.url = url
        self.token = token
        self.index = index
        self.retry = retry or RetryConfig()

    async def export(self, items: list[Union[Alert, TimelineEvent]]) -> None:
        try:
            import httpx
        except ImportError:
            raise ImportError(
                "httpx is required for SplunkHECAdapter: pip install httpx"
            )

        async def _do() -> None:
            events: list[str] = []
            for item in items:
                data = _item_to_json(item)
                event: dict = {"event": data}
                if self.index:
                    event["index"] = self.index
                events.append(json.dumps(event))
            body = "\n".join(events)
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    self.url,
                    content=body,
                    headers={
                        "Authorization": f"Splunk {self.token}",
                        "Content-Type": "application/json",
                    },
                )
                if resp.status_code >= 400:
                    raise ExportError(f"Splunk HEC export failed: {resp.status_code}")

        await _with_retry(_do, self.retry)


class ElasticAdapter:
    """Export items to Elasticsearch via the _bulk API."""

    def __init__(
        self,
        url: str,
        index: str,
        api_key: str | None = None,
        retry: RetryConfig | None = None,
    ) -> None:
        self.url = url
        self.index = index
        self.api_key = api_key
        self.retry = retry or RetryConfig()

    async def export(self, items: list[Union[Alert, TimelineEvent]]) -> None:
        try:
            import httpx
        except ImportError:
            raise ImportError(
                "httpx is required for ElasticAdapter: pip install httpx"
            )

        async def _do() -> None:
            lines: list[str] = []
            for item in items:
                lines.append(json.dumps({"index": {"_index": self.index}}))
                lines.append(json.dumps(_item_to_json(item)))
            body = "\n".join(lines) + "\n"
            headers: dict[str, str] = {"Content-Type": "application/x-ndjson"}
            if self.api_key:
                headers["Authorization"] = f"ApiKey {self.api_key}"
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self.url}/_bulk", content=body, headers=headers
                )
                if resp.status_code >= 400:
                    raise ExportError(
                        f"Elasticsearch export failed: {resp.status_code}"
                    )
                try:
                    payload = resp.json()
                except ValueError:
                    payload = None
                if isinstance(payload, dict) and payload.get("errors") is True:
                    raise ExportError(
                        f"Elasticsearch export failed: {resp.status_code}"
                    )

        await _with_retry(_do, self.retry)


def to_stix(
    alerts: list[Alert], ioc_matches: list[IocMatch] | None = None
) -> dict:
    """Convert alerts and optional IOC matches to a STIX 2.1 bundle."""
    objects: list[dict] = []
    for alert in alerts:
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": alert.triggered_at.isoformat(),
                "modified": alert.triggered_at.isoformat(),
                "name": alert.title,
                "description": alert.description,
                "pattern_type": "clawdstrike",
                "pattern": f"[alert:rule_name = '{_escape_stix_value(alert.rule_name)}']",
                "valid_from": alert.triggered_at.isoformat(),
                "labels": [alert.severity.value],
            }
        )
    if ioc_matches:
        for match in ioc_matches:
            for ioc in match.matched_iocs:
                objects.append(
                    {
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": f"indicator--{uuid.uuid4()}",
                        "created": match.event.timestamp.isoformat(),
                        "modified": match.event.timestamp.isoformat(),
                        "name": f"IOC: {ioc.indicator}",
                        "description": ioc.description
                        or f"IOC match: {ioc.indicator}",
                        "pattern_type": "stix",
                        "pattern": _ioc_to_stix_pattern(ioc),
                        "valid_from": match.event.timestamp.isoformat(),
                    }
                )
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def to_csv(items: list[Union[Alert, TimelineEvent]]) -> str:
    """Convert items to CSV string. Handles mixed Alert/TimelineEvent lists."""
    if not items:
        return ""
    alerts = [i for i in items if isinstance(i, Alert)]
    events = [i for i in items if isinstance(i, TimelineEvent)]
    sections: list[str] = []
    if alerts:
        sections.append(_alerts_csv(alerts))
    if events:
        sections.append(_events_csv(events))
    return "\n".join(sections)


def _alerts_csv(alerts: list[Alert]) -> str:
    headers = [
        "rule_name",
        "severity",
        "title",
        "triggered_at",
        "description",
        "evidence_count",
    ]
    rows = [
        ",".join(
            [
                _csv_escape(a.rule_name),
                _csv_escape(a.severity.value),
                _csv_escape(a.title),
                _csv_escape(a.triggered_at.isoformat()),
                _csv_escape(a.description),
                str(len(a.evidence)),
            ]
        )
        for a in alerts
    ]
    return "\n".join([",".join(headers)] + rows)


def _events_csv(events: list[TimelineEvent]) -> str:
    headers = [
        "timestamp",
        "source",
        "kind",
        "verdict",
        "summary",
        "process",
        "action_type",
    ]
    rows = [
        ",".join(
            [
                _csv_escape(e.timestamp.isoformat()),
                _csv_escape(e.source.value),
                _csv_escape(e.kind.value),
                _csv_escape(e.verdict.value),
                _csv_escape(e.summary),
                _csv_escape(e.process or ""),
                _csv_escape(e.action_type or ""),
            ]
        )
        for e in events
    ]
    return "\n".join([",".join(headers)] + rows)


def to_jsonl(items: list[Union[Alert, TimelineEvent]]) -> str:
    """Convert items to newline-delimited JSON (JSONL) string."""
    return "\n".join(json.dumps(_item_to_json(item)) for item in items)


def _item_to_json(item: Union[Alert, TimelineEvent]) -> dict:
    if isinstance(item, Alert):
        return {
            "type": "alert",
            "rule_name": item.rule_name,
            "severity": item.severity.value,
            "title": item.title,
            "triggered_at": item.triggered_at.isoformat(),
            "description": item.description,
            "evidence_count": len(item.evidence),
        }
    return {
        "type": "event",
        "timestamp": item.timestamp.isoformat(),
        "source": item.source.value,
        "kind": item.kind.value,
        "verdict": item.verdict.value,
        "summary": item.summary,
        "process": item.process,
        "action_type": item.action_type,
    }


def _escape_stix_value(value: str) -> str:
    """Escape backslashes, single quotes, and brackets for STIX patterns."""
    return value.replace("\\", "\\\\").replace("'", "\\'").replace("]", "\\]")


def _ioc_to_stix_pattern(ioc: IocEntry) -> str:
    ioc_type_val = ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else str(ioc.ioc_type)
    escaped = _escape_stix_value(ioc.indicator)
    mapping = {
        "sha256": f"[file:hashes.'SHA-256' = '{escaped}']",
        "sha1": f"[file:hashes.'SHA-1' = '{escaped}']",
        "md5": f"[file:hashes.MD5 = '{escaped}']",
        "domain": f"[domain-name:value = '{escaped}']",
        "ipv4": f"[ipv4-addr:value = '{escaped}']",
        "ipv6": f"[ipv6-addr:value = '{escaped}']",
        "url": f"[url:value = '{escaped}']",
    }
    return mapping.get(ioc_type_val, f"[x-clawdstrike:value = '{escaped}']")


def _csv_escape(value: str) -> str:
    if "," in value or '"' in value or "\n" in value or "\r" in value:
        return '"' + value.replace('"', '""') + '"'
    return value


__all__ = [
    "ExportAdapter",
    "RetryConfig",
    "WebhookAdapter",
    "SplunkHECAdapter",
    "ElasticAdapter",
    "to_stix",
    "to_csv",
    "to_jsonl",
]
