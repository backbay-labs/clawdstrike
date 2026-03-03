"""DataFrame and notebook integration for Hunt SDK.

Provides pandas/polars DataFrame conversion with lazy imports.
"""

from __future__ import annotations

from clawdstrike.hunt.types import Alert, TimelineEvent


def _event_to_dict(e: TimelineEvent) -> dict:
    return {
        "timestamp": e.timestamp.isoformat(),
        "source": e.source.value,
        "kind": e.kind.value,
        "verdict": e.verdict.value,
        "severity": e.severity,
        "summary": e.summary,
        "process": e.process,
        "namespace": e.namespace,
        "pod": e.pod,
        "action_type": e.action_type,
    }


def _alert_to_dict(a: Alert) -> dict:
    return {
        "rule_name": a.rule_name,
        "severity": a.severity.value,
        "title": a.title,
        "triggered_at": a.triggered_at.isoformat(),
        "description": a.description,
        "evidence_count": len(a.evidence),
    }


def to_dataframe(events: list[TimelineEvent]):
    """Convert events to pandas DataFrame. Requires pandas."""
    try:
        import pandas as pd
    except ImportError:
        raise ImportError("pandas is required: pip install pandas")
    return pd.DataFrame([_event_to_dict(e) for e in events])


def to_polars(events: list[TimelineEvent]):
    """Convert events to polars DataFrame. Requires polars."""
    try:
        import polars as pl
    except ImportError:
        raise ImportError("polars is required: pip install polars")
    return pl.DataFrame([_event_to_dict(e) for e in events])


def alerts_to_dataframe(alerts: list[Alert]):
    """Convert alerts to pandas DataFrame. Requires pandas."""
    try:
        import pandas as pd
    except ImportError:
        raise ImportError("pandas is required: pip install pandas")
    return pd.DataFrame([_alert_to_dict(a) for a in alerts])


def display_timeline(events: list[TimelineEvent]) -> None:
    """Display timeline as HTML in IPython/Jupyter. Requires IPython."""
    try:
        from IPython.display import display, HTML
    except ImportError:
        raise ImportError("IPython is required for display_timeline")
    rows = "".join(
        f"<tr><td>{e.timestamp.isoformat()}</td><td>{e.source.value}</td>"
        f"<td>{e.verdict.value}</td><td>{e.summary}</td></tr>"
        for e in events
    )
    html = (
        "<table><thead><tr><th>Timestamp</th><th>Source</th>"
        "<th>Verdict</th><th>Summary</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )
    display(HTML(html))


__all__ = ["to_dataframe", "to_polars", "alerts_to_dataframe", "display_timeline"]
