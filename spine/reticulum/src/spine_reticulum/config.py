"""YAML configuration parsing for the Reticulum adapter."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

from .priority import Priority

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.spine-reticulum/config.yaml")


@dataclass
class PeerConfig:
    name: str
    destination_hash: str
    aegis_node_id: Optional[str] = None


@dataclass
class AdapterConfig:
    """Parsed adapter configuration."""

    # Reticulum
    reticulum_config_dir: str = os.path.expanduser("~/.reticulum")
    identity_path: str = os.path.expanduser("~/.spine-reticulum/identity")

    # Adapter
    node_name: str = "spine-reticulum-node"
    db_path: str = os.path.expanduser("~/.spine-reticulum/spine.db")
    audit_log_path: str = os.path.expanduser("~/.spine-reticulum/audit.jsonl")
    lxmf_storage_dir: str = os.path.expanduser("~/.spine-reticulum/lxmf/")
    default_link_bps: float = 1200.0
    revocation_rate_limit_per_hour: int = 10

    # Drop thresholds
    drop_thresholds: dict[Priority, float] = field(default_factory=lambda: {
        Priority.HEARTBEAT: 100.0,
        Priority.NODE_ATTESTATION: 50.0,
        Priority.RUN: 20.0,
    })

    # Gateway (optional)
    nats_url: Optional[str] = None
    disclosure_policy_path: Optional[str] = None

    # Peers
    peers: list[PeerConfig] = field(default_factory=list)


def _expand(path: str) -> str:
    return os.path.expanduser(os.path.expandvars(path))


def load_config(path: str = DEFAULT_CONFIG_PATH) -> AdapterConfig:
    """Load adapter configuration from a YAML file."""
    with open(path, "r") as f:
        raw: dict[str, Any] = yaml.safe_load(f) or {}

    ret_section = raw.get("reticulum", {})
    adapter_section = raw.get("adapter", {})
    gateway_section = raw.get("gateway", {})
    peers_section = raw.get("peers", [])

    drop_raw = adapter_section.get("drop_thresholds", {})
    drop_thresholds: dict[Priority, float] = {}
    name_to_priority = {p.name.lower(): p for p in Priority}
    for name, bps in drop_raw.items():
        prio = name_to_priority.get(name.lower())
        if prio is not None:
            drop_thresholds[prio] = float(bps)

    peers = [
        PeerConfig(
            name=p.get("name", ""),
            destination_hash=p.get("destination_hash", ""),
            aegis_node_id=p.get("aegis_node_id"),
        )
        for p in peers_section
    ]

    return AdapterConfig(
        reticulum_config_dir=_expand(
            ret_section.get("config_dir", "~/.reticulum")
        ),
        identity_path=_expand(
            ret_section.get("identity_path", "~/.spine-reticulum/identity")
        ),
        node_name=adapter_section.get("node_name", "spine-reticulum-node"),
        db_path=_expand(adapter_section.get("db_path", "~/.spine-reticulum/spine.db")),
        audit_log_path=_expand(
            adapter_section.get("audit_log_path", "~/.spine-reticulum/audit.jsonl")
        ),
        lxmf_storage_dir=_expand(
            adapter_section.get("lxmf_storage_dir", "~/.spine-reticulum/lxmf/")
        ),
        default_link_bps=float(
            adapter_section.get("default_link_bps", 1200)
        ),
        revocation_rate_limit_per_hour=int(
            adapter_section.get("revocation_rate_limit_per_hour", 10)
        ),
        drop_thresholds=drop_thresholds or {
            Priority.HEARTBEAT: 100.0,
            Priority.NODE_ATTESTATION: 50.0,
            Priority.RUN: 20.0,
        },
        nats_url=gateway_section.get("nats_url"),
        disclosure_policy_path=(
            _expand(gateway_section["disclosure_policy_path"])
            if "disclosure_policy_path" in gateway_section
            else None
        ),
        peers=peers,
    )


def load_disclosure_policy(path: str) -> dict[str, Any]:
    """Load a disclosure policy YAML file."""
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}
