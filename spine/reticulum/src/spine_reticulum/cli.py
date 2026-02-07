"""CLI entry points for the Reticulum adapter (``spine-reticulum`` command)."""

from __future__ import annotations

import json
import logging
import sys

import click

from .audit import verify_chain
from .config import DEFAULT_CONFIG_PATH, load_config
from .envelope import verify_envelope


@click.group()
@click.option(
    "--config", "-c",
    default=DEFAULT_CONFIG_PATH,
    envvar="SPINE_RETICULUM_CONFIG",
    help="Path to adapter config YAML.",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging.")
@click.pass_context
def main(ctx: click.Context, config: str, verbose: bool) -> None:
    """Spine Reticulum Adapter -- off-grid envelope transport."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config


@main.command()
@click.pass_context
def run(ctx: click.Context) -> None:
    """Start the Reticulum adapter process."""
    from .adapter import ReticulumAdapter

    cfg = load_config(ctx.obj["config_path"])
    adapter = ReticulumAdapter(cfg)
    try:
        adapter.start()
        click.echo(f"Adapter running (node={cfg.node_name}). Press Ctrl+C to stop.")
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        click.echo("\nShutting down...")
    finally:
        adapter.stop()


@main.command()
@click.argument("envelope_file", type=click.Path(exists=True))
def verify(envelope_file: str) -> None:
    """Verify a signed envelope JSON file."""
    with open(envelope_file, "r") as f:
        envelope = json.load(f)
    try:
        valid = verify_envelope(envelope)
        if valid:
            click.echo("Envelope signature is VALID.")
        else:
            click.echo("Envelope signature is INVALID.", err=True)
            sys.exit(1)
    except ValueError as exc:
        click.echo(f"Verification error: {exc}", err=True)
        sys.exit(1)


@main.command("verify-audit")
@click.argument("audit_log", type=click.Path(exists=True))
def verify_audit(audit_log: str) -> None:
    """Verify the hash chain integrity of an audit log file."""
    valid, count = verify_chain(audit_log)
    if valid:
        click.echo(f"Audit log OK ({count} entries, chain intact).")
    else:
        click.echo(f"Audit log TAMPERED at entry {count}.", err=True)
        sys.exit(1)


@main.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show adapter status (store stats, peer count)."""
    from .store import SpineStore

    cfg = load_config(ctx.obj["config_path"])
    store = SpineStore(cfg.db_path)
    total = store.count()
    store.close()
    click.echo(f"Envelopes stored: {total}")
    click.echo(f"DB path: {cfg.db_path}")
    click.echo(f"Audit log: {cfg.audit_log_path}")


@main.command("send-envelope")
@click.argument("envelope_file", type=click.Path(exists=True))
@click.pass_context
def send_envelope(ctx: click.Context, envelope_file: str) -> None:
    """Send a signed envelope via Reticulum."""
    from .adapter import ReticulumAdapter

    cfg = load_config(ctx.obj["config_path"])
    with open(envelope_file, "r") as f:
        envelope = json.load(f)

    adapter = ReticulumAdapter(cfg)
    adapter.start()
    try:
        adapter.send_envelope(envelope)
        click.echo(f"Envelope {envelope.get('envelope_hash', '?')} sent.")
    finally:
        adapter.stop()
