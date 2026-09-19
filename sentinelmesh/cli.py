from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from sentinelmesh.config import Settings
from sentinelmesh.core import (
    export_filename_stem,
    prune_records_older_than,
    safe_export_payload,
    write_archive_index,
    write_json_export,
)
from sentinelmesh.profiler import AttackProfiler
from sentinelmesh.storage import EventStore


def add_subcommands(parser: argparse.ArgumentParser, settings: Settings) -> None:
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("export-sessions", help="Export recent sessions as JSON archives")
    subparsers.add_parser("archive-recent", help="Export recent sessions and write an archive index")
    subparsers.add_parser("stats", help="Print current store statistics")

    wipe_parser = subparsers.add_parser("wipe", help="Remove old records from the local store")
    wipe_parser.add_argument(
        "--before",
        required=True,
        help="ISO timestamp before which records will be removed",
    )
    wipe_parser.add_argument(
        "--include-profiles",
        action="store_true",
        help="Also remove profiles older than the cutoff",
    )
    wipe_parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print a JSON report of deleted rows instead of a human summary",
    )

    key_parser = subparsers.add_parser("rotate-keys", help="Replace the local SSH host key and clear caches")
    key_parser.add_argument(
        "--retain-reports",
        action="store_true",
        help="Keep existing reports and only rotate keys",
    )

    subparsers.add_parser("generate-keys", help="Generate a new SSH host key if one is missing")

    subparsers.add_parser("doctor", help="Validate deployment settings and local artifacts")


def run_command(args: argparse.Namespace, settings: Settings) -> None:
    store = EventStore(settings.database_path)

    if args.command == "export-sessions":
        _export_sessions(store, settings.reports_dir)
        return

    if args.command == "archive-recent":
        _archive_recent(store, settings.reports_dir)
        return

    if args.command == "stats":
        _print_stats(store, settings)
        return

    if args.command == "wipe":
        _run_wipe(args, settings.database_path, stdout=args.stdout)
        return

    if args.command == "rotate-keys":
        _rotate_keys(settings, retain_reports=args.retain_reports)
        return

    if args.command == "generate-keys":
        _generate_keys(settings)
        return

    if args.command == "doctor":
        _run_doctor(settings)
        return


def _export_sessions(store: EventStore, reports_dir: Path) -> None:
    sessions = store.list_recent_sessions(50)
    exported = 0
    for session in sessions:
        commands = store.list_commands_for_session(session.session_id)
        profiler = AttackProfiler()
        profile = profiler.build_profile(session, commands)
        payload = safe_export_payload(session, profile, [])
        stem = export_filename_stem(session.session_id, session.service, session.started_at)
        path = write_json_export(reports_dir, stem, payload)
        print(f"exported {session.service} session {session.session_id} -> {path.name}")
        exported += 1

    print(f"export complete: {exported} session(s) written to {reports_dir}")


def _archive_recent(store: EventStore, reports_dir: Path) -> None:
    sessions = store.list_recent_sessions(200)
    entries: list[dict[str, Any]] = []
    exported = 0
    for session in sessions:
        commands = store.list_commands_for_session(session.session_id)
        profiler = AttackProfiler()
        profile = profiler.build_profile(session, commands)
        payload = safe_export_payload(session, profile, [])
        stem = export_filename_stem(session.session_id, session.service, session.started_at)
        path = write_json_export(reports_dir, stem, payload)
        entries.append(
            {
                "filename": path.name,
                "session_id": session.session_id,
                "service": session.service,
                "remote_ip": session.remote_ip,
                "started_at": str(session.started_at),
                "exported_at": str(Path.cwd().joinpath(".").resolve()),
            }
        )
        exported += 1

    index_path = write_archive_index(reports_dir / "exports", entries)
    print(f"archive complete: {exported} session(s) indexed at {index_path}")


def _print_stats(store: EventStore, settings: Settings) -> None:
    metrics = store.dashboard_metrics()
    print(json.dumps(metrics, indent=2, sort_keys=True))
    print("providers:", json.dumps(settings.intel_provider_status(), sort_keys=True))
    print("coverage:", settings.intel_provider_coverage())
    print("warnings:", settings.deployment_warnings())


def _run_wipe(args: argparse.Namespace, database_path: Path, *, stdout: bool) -> None:
    deleted = prune_records_older_than(
        database_path,
        args.before,
        include_sessions=True,
        include_commands=True,
        include_events=True,
        include_profiles=args.include_profiles,
    )

    summary = {
        "before": args.before,
        "deleted": deleted,
        "include_profiles": args.include_profiles,
    }

    if stdout:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return

    lines = [
        "wipe complete",
        f"before: {args.before}",
        f"deleted: {deleted}",
    ]
    if args.include_profiles:
        lines.append("profiles were included in the wipe")

    print("\n".join(lines))


def _run_doctor(settings: Settings) -> None:
    from sentinelmesh.doctor import build_report

    print(json.dumps(build_report(settings), indent=2))


def _rotate_keys(settings: Settings, *, retain_reports: bool) -> None:
    from sentinelmesh.honeypot_engine import _ensure_host_key

    try:
        import asyncssh
    except Exception:
        asyncssh = None

    if asyncssh is not None:
        _ensure_host_key(asyncssh)

    if settings.host_key_path.exists():
        print(f"host key present at {settings.host_key_path}")
    else:
        print("no host key material available; run generate-keys or install asyncssh")


def _generate_keys(settings: Settings) -> None:
    try:
        import asyncssh
    except Exception as exc:
        print(f"cannot generate keys: asyncssh unavailable ({exc})")
        sys.exit(1)

    from sentinelmesh.honeypot_engine import _ensure_host_key

    _ensure_host_key(asyncssh)
    print(f"host key generated at {settings.host_key_path}")
