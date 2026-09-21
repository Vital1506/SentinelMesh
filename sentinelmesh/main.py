from __future__ import annotations

import argparse
import asyncio
import json
import logging
import threading
from pathlib import Path

from sentinelmesh.config import Settings
from sentinelmesh.deception_ai import AdaptiveDeceptionEngine, extract_sequences
from sentinelmesh.doctor import print_report, report_as_json
from sentinelmesh.honeypot_engine import HoneypotEngine
from sentinelmesh.intel_engine import ThreatIntelCorrelator
from sentinelmesh.profiler import AttackProfiler
from sentinelmesh.reporter import ReportGenerator
from sentinelmesh.storage import EventStore


def _make_settings() -> Settings:
    return Settings.from_env()


def build_runtime() -> tuple[Settings, EventStore, AdaptiveDeceptionEngine, HoneypotEngine]:
    settings = _make_settings()
    store = EventStore(settings.database_path)
    profiler = AttackProfiler()
    correlator = ThreatIntelCorrelator(settings)
    reporter = ReportGenerator(settings.reports_dir)
    deception_engine = AdaptiveDeceptionEngine(
        settings.model_dir / "sequence_model.json", settings.hostname_seed
    )
    honeypot = HoneypotEngine(
        settings, store, profiler, correlator, reporter, deception_engine
    )
    return settings, store, deception_engine, honeypot


def main() -> None:
    settings = _make_settings()

    log_level = getattr(settings, "log_level", None)
    if isinstance(log_level, str) and log_level:
        level = getattr(logging, log_level.upper(), logging.INFO)
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="SentinelMesh adaptive deception platform"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "serve", help="Run honeypot services and dashboard together"
    )
    subparsers.add_parser(
        "honeypot", help="Run only the deception services"
    )
    subparsers.add_parser(
        "dashboard", help="Run only the web dashboard"
    )

    train_parser = subparsers.add_parser(
        "train", help="Train the sequence predictor from JSON data"
    )
    train_parser.add_argument(
        "--dataset", required=True, help="Path to a JSON list of command sequences"
    )

    report_parser = subparsers.add_parser(
        "report", help="Print the latest profile and report inventory"
    )
    report_parser.add_argument("--limit", type=int, default=10)

    doctor_parser = subparsers.add_parser(
        "doctor", help="Validate deployment settings and local artifacts"
    )
    doctor_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Print the doctor report as JSON",
    )

    _add_cli_subcommands(parser)

    args = parser.parse_args()
    settings = _make_settings()

    if args.command == "serve":
        _, store, _, honeypot = build_runtime()
        _run_dashboard_thread(store, settings)
        asyncio.run(_run_honeypot(honeypot))
        return

    if args.command == "honeypot":
        _, _, _, honeypot = build_runtime()
        asyncio.run(_run_honeypot(honeypot))
        return

    if args.command == "dashboard":
        _, store, _, _ = build_runtime()
        _run_dashboard(store, settings)
        return

    if args.command == "train":
        _, _, deception_engine, _ = build_runtime()
        dataset_path = Path(args.dataset)
        sequences = _load_sequences(dataset_path)
        deception_engine.train(sequences)
        print(
            f"trained model with {len(sequences)} sequences -> "
            f"{settings.model_dir / 'sequence_model.json'}"
        )
        return

    if args.command == "report":
        _, store, _, _ = build_runtime()
        profiles = store.list_profiles(limit=args.limit)
        sessions = store.list_recent_sessions(limit=args.limit)
        print(
            json.dumps(
                {
                    "profiles": [profile.to_record() for profile in profiles],
                    "sessions": [session.to_record() for session in sessions],
                    "reports_dir": str(settings.reports_dir),
                },
                indent=2,
            )
        )
        return

    if args.command == "doctor":
        if args.as_json:
            print(report_as_json(settings))
        else:
            print_report(settings)
        return

    _run_cli_command(args, settings)



async def _run_honeypot(honeypot: HoneypotEngine) -> None:
    try:
        await honeypot.start()
        await honeypot.serve_forever()
    except Exception:
        logging.exception("SentinelMesh service start failed")
        raise
    finally:
        honeypot.shutdown_sync()

def _add_cli_subcommands(parser: argparse.ArgumentParser) -> None:
    from sentinelmesh.cli import add_subcommands

    settings = _make_settings()
    add_subcommands(parser, settings)


def _run_cli_command(args: argparse.Namespace, settings: Settings) -> None:
    from sentinelmesh.cli import run_command

    run_command(args, settings)


def _run_dashboard_thread(store: EventStore, settings: Settings) -> None:
    thread = threading.Thread(target=_run_dashboard, args=(store, settings), daemon=True)
    thread.start()


def _run_dashboard(store: EventStore, settings: Settings) -> None:
    import uvicorn

    from sentinelmesh.dashboard import create_app

    templates_dir = Path(__file__).resolve().parent / "templates"
    app = create_app(store, settings, templates_dir)
    uvicorn.run(
        app,
        host=settings.dashboard_host,
        port=settings.dashboard_port,
        log_level="warning" if _is_lab(settings) else "info",
    )


def _is_lab(settings: Settings) -> bool:
    return settings.environment_name.lower() in {"lab", "demo", "docker"}


def _load_sequences(dataset_path: Path) -> list[list[str]]:
    payload = json.loads(dataset_path.read_text(encoding="utf-8"))
    if all(isinstance(item, list) for item in payload):
        return [[str(token) for token in item] for item in payload]
    commands = [str(item) for item in payload]
    return extract_sequences(commands)
