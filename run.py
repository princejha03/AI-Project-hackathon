#!/usr/bin/env python3
"""One-command launcher for TrueSignal.

Run this file - `python run.py` - from anywhere, and it starts the web UI
(dashboard, both demo projects, findings/audit, analysis, ledger, activity,
settings) and opens it in your browser. No other setup required: it
installs Flask automatically the first time if it isn't already present.

The CLI demo (`truesignal analyze`, `truesignal ledger`, etc.) is a separate,
narrower entry point documented in README.md - this script always launches
the full web app.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _ensure_flask() -> None:
    try:
        import flask  # noqa: F401
    except ImportError:
        print("Flask isn't installed yet - installing it now (one-time)...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "flask"])


def _run_script(script_path: Path) -> None:
    subprocess.check_call([sys.executable, str(script_path)])


def run_full() -> None:
    print("=" * 60)
    print(" TrueSignal - full run: fixtures, tests, analyze, ledger")
    print("=" * 60)

    make_fixtures = ROOT / "scripts" / "make_fixtures.py"
    run_tests = ROOT / "scripts" / "run_tests.py"

    if make_fixtures.exists():
        _run_script(make_fixtures)
    else:
        print("Warning: scripts/make_fixtures.py not found; skipping fixtures step")

    if run_tests.exists():
        _run_script(run_tests)
    else:
        print("Warning: scripts/run_tests.py not found; skipping tests step")

    # analyze (mock mode, auto-approve)
    if (ROOT / ".truesignal").exists():
        try:
            subprocess.check_call(["rmdir", "/s", "/q", str(ROOT / ".truesignal")], shell=True)
        except Exception:
            pass

    subprocess.check_call([
        sys.executable,
        "-m",
        "truesignal.cli",
        "analyze",
        "--project",
        "webshop",
        "--yes",
    ])

    subprocess.check_call([sys.executable, "-m", "truesignal.cli", "ledger"])


def run_ui() -> None:
    _ensure_flask()

    print("=" * 60)
    print(" TrueSignal - starting the web UI")
    print(" http://127.0.0.1:5000 will open in your browser")
    print(" Press Ctrl+C in this window to stop the server")
    print("=" * 60)

    # Add project root to sys.path so `truesignal` imports work when running from elsewhere
    sys.path.insert(0, str(ROOT))

    from truesignal.webapp.server import main as run_server

    # server.main() opens the browser itself once it's actually listening
    run_server()


def main() -> None:
    if sys.version_info < (3, 10):
        sys.exit("TrueSignal requires Python 3.10 or newer.")

    parser = argparse.ArgumentParser(description="TrueSignal launcher")
    parser.add_argument(
        "mode",
        nargs="?",
        choices=("ui", "full", "both"),
        default="ui",
        help="Choose 'ui' to start the web UI, 'full' to run fixtures/tests/analyze/ledger, or 'both'.",
    )
    args = parser.parse_args()

    if args.mode in ("ui", "both"):
        # ensure flask only when running UI
        _ensure_flask()

    if args.mode == "full":
        run_full()
    elif args.mode == "ui":
        run_ui()
    else:  # both
        run_full()
        run_ui()


if __name__ == "__main__":
    main()
