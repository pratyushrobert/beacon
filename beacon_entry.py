"""
Beacon Application Entry Point.
Dual-mode executable:
- When launched without arguments (or double-clicked from file manager / desktop), starts the backend and opens the dashboard in the browser.
- When launched with arguments (e.g. analyze, live, memory, serve, --help), operates as the standalone CLI tool.
"""

from __future__ import annotations

import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _log_startup_error(message: str, exc: Optional[BaseException] = None) -> Path:
    """Persistently record startup exceptions in ~/.beacon/logs."""
    env_dir = os.environ.get("BEACON_DATA_DIR")
    base_dir = Path(env_dir) if env_dir else Path.home() / ".beacon"
    logs_dir = base_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = logs_dir / "beacon-startup.log"

    tb_text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)) if exc else ""
    stamp = datetime.now(timezone.utc).isoformat()
    entry = (
        f"\n{'='*70}\n"
        f"BEACON STARTUP FAILURE at {stamp}\n"
        f"PID: {os.getpid()} | Executable: {sys.executable}\n"
        f"Arguments: {sys.argv}\n"
        f"Message: {message}\n"
    )
    if tb_text:
        entry += f"Traceback:\n{tb_text}\n"
    entry += f"{'='*70}\n"

    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception:
        pass

    # Also append to beacon-launcher.log if possible
    launcher_log = logs_dir / "beacon-launcher.log"
    try:
        with open(launcher_log, "a", encoding="utf-8") as f:
            f.write(f"\n[FATAL STARTUP ERROR] {message}\n{tb_text}\n")
    except Exception:
        pass

    return log_file


def _report_fatal_error(message: str, exc: Optional[BaseException] = None) -> None:
    """Print visible error and display native alert on Windows when double-clicked."""
    log_file = _log_startup_error(message, exc)

    print("\n" + "!" * 70, file=sys.stderr)
    print("  BEACON STARTUP ERROR", file=sys.stderr)
    print("!" * 70, file=sys.stderr)
    print(f"  {message}", file=sys.stderr)
    if exc:
        print(f"\n  Details: {exc}", file=sys.stderr)
    print(f"\n  A detailed diagnostic log was saved to:\n  {log_file}", file=sys.stderr)
    print("!" * 70 + "\n", file=sys.stderr)

    # If launched as GUI (double-clicked, no CLI args) on Windows, display a native error dialog
    if sys.platform == "win32" and len(sys.argv) <= 1:
        try:
            import ctypes
            dialog_body = (
                f"Beacon failed to start:\n\n{message}\n\n"
                f"Review diagnostic logs at:\n{log_file}"
            )
            ctypes.windll.user32.MessageBoxW(0, dialog_body, "Beacon - Startup Error", 0x10)
        except Exception:
            pass
        try:
            input("Press Enter to exit...")
        except Exception:
            pass


def main() -> None:
    try:
        if len(sys.argv) == 1:
            from beacon.launcher import launch_beacon
            exit_code = launch_beacon()
            if exit_code != 0:
                _report_fatal_error(f"Beacon launcher exited with failure code {exit_code}")
            sys.exit(exit_code)
        else:
            from beacon.cli.main import app
            app()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        sys.exit(0)
    except BaseException as exc:
        _report_fatal_error(str(exc), exc=exc)
        sys.exit(1)


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    main()
