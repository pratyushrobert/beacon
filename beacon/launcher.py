"""Production-ready cross-platform launcher for Beacon investigation platform."""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from beacon import __version__
from beacon.utils.paths import (
    find_frontend_dist,
    get_beacon_data_dir,
    get_beacon_lock_path,
    get_beacon_logs_dir,
)

logger = logging.getLogger("beacon.launcher")


class SingleInstanceLock:
    """
    Cross-platform single-instance file lock mechanism.
    Guarantees only one launcher process binds the primary instance at a time.
    """

    def __init__(self, lock_file: Optional[Path] = None):
        self.lock_path = lock_file or get_beacon_lock_path()
        self._file_handle: Optional[Any] = None
        self.acquired = False

    def acquire(self, host: str, port: int) -> bool:
        """Attempt to acquire non-blocking lock. Returns True on success, False if already held."""
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._file_handle = open(self.lock_path, "a+")
            self._file_handle.seek(0)

            if sys.platform == "win32":
                import msvcrt
                try:
                    # Lock first byte non-blocking
                    msvcrt.locking(self._file_handle.fileno(), msvcrt.LK_NBLCK, 1)
                    self.acquired = True
                except (IOError, OSError):
                    self.acquired = False
            else:
                import fcntl
                try:
                    fcntl.flock(self._file_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.acquired = True
                except (IOError, OSError):
                    self.acquired = False

            if self.acquired:
                # Write current process and port metadata
                self._file_handle.seek(0)
                self._file_handle.truncate(0)
                payload = {
                    "pid": os.getpid(),
                    "host": host,
                    "port": port,
                    "version": __version__,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                }
                self._file_handle.write(json.dumps(payload))
                self._file_handle.flush()
                return True
            else:
                self._file_handle.close()
                self._file_handle = None
                return False

        except Exception as e:
            logger.debug(f"Lock acquire note: {e}")
            if self._file_handle:
                try:
                    self._file_handle.close()
                except Exception:
                    pass
                self._file_handle = None
            return False

    def read_existing_metadata(self) -> Optional[Dict[str, Any]]:
        """Read metadata from existing lock file if present."""
        if self._file_handle:
            try:
                pos = self._file_handle.tell()
                self._file_handle.seek(0)
                content = self._file_handle.read().strip()
                self._file_handle.seek(pos)
                if content:
                    return json.loads(content)
            except Exception:
                pass

        if not self.lock_path.exists():
            return None
        try:
            content = self.lock_path.read_text(encoding="utf-8").strip()
            if content:
                return json.loads(content)
        except Exception:
            pass
        return None

    def release(self) -> None:
        """Release lock and remove lock file."""
        if not self.acquired or not self._file_handle:
            return
        try:
            if sys.platform == "win32":
                import msvcrt
                try:
                    self._file_handle.seek(0)
                    msvcrt.locking(self._file_handle.fileno(), msvcrt.LK_UNLCK, 1)
                except Exception:
                    pass
            else:
                import fcntl
                try:
                    fcntl.flock(self._file_handle.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
            self._file_handle.close()
        except Exception:
            pass
        finally:
            self._file_handle = None
            self.acquired = False
            try:
                if self.lock_path.exists():
                    self.lock_path.unlink()
            except Exception:
                pass


def is_pid_running(pid: int) -> bool:
    """Check if process with given PID is currently active."""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
        except Exception:
            pass
        return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False


def is_port_in_use(host: str, port: int) -> bool:
    """Test if a local TCP port is already open/in-use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


def check_existing_beacon(host: str, port: int, timeout: float = 0.8) -> Optional[Dict[str, Any]]:
    """
    Check if a running server at http://{host}:{port}/api/health is an existing Beacon instance.
    """
    url = f"http://{host}:{port}/api/health"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Beacon-Launcher-Probe"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "healthy" and "version" in data:
                    return data
    except Exception:
        pass
    return None


def find_available_port(host: str, start_port: int, max_attempts: int = 50) -> int:
    """
    Find the first available port starting from start_port up to start_port + max_attempts.
    """
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"Could not find an available port for {host} between {start_port} and {start_port + max_attempts}")


def wait_for_backend_ready(host: str, port: int, timeout: float = 25.0) -> bool:
    """
    Poll http://{host}:{port}/api/health until backend responds 200 OK or timeout expires.
    """
    url = f"http://{host}:{port}/api/health"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Beacon-Launcher-Readiness"})
            with urllib.request.urlopen(req, timeout=0.4) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.15)
    return False


def setup_launcher_logging() -> Path:
    """Configure diagnostic file logging while avoiding secret leakage."""
    logs_dir = get_beacon_logs_dir()
    log_file = logs_dir / "beacon-launcher.log"

    # Rotating or truncating log if too large (> 5MB)
    if log_file.exists() and log_file.stat().st_size > 5 * 1024 * 1024:
        try:
            old_log = logs_dir / "beacon-launcher.old.log"
            if old_log.exists():
                old_log.unlink()
            log_file.rename(old_log)
        except Exception:
            pass

    file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    # Avoid duplicate handlers if setup is called multiple times
    if not any(isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", "") == str(log_file) for h in root_logger.handlers):
        root_logger.addHandler(file_handler)

    return log_file


def launch_beacon(
    host: Optional[str] = None,
    port: Optional[int] = None,
    open_browser: bool = True,
    pin: Optional[str] = None,
    low_resource: bool = False,
    headless: bool = False,
) -> int:
    """
    Main entry point for one-click production launcher.
    Starts backend and SPA on single origin, verifies readiness, and opens dashboard.
    """
    log_path = setup_launcher_logging()
    logger.info(f"=== Beacon Launcher v{__version__} starting (PID: {os.getpid()}) ===")

    # 1. Resolve host and port preferences
    effective_host = host or os.environ.get("BEACON_HOST", "127.0.0.1")
    default_port = int(port or os.environ.get("BEACON_PORT", "8000"))

    if low_resource or os.environ.get("BEACON_LOW_RESOURCE") in ("1", "true", "True"):
        os.environ["BEACON_LOW_RESOURCE"] = "1"
        os.environ["BEACON_BUFFER_CAPACITY"] = "500"
        logger.info("Low-resource hardware profile activated.")

    if pin:
        os.environ["BEACON_PIN"] = pin.strip()
        logger.info("Access PIN configured for remote authorization.")

    # 2. Check for duplicate instances
    lock = SingleInstanceLock()
    if is_port_in_use(effective_host, default_port):
        existing_info = check_existing_beacon(effective_host, default_port)
        if existing_info:
            target_url = f"http://{effective_host}:{default_port}/"
            logger.info(f"Existing Beacon instance detected on {target_url}. Directing browser there.")
            print(f"\n[Beacon] Instance already running on {target_url}. Opening dashboard...")
            if open_browser and not headless:
                webbrowser.open(target_url)
            return 0
        else:
            logger.warning(f"Port {default_port} is in use by another application.")
            try:
                selected_port = find_available_port(effective_host, default_port + 1)
                logger.info(f"Selected alternate port {selected_port}.")
                print(f"[Beacon] Port {default_port} in use. Using alternate port: {selected_port}")
            except Exception as e:
                logger.error(f"Failed to find available port: {e}")
                print(f"[Beacon ERROR] {e}")
                return 1
    else:
        selected_port = default_port

    if not lock.acquire(effective_host, selected_port):
        # Lock held by another process; check if that process is active
        meta = lock.read_existing_metadata()
        if meta and "port" in meta:
            running_port = meta["port"]
            running_host = meta.get("host", effective_host)
            existing_info = check_existing_beacon(running_host, running_port)
            if existing_info:
                target_url = f"http://{running_host}:{running_port}/"
                logger.info(f"Another Beacon instance is active on {target_url}. Opening browser.")
                print(f"\n[Beacon] Active instance running on {target_url}.")
                if open_browser and not headless:
                    webbrowser.open(target_url)
                return 0

            # Stale lock cleanup if previous process died
            old_pid = meta.get("pid", 0)
            if not is_pid_running(old_pid):
                logger.info(f"Clearing stale lock from deceased process PID {old_pid}.")
                try:
                    if lock.lock_path.exists():
                        lock.lock_path.unlink()
                    lock.acquire(effective_host, selected_port)
                except Exception as e:
                    logger.debug(f"Stale lock recovery note: {e}")

    # 4. Inspect frontend assets
    frontend_dir = find_frontend_dist()
    if not frontend_dir or not (frontend_dir / "index.html").exists():
        logger.warning(
            "Frontend production assets (web/dist/index.html) not found. "
            "Backend will serve fallback informational page at root."
        )
        print("[Beacon WARNING] Pre-built web assets not found. Run 'npm run build' inside web/ for full GUI.")

    # 5. Start Uvicorn production server in-process
    import uvicorn
    from beacon.api.server import app

    config = uvicorn.Config(
        app=app,
        host=effective_host,
        port=selected_port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)

    server_thread = threading.Thread(
        target=server.run,
        name="BeaconServerThread",
        daemon=True,
    )
    server_thread.start()

    # 6. Wait for backend readiness
    dashboard_url = f"http://{effective_host}:{selected_port}/"
    logger.info(f"Waiting for backend readiness at {dashboard_url}api/health...")
    ready = wait_for_backend_ready(effective_host, selected_port, timeout=20.0)

    if not ready:
        logger.error(f"Backend failed to respond at {dashboard_url} within 20 seconds.")
        print(f"[Beacon ERROR] Backend failed to start. Review logs at: {log_path}")
        server.should_exit = True
        lock.release()
        return 1

    logger.info(f"Backend is ready. Dashboard accessible at {dashboard_url}")
    print("\n" + "=" * 60)
    print(f"  BEACON CYBERSECURITY INVESTIGATION PLATFORM")
    print(f"  Version:   {__version__}")
    print(f"  Dashboard: {dashboard_url}")
    print(f"  Logs:      {log_path}")
    print("=" * 60)
    print("  Press Ctrl+C to stop Beacon gracefully.\n")

    # 7. Open browser automatically
    if open_browser and not headless:
        try:
            logger.info(f"Launching default web browser to: {dashboard_url}")
            webbrowser.open(dashboard_url)
        except Exception as e:
            logger.warning(f"Could not open browser automatically: {e}")
            print(f"[Beacon] Please open your browser and navigate to: {dashboard_url}")

    # 8. Setup graceful termination signal handlers
    stop_event = threading.Event()

    def handle_shutdown(signum=None, frame=None):
        logger.info(f"Shutdown requested via signal {signum}. Stopping services...")
        stop_event.set()
        server.should_exit = True
        # Terminate any active live packet capture to prevent orphaned dumpcap/tshark
        try:
            from beacon.live.service import get_live_service
            live_service = get_live_service()
            if live_service.is_running():
                logger.info("Stopping active background packet capture...")
                live_service.stop_capture()
        except Exception as e:
            logger.debug(f"Live capture cleanup note: {e}")

    # Register POSIX & Windows signal handlers
    try:
        signal.signal(signal.SIGINT, handle_shutdown)
        signal.signal(signal.SIGTERM, handle_shutdown)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, handle_shutdown)
    except Exception as e:
        logger.debug(f"Signal registration note: {e}")

    # 9. Main monitor loop
    try:
        while not stop_event.is_set() and not server.should_exit:
            time.sleep(0.5)
    except KeyboardInterrupt:
        handle_shutdown()
    finally:
        logger.info("Cleaning up launcher state...")
        server.should_exit = True
        lock.release()
        logger.info("Beacon shutdown complete.")
        print("\n[Beacon] Process terminated cleanly.")

    return 0


def main() -> None:
    """Direct launcher CLI execution."""
    sys.exit(launch_beacon())


if __name__ == "__main__":
    main()
