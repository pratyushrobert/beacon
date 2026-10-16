"""TShark interface layer for packet capture processing."""

import json
import subprocess
import shutil
import sys
from pathlib import Path
from typing import Optional, Iterator, Dict, Any, List
from dataclasses import dataclass
import logging

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

logger = logging.getLogger(__name__)
console = Console()


@dataclass
class TSharkInfo:
    """TShark installation information."""

    installed: bool
    version: Optional[str] = None
    path: Optional[str] = None
    error: Optional[str] = None


class TSharkInterface:
    """Interface for TShark command-line tool with built-in native PCAP/PCAPNG fallback."""

    using_native: bool = False

    def __init__(self, require_tshark: bool = False):
        """Initialize TShark interface and check installation."""
        self.tshark_info = self._check_tshark()
        self.using_native = not self.tshark_info.installed

        if self.using_native:
            if require_tshark:
                raise RuntimeError(
                    f"TShark not found: {self.tshark_info.error}\n"
                    "Please install Wireshark/TShark:\n"
                    "  Windows: https://www.wireshark.org/download.html\n"
                    "  Linux: sudo apt-get install tshark\n"
                    "  macOS: brew install wireshark"
                )
            self.tshark_info.version = "Beacon Built-in Native Engine"
            self.tshark_info.path = "builtin:pcap_native"
            logger.info("TShark executable not found. Operating with Beacon Native Engine for offline PCAP/PCAPNG decoding.")
        else:
            logger.info(f"TShark found: {self.tshark_info.version} at {self.tshark_info.path}")

    def _check_tshark(self) -> TSharkInfo:
        """Check if TShark is installed and get version info."""
        # Try common TShark paths on Linux and Windows
        common_paths = [
            shutil.which("tshark"),
            "/usr/bin/tshark",
            "/usr/sbin/tshark",
            "/usr/local/bin/tshark",
            "/opt/homebrew/bin/tshark",
            "/Applications/Wireshark.app/Contents/MacOS/tshark",
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            r"C:\Wireshark\tshark.exe",
        ]

        tshark_path = None
        for path in common_paths:
            if path and Path(path).exists():
                tshark_path = path
                break

        if not tshark_path:
            return TSharkInfo(
                installed=False,
                error="TShark executable not found in PATH or standard system locations",
            )

        try:
            result = subprocess.run(
                [tshark_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                version_line = result.stdout.split("\n")[0]
                return TSharkInfo(
                    installed=True,
                    version=version_line,
                    path=tshark_path,
                )
            else:
                return TSharkInfo(
                    installed=False,
                    error=f"TShark version check failed: {result.stderr}",
                )

        except subprocess.TimeoutExpired:
            return TSharkInfo(
                installed=False,
                error="TShark version check timed out",
            )
        except Exception as e:
            return TSharkInfo(
                installed=False,
                error=f"Error checking TShark: {str(e)}",
            )

    def _find_capinfos(self) -> Optional[str]:
        """Locate capinfos executable if available."""
        which_path = shutil.which("capinfos")
        if which_path:
            return which_path
        if self.tshark_info and self.tshark_info.path:
            tshark_dir = Path(self.tshark_info.path).parent
            candidate = tshark_dir / ("capinfos.exe" if sys.platform == "win32" else "capinfos")
            if candidate.exists():
                return str(candidate)
        for p in [
            "/usr/bin/capinfos",
            "/usr/sbin/capinfos",
            "/usr/local/bin/capinfos",
            "/opt/homebrew/bin/capinfos",
            "/Applications/Wireshark.app/Contents/MacOS/capinfos",
        ]:
            if Path(p).exists():
                return p
        return None

    def get_capture_info(self, pcap_path: Path) -> Dict[str, Any]:
        """Get basic information about a capture file."""
        if not pcap_path.exists():
            raise FileNotFoundError(f"Capture file not found: {pcap_path}")

        if self.using_native or not self.tshark_info.installed:
            try:
                from beacon.core.pcap_native import get_native_capture_info
                return get_native_capture_info(pcap_path)
            except Exception as e:
                logger.debug(f"Native capture info note: {e}")

        capinfos_bin = self._find_capinfos()
        if capinfos_bin:
            try:
                # Use capinfos for capture statistics
                result = subprocess.run(
                    [capinfos_bin, "-M", "-c", "-u", "-a", "-e", "-S", str(pcap_path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if result.returncode == 0:
                    info = {"file_path": str(pcap_path)}
                    for line in result.stdout.split("\n"):
                        if ":" in line:
                            key, value = line.split(":", 1)
                            info[key.strip()] = value.strip()
                    return info
                else:
                    logger.warning(f"capinfos failed: {result.stderr}")
            except Exception as e:
                logger.warning(f"capinfos execution error: {e}")

        try:
            from beacon.core.pcap_native import get_native_capture_info
            return get_native_capture_info(pcap_path)
        except Exception:
            pass

        # Fallback to basic file info if capinfos is unavailable or failed
        return {
            "file_path": str(pcap_path),
            "file_size": pcap_path.stat().st_size,
            "file_type": pcap_path.suffix,
        }

    def read_packets_json(
        self, pcap_path: Path, packet_limit: Optional[int] = None, display_filter: Optional[str] = None
    ) -> Iterator[Dict[str, Any]]:
        """
        Read packets from capture file as JSON stream using EK format.

        Uses TShark's EK (Elasticsearch) format for memory-efficient streaming,
        with seamless fallback to Beacon's native pure-Python PCAP decoder.

        Args:
            pcap_path: Path to PCAP/PCAPNG file
            packet_limit: Maximum number of packets to read (None = all)
            display_filter: Wireshark display filter (e.g., "tcp.port == 443")

        Yields:
            Dict containing packet data in EK JSON format
        """
        if not pcap_path.exists():
            raise FileNotFoundError(f"Capture file not found: {pcap_path}")

        if self.using_native or not self.tshark_info.installed or not self.tshark_info.path:
            from beacon.core.pcap_native import read_native_packets
            yield from read_native_packets(pcap_path, packet_limit=packet_limit)
            return

        # Use EK format for memory efficiency - outputs one JSON object per line
        cmd = [
            self.tshark_info.path,
            "-r", str(pcap_path),
            "-T", "ek",  # Elasticsearch JSON format (streaming)
        ]

        if packet_limit:
            cmd.extend(["-c", str(packet_limit)])

        if display_filter:
            cmd.extend(["-Y", display_filter])

        try:
            logger.debug(f"Running TShark command: {' '.join(cmd)}")

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered for streaming
            )

            # Stream packets line by line (memory efficient)
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue

                try:
                    packet = json.loads(line)
                    yield packet
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse packet line: {line[:100]}... Error: {e}")
                    continue

            # Wait for process to complete
            process.wait()

            if process.returncode != 0:
                stderr = process.stderr.read()
                logger.warning(f"TShark exited with code {process.returncode}: {stderr}. Falling back to native PCAP decoder.")
                from beacon.core.pcap_native import read_native_packets
                yield from read_native_packets(pcap_path, packet_limit=packet_limit)
                return

        except Exception as e:
            logger.warning(f"TShark execution note: {e}. Falling back to native PCAP decoder.")
            from beacon.core.pcap_native import read_native_packets
            yield from read_native_packets(pcap_path, packet_limit=packet_limit)

    def read_packets_ek(
        self, pcap_path: Path, packet_limit: Optional[int] = None
    ) -> Iterator[Dict[str, Any]]:
        """
        Read packets using EK format or native decoder.
        """
        return self.read_packets_json(pcap_path, packet_limit=packet_limit)

    def get_packet_count(self, pcap_path: Path) -> int:
        """Get total packet count quickly without parsing full capture."""
        if self.using_native or not self.tshark_info.installed:
            try:
                from beacon.core.pcap_native import get_native_packet_count
                return get_native_packet_count(pcap_path)
            except Exception as e:
                logger.debug(f"Native packet count check failed: {e}")

        # 1. Fast capinfos check
        capinfos_bin = self._find_capinfos()
        if capinfos_bin:
            try:
                capinfos_res = subprocess.run(
                    [capinfos_bin, "-c", "-M", str(pcap_path)],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                if capinfos_res.returncode == 0:
                    for line in capinfos_res.stdout.splitlines():
                        if "number of packets" in line.lower() or "packets:" in line.lower():
                            val = line.split(":")[-1].strip()
                            if val.isdigit():
                                return int(val)
            except Exception as e:
                logger.debug(f"capinfos packet count check failed: {e}")

        # 2. TShark IO statistics check
        if self.tshark_info.path:
            try:
                result = subprocess.run(
                    [self.tshark_info.path, "-r", str(pcap_path), "-q", "-z", "io,stat,0"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if result.returncode == 0:
                    # In io,stat,0 output, data row format is: | <interval> | <frames> | <bytes> |
                    for line in result.stdout.splitlines():
                        if "<>" in line and "|" in line:
                            parts = [p.strip() for p in line.split("|") if p.strip()]
                            if len(parts) >= 2 and parts[1].isdigit():
                                return int(parts[1])
            except Exception as e:
                logger.debug(f"TShark io,stat packet count check failed: {e}")

        # 3. Fallback to native packet counter
        try:
            from beacon.core.pcap_native import get_native_packet_count
            return get_native_packet_count(pcap_path)
        except Exception as e:
            logger.debug(f"Native fallback packet counting failed: {e}")

        return 0


# Singleton instance
_tshark_interface: Optional[TSharkInterface] = None


def get_tshark_interface() -> TSharkInterface:
    """Get or create singleton TShark interface."""
    global _tshark_interface
    if _tshark_interface is None:
        _tshark_interface = TSharkInterface()
    return _tshark_interface
