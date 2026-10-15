"""TShark interface layer for packet capture processing."""

import json
import subprocess
import shutil
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
    """Interface for TShark command-line tool."""

    def __init__(self):
        """Initialize TShark interface and check installation."""
        self.tshark_info = self._check_tshark()

        if not self.tshark_info.installed:
            raise RuntimeError(
                f"TShark not found: {self.tshark_info.error}\n"
                "Please install Wireshark/TShark:\n"
                "  Windows: https://www.wireshark.org/download.html\n"
                "  Linux: sudo apt-get install tshark\n"
                "  macOS: brew install wireshark"
            )

        logger.info(f"TShark found: {self.tshark_info.version} at {self.tshark_info.path}")

    def _check_tshark(self) -> TSharkInfo:
        """Check if TShark is installed and get version info."""
        # Try common TShark paths on Windows
        common_paths = [
            shutil.which("tshark"),
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
                error="TShark executable not found in PATH",
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

    def get_capture_info(self, pcap_path: Path) -> Dict[str, Any]:
        """Get basic information about a capture file."""
        if not pcap_path.exists():
            raise FileNotFoundError(f"Capture file not found: {pcap_path}")

        try:
            # Use capinfos for capture statistics
            result = subprocess.run(
                ["capinfos", "-M", "-c", "-u", "-a", "-e", "-S", str(pcap_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                logger.warning(f"capinfos failed: {result.stderr}")
                # Fallback to basic file info
                return {
                    "file_path": str(pcap_path),
                    "file_size": pcap_path.stat().st_size,
                    "file_type": pcap_path.suffix,
                }

            # Parse capinfos output
            info = {"file_path": str(pcap_path)}
            for line in result.stdout.split("\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    info[key.strip()] = value.strip()

            return info

        except Exception as e:
            logger.error(f"Error getting capture info: {e}")
            return {
                "file_path": str(pcap_path),
                "error": str(e),
            }

    def read_packets_json(
        self, pcap_path: Path, packet_limit: Optional[int] = None, display_filter: Optional[str] = None
    ) -> Iterator[Dict[str, Any]]:
        """
        Read packets from capture file as JSON stream using EK format.

        Uses TShark's EK (Elasticsearch) format for memory-efficient streaming.
        For large captures, this is preferred over the JSON array format.

        Args:
            pcap_path: Path to PCAP/PCAPNG file
            packet_limit: Maximum number of packets to read (None = all)
            display_filter: Wireshark display filter (e.g., "tcp.port == 443")

        Yields:
            Dict containing packet data in EK JSON format
        """
        if not pcap_path.exists():
            raise FileNotFoundError(f"Capture file not found: {pcap_path}")

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
                logger.error(f"TShark error: {stderr}")
                raise RuntimeError(f"TShark failed with code {process.returncode}: {stderr}")

            # Log any warnings
            stderr = process.stderr.read()
            if stderr:
                logger.debug(f"TShark warnings: {stderr}")

        except FileNotFoundError:
            raise RuntimeError(f"TShark executable not found at {self.tshark_info.path}")
        except Exception as e:
            logger.error(f"Error reading packets: {e}")
            raise

    def read_packets_ek(
        self, pcap_path: Path, packet_limit: Optional[int] = None
    ) -> Iterator[Dict[str, Any]]:
        """
        Read packets using TShark's EK (Elasticsearch) format.

        EK format outputs one JSON object per line, which is more memory-efficient
        for large captures than the standard JSON array format.

        Args:
            pcap_path: Path to PCAP/PCAPNG file
            packet_limit: Maximum number of packets to read

        Yields:
            Dict containing packet data
        """
        if not pcap_path.exists():
            raise FileNotFoundError(f"Capture file not found: {pcap_path}")

        cmd = [
            self.tshark_info.path,
            "-r", str(pcap_path),
            "-T", "ek",  # Elasticsearch JSON format (one object per line)
        ]

        if packet_limit:
            cmd.extend(["-c", str(packet_limit)])

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
            )

            # Read line by line
            for line in process.stdout:
                line = line.strip()
                if line:
                    try:
                        packet = json.loads(line)
                        yield packet
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse packet line: {line[:100]}...")
                        continue

            process.wait()

            if process.returncode != 0:
                stderr = process.stderr.read()
                logger.error(f"TShark error: {stderr}")
                raise RuntimeError(f"TShark failed: {stderr}")

        except Exception as e:
            logger.error(f"Error reading packets with EK format: {e}")
            raise

    def get_packet_count(self, pcap_path: Path) -> int:
        """Get total packet count quickly without parsing full capture."""
        try:
            # 1. Fast capinfos check
            capinfos_res = subprocess.run(
                ["capinfos", "-c", "-M", str(pcap_path)],
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

            # 2. TShark IO statistics check
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

            # 3. Fallback: count lines of packet numbers
            result = subprocess.run(
                [self.tshark_info.path, "-r", str(pcap_path), "-T", "fields", "-e", "frame.number"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                lines = [l for l in result.stdout.splitlines() if l.strip()]
                return len(lines)

            return 0

        except Exception as e:
            logger.error(f"Error getting packet count: {e}")
            return 0


# Singleton instance
_tshark_interface: Optional[TSharkInterface] = None


def get_tshark_interface() -> TSharkInterface:
    """Get or create singleton TShark interface."""
    global _tshark_interface
    if _tshark_interface is None:
        _tshark_interface = TSharkInterface()
    return _tshark_interface
