"""Tests for Linux compatibility, CLI invocations, and runtime hardening."""

from __future__ import annotations

import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from beacon.cli import app
from beacon.core.engine import AnalysisEngine
from beacon.core.tshark_interface import TSharkInfo, TSharkInterface
from beacon.live.models import LiveCaptureStatus, RollingPacket
from beacon.live.service import LiveCaptureService, get_current_process_memory_mb


runner = CliRunner()


# =========================================================================
# 1. CLI Invocation & Flag Stability Tests
# =========================================================================

@pytest.mark.parametrize(
    "subcommand_args",
    [
        ["--help"],
        ["analyze", "--help"],
        ["hosts", "--help"],
        ["conversations", "--help"],
        ["findings", "--help"],
        ["protocols", "--help"],
        ["timeline", "--help"],
        ["ioc", "--help"],
        ["packet", "--help"],
        ["report", "--help"],
        ["info", "--help"],
        ["version-info", "--help"],
        ["serve", "--help"],
        ["launch", "--help"],
        ["memory", "--help"],
        ["memory", "status", "--help"],
        ["memory", "briefing", "--help"],
        ["memory", "changes", "--help"],
        ["memory", "recurring", "--help"],
        ["memory", "ack", "--help"],
        ["live", "--help"],
        ["live", "interfaces", "--help"],
        ["live", "status", "--help"],
        ["live", "start", "--help"],
        ["live", "incidents", "--help"],
        ["live", "incident", "--help"],
        ["live", "pin", "--help"],
        ["live", "note", "--help"],
        ["live", "export", "--help"],
    ],
)
def test_cli_subcommands_help(subcommand_args: list[str]) -> None:
    """Ensure every command and subcommand can be invoked without Typer/Click crashes."""
    result = runner.invoke(app, subcommand_args)
    assert result.exit_code == 0, f"Failed for {subcommand_args}: {result.output}"
    assert "Usage:" in result.output or "Options" in result.output or "Commands" in result.output


def test_cli_version_info_command() -> None:
    """Test version-info command execution."""
    result = runner.invoke(app, ["version-info"])
    assert result.exit_code == 0
    assert "Beacon" in result.output


def test_cli_analyze_argument_handling(tmp_path: Path) -> None:
    """Test analyze with mode and options without Click/Typer Option crashes."""
    pcap = tmp_path / "test.pcap"
    pcap.write_bytes(b"dummy")

    with patch.object(AnalysisEngine, "analyze") as mock_analyze:
        mock_analyze.side_effect = RuntimeError("Mocked analyze stopped")
        result = runner.invoke(
            app,
            ["analyze", str(pcap), "--mode", "blue", "--limit", "10"],
        )
        assert mock_analyze.called or "Mocked analyze stopped" in result.output or result.exit_code != 0
        assert "TypeError: TyperOption.__init__()" not in (result.output or "")


def test_cli_memory_flags() -> None:
    """Verify boolean flags and secondary flag syntax do not crash Option parsing."""
    result = runner.invoke(
        app,
        ["memory", "changes", "--days", "7"],
    )
    assert "TypeError: TyperOption.__init__()" not in (result.output or "")
    assert "TypeError: __init__()" not in (result.output or "")


# =========================================================================
# 2. Cross-Platform Memory Monitoring Tests
# =========================================================================

def test_get_current_process_memory_mb_real() -> None:
    """Test that the live memory function returns a reasonable float on current platform."""
    mem = get_current_process_memory_mb()
    assert isinstance(mem, float)
    assert mem > 0.0


def test_get_current_process_memory_mb_linux_procfs() -> None:
    """Test Linux /proc/self/statm parsing logic."""
    statm_content = "25000 12000 3000 100 0 500 0\n"

    from unittest.mock import mock_open
    with patch("sys.platform", "linux"):
        with patch("builtins.open", mock_open(read_data=statm_content)):
            with patch("os.sysconf", return_value=4096, create=True):
                # 12000 pages * 4096 bytes / (1024 * 1024) = 46.875 MB
                mem = get_current_process_memory_mb()
                assert mem == pytest.approx(46.875, rel=0.01)


def test_get_current_process_memory_mb_fallback() -> None:
    """Test fallback when procfs and win32 are unavailable."""
    with patch("sys.platform", "linux"):
        with patch("pathlib.Path.exists", return_value=False):
            mock_resource = MagicMock()
            mock_resource.RUSAGE_SELF = 0
            # 100000 KB on Linux = ~97.65 MB
            mock_resource.getrusage.return_value.ru_maxrss = 100000
            with patch.dict("sys.modules", {"resource": mock_resource}):
                mem = get_current_process_memory_mb()
                assert mem > 0.0


# =========================================================================
# 3. Data Integrity & Packet Reconstruction Tests
# =========================================================================

def test_rolling_packet_is_reconstructed_property() -> None:
    """Ensure synthesized frames are explicitly marked as reconstructed."""
    # Verbatim packet with raw_hex
    verbatim_pkt = RollingPacket(
        number=1,
        timestamp=1694942400.0,
        length=128,
        raw_hex="00112233445566778899aabbccddeeff",
    )
    assert verbatim_pkt.is_reconstructed is False
    assert verbatim_pkt.to_dict()["is_reconstructed"] is False

    # Synthesized packet without raw_hex
    synth_pkt = RollingPacket(
        number=2,
        timestamp=1694942400.0,
        length=64,
        raw_hex="",
    )
    assert synth_pkt.is_reconstructed is True
    assert synth_pkt.to_dict()["is_reconstructed"] is True


# =========================================================================
# 4. TShark Interface & Capinfos Fallback Tests
# =========================================================================

def test_tshark_interface_find_capinfos(tmp_path: Path) -> None:
    """Test capinfos discovery beside tshark or in PATH."""
    interface = object.__new__(TSharkInterface)
    interface.tshark_info = TSharkInfo(
        installed=True,
        version="TShark 4.0",
        path=str(tmp_path / "tshark"),
    )

    with patch("shutil.which", return_value="/usr/bin/capinfos"):
        assert interface._find_capinfos() == "/usr/bin/capinfos"

    with patch("shutil.which", return_value=None):
        with patch("pathlib.Path.exists", return_value=False):
            assert interface._find_capinfos() is None


def test_tshark_get_packet_count_capinfos_fallback(tmp_path: Path) -> None:
    """Test get_packet_count falls back gracefully when capinfos is missing or errors."""
    interface = object.__new__(TSharkInterface)
    interface.tshark_info = TSharkInfo(
        installed=True,
        version="TShark 4.0",
        path="tshark",
    )

    pcap_path = tmp_path / "test.pcap"
    pcap_path.write_bytes(b"dummy")

    with patch.object(interface, "_find_capinfos", return_value=None):
        # capinfos is None; should invoke tshark -q -z io,stat,0
        io_stat_output = "=======================\n| <> | 42 | 1024 |\n======================="
        mock_result = MagicMock(returncode=0, stdout=io_stat_output)
        with patch("subprocess.run", return_value=mock_result) as mock_subproc:
            count = interface.get_packet_count(pcap_path)
            assert count == 42
            assert mock_subproc.called


def test_tshark_get_capture_info_capinfos_fallback(tmp_path: Path) -> None:
    """Test get_capture_info returns basic metadata if capinfos is unavailable."""
    interface = object.__new__(TSharkInterface)
    interface.tshark_info = TSharkInfo(
        installed=True,
        version="TShark 4.0",
        path="tshark",
    )

    pcap_path = tmp_path / "test.pcap"
    pcap_path.write_bytes(b"abc" * 10)

    with patch.object(interface, "_find_capinfos", return_value=None):
        info = interface.get_capture_info(pcap_path)
        assert info["file_path"] == str(pcap_path)
        assert info["file_size"] == 30
        assert info["file_type"] == ".pcap"


# =========================================================================
# 5. Linux Process Group & Capture Permissions Tests
# =========================================================================

def test_stop_capture_process_group_termination() -> None:
    """Test that stop_capture sends SIGTERM to the process group on POSIX systems."""
    service = LiveCaptureService()
    service.status = LiveCaptureStatus.CAPTURING

    mock_proc = MagicMock()
    mock_proc.pid = 12345
    mock_proc.poll.side_effect = [None, 0]  # First alive, then exited after SIGTERM
    service._process = mock_proc

    with patch("sys.platform", "linux"):
        with patch("os.getpgid", return_value=12345, create=True) as mock_getpgid:
            with patch("os.killpg", create=True) as mock_killpg:
                service.stop_capture()
                mock_getpgid.assert_called_once_with(12345)
                mock_killpg.assert_called_with(12345, signal.SIGTERM)
                assert service.status == LiveCaptureStatus.STOPPED


def test_capture_worker_permission_reporting() -> None:
    """Verify that stderr permission errors result in actionable Wireshark instructions."""
    service = LiveCaptureService()
    service.selected_interface = "eth0"

    permission_stderr = "dumpcap: The capture session could not be initiated: Permission denied"
    mock_proc = MagicMock()
    mock_proc.stdout = []
    mock_proc.poll.return_value = 1
    mock_proc.returncode = 1
    mock_proc.stderr.read.return_value = permission_stderr

    mock_tshark = MagicMock()
    mock_tshark.tshark_info.path = "tshark"
    with patch("beacon.live.service.get_tshark_interface", return_value=mock_tshark):
        with patch("subprocess.Popen", return_value=mock_proc):
            service._capture_worker()
            assert "wireshark" in service.error_message.lower()
            assert "dpkg-reconfigure wireshark-common" in service.error_message
