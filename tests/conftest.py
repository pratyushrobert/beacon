"""Test configuration."""

import pytest


@pytest.fixture
def sample_pcap_path(tmp_path):
    """Create a temporary path for test PCAP files."""
    return tmp_path / "test_capture.pcap"
