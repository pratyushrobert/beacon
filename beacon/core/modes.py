"""Analysis mode definitions and configurations."""

from enum import Enum
from typing import Dict, List
from pydantic import BaseModel


class AnalysisMode(str, Enum):
    """Operating modes for Beacon analysis."""

    BLUE = "blue"  # Defensive / Blue Team
    RED = "red"  # Offensive / Penetration Testing
    WHITE = "white"  # Neutral / Exploration


class ModeConfig(BaseModel):
    """Configuration for each analysis mode."""

    name: str
    description: str
    focus: str
    detection_categories: List[str]
    color_theme: str
    redact_sensitive: bool = False


# Mode-specific configurations
MODE_CONFIGS: Dict[AnalysisMode, ModeConfig] = {
    AnalysisMode.BLUE: ModeConfig(
        name="Blue Mode",
        description="Defensive / Blue Team",
        focus="Anomaly and attack detection",
        detection_categories=[
            "port_scanning",
            "host_scanning",
            "syn_scanning",
            "udp_scanning",
            "connection_failures",
            "periodic_beaconing",
            "dns_anomalies",
            "unexpected_communication",
            "data_exfiltration",
            "traffic_spikes",
        ],
        color_theme="blue",
        redact_sensitive=False,
    ),
    AnalysisMode.RED: ModeConfig(
        name="Red Mode",
        description="Offensive / Penetration Testing",
        focus="Information exposure and vulnerability discovery",
        detection_categories=[
            "cleartext_credentials",
            "ntlm_hashes",
            "session_tokens",
            "api_keys",
            "cookies",
            "infrastructure_leakage",
            "server_banners",
            "version_disclosure",
        ],
        color_theme="red",
        redact_sensitive=True,  # Redact by default in Red mode
    ),
    AnalysisMode.WHITE: ModeConfig(
        name="White Mode",
        description="Neutral / Exploration",
        focus="Technical analysis and packet exploration",
        detection_categories=[
            "packet_statistics",
            "protocol_distribution",
            "conversation_mapping",
            "tcp_stats",
            "udp_stats",
            "timeline_analysis",
        ],
        color_theme="white",
        redact_sensitive=False,
    ),
}


def get_mode_config(mode: AnalysisMode) -> ModeConfig:
    """Get configuration for a specific analysis mode."""
    return MODE_CONFIGS[mode]
