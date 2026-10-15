"""
Beacon - Cybersecurity Network Traffic Analysis Platform

A professional, modular PCAP/PCAPNG network traffic analysis platform
built on TShark to transform raw network traffic into actionable security intelligence.
"""

__version__ = "0.1.0"
__author__ = "Beacon Development Team"

from beacon.core.engine import AnalysisEngine
from beacon.core.modes import AnalysisMode

__all__ = ["AnalysisEngine", "AnalysisMode", "__version__"]
