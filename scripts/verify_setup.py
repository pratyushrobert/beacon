#!/usr/bin/env python3
"""Quick verification script for Beacon core functionality."""

import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_imports():
    """Test that all core modules can be imported."""
    print("Testing imports...")

    try:
        from beacon import __version__, AnalysisEngine, AnalysisMode
        print(f"✓ Beacon version {__version__}")

        from beacon.core.tshark_interface import get_tshark_interface
        print("✓ TShark interface")

        from beacon.core.packet_parser import PacketParser
        print("✓ Packet parser")

        from beacon.detection.engine import DetectionEngine
        print("✓ Detection engine")

        from beacon.models import Finding, Severity, Confidence
        print("✓ Models")

        from beacon.analysis.hosts import HostAnalyzer
        from beacon.analysis.conversations import ConversationAnalyzer
        from beacon.analysis.timeline import TimelineBuilder
        from beacon.analysis.ioc_extractor import IOCExtractor
        print("✓ Analysis modules")

        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False


def test_tshark():
    """Check if TShark is available."""
    print("\nChecking TShark...")

    try:
        from beacon.core.tshark_interface import get_tshark_interface
        tshark = get_tshark_interface()
        print(f"✓ TShark found: {tshark.tshark_info.version}")
        return True
    except Exception as e:
        print(f"✗ TShark not available: {e}")
        return False


def test_detection_engine():
    """Test detection engine initialization."""
    print("\nTesting detection engine...")

    try:
        from beacon.detection.engine import DetectionEngine

        # Test Blue mode
        blue_engine = DetectionEngine(mode="blue")
        print("✓ Blue mode detection engine initialized")

        # Test Red mode
        red_engine = DetectionEngine(mode="red")
        print("✓ Red mode detection engine initialized")

        return True
    except Exception as e:
        print(f"✗ Detection engine failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("Beacon Verification Script")
    print("=" * 60)

    results = []

    results.append(("Imports", test_imports()))
    results.append(("TShark", test_tshark()))
    results.append(("Detection Engine", test_detection_engine()))

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)

    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {name}")

    all_passed = all(result[1] for result in results)

    if all_passed:
        print("\n✓ All tests passed!")
        print("\nNext steps:")
        print("  1. Get a PCAP file for testing")
        print("  2. Run: python -m beacon analyze <file.pcap> --mode blue")
        print("  3. Run: python -m beacon findings <file.pcap> --mode blue")
        return 0
    else:
        print("\n✗ Some tests failed. Please fix the issues above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
