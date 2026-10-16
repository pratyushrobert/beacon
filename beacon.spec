# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
import sys

block_cipher = None

# Ensure web/dist exists
dist_dir = Path("web") / "dist"
datas = []
if dist_dir.is_dir() and (dist_dir / "index.html").is_file():
    datas.append((str(dist_dir), "web/dist"))

sample_pcap = Path("examples") / "sample.pcap"
if sample_pcap.is_file():
    datas.append((str(sample_pcap), "examples"))

hidden_imports = [
    "uvicorn",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "fastapi",
    "fastapi.staticfiles",
    "multipart",
    "python_multipart",
    "sqlite3",
    "pydantic",
    "pydantic_settings",
    "rich",
    "rich.box",
    "rich.panel",
    "rich.table",
    "rich.text",
    "rich.progress",
    "click",
    "typer",
    "beacon",
    "beacon.__main__",
    "beacon.analysis",
    "beacon.analysis.conversations",
    "beacon.analysis.hosts",
    "beacon.analysis.ioc_extractor",
    "beacon.analysis.packet_inspector",
    "beacon.analysis.timeline",
    "beacon.analysis.topology",
    "beacon.api",
    "beacon.api.server",
    "beacon.cli",
    "beacon.cli.main",
    "beacon.core",
    "beacon.core.engine",
    "beacon.core.modes",
    "beacon.core.packet_parser",
    "beacon.core.pcap_native",
    "beacon.core.tshark_interface",
    "beacon.detection",
    "beacon.detection.engine",
    "beacon.exports",
    "beacon.exports.reports",
    "beacon.launcher",
    "beacon.live",
    "beacon.live.buffer",
    "beacon.live.detection",
    "beacon.live.models",
    "beacon.live.pcap_writer",
    "beacon.live.retention",
    "beacon.live.service",
    "beacon.memory",
    "beacon.memory.baseline",
    "beacon.memory.detector",
    "beacon.memory.models",
    "beacon.memory.store",
    "beacon.models",
    "beacon.utils",
    "beacon.utils.formatters",
    "beacon.utils.paths",
]

a = Analysis(
    ["beacon_entry.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "scipy", "notebook", "IPython"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="Beacon",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

if sys.platform == "darwin":
    app = BUNDLE(
        exe,
        name="Beacon.app",
        icon=None,
        bundle_identifier="org.beacon.analyzer",
        info_plist={
            "NSHighResolutionCapable": "True",
            "LSMinimumSystemVersion": "12.0",
            "CFBundleShortVersionString": "0.1.0",
            "CFBundleName": "Beacon",
            "CFBundleDisplayName": "Beacon",
        },
    )
