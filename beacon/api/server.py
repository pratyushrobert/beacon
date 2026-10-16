"""REST API server for Beacon cybersecurity investigation platform."""

from __future__ import annotations

import asyncio
import json
import logging
import hmac
import os
import secrets
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    Query,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from beacon.analysis.conversations import ConversationAnalyzer
from beacon.analysis.hosts import HostAnalyzer
from beacon.analysis.ioc_extractor import IOCExtractor
from beacon.analysis.timeline import TimelineBuilder
from beacon.core.engine import AnalysisEngine
from beacon.core.modes import AnalysisMode
from beacon.exports.reports import ReportGenerator
from beacon.live import LiveCaptureStatus, get_live_service

logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(title="Beacon API", version="0.1.0", description="Cybersecurity Network Traffic Investigation Platform")

# Enable CORS for local network and web clients (supports ASUS laptop, smartphone, and dev servers)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_configured_pin() -> Optional[str]:
    pin = os.environ.get("BEACON_PIN", "").strip()
    return pin if pin else None


class PinRateLimiter:
    """Sliding-window IP rate limiter to protect PIN verification from brute-force attacks."""

    def __init__(self, max_attempts: int = 5, window_seconds: float = 60.0, lockout_seconds: float = 60.0):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._attempts: Dict[str, List[float]] = {}
        self._lockouts: Dict[str, float] = {}

    def is_locked(self, client_ip: str) -> Tuple[bool, float]:
        """Check if client IP is locked out. Returns (is_locked, remaining_seconds)."""
        now = time.time()
        lockout_until = self._lockouts.get(client_ip, 0.0)
        if now < lockout_until:
            return True, max(1.0, round(lockout_until - now, 1))
        if client_ip in self._lockouts:
            del self._lockouts[client_ip]
        return False, 0.0

    def record_attempt(self, client_ip: str, success: bool) -> None:
        """Record an attempt. Clears on success; increments lockout window on repeated failures."""
        now = time.time()
        if success:
            self._attempts.pop(client_ip, None)
            self._lockouts.pop(client_ip, None)
            return

        attempts = self._attempts.get(client_ip, [])
        attempts = [t for t in attempts if now - t <= self.window_seconds]
        attempts.append(now)
        self._attempts[client_ip] = attempts

        if len(attempts) >= self.max_attempts:
            self._lockouts[client_ip] = now + self.lockout_seconds

    def reset(self) -> None:
        """Reset rate limiter state (used in testing)."""
        self._attempts.clear()
        self._lockouts.clear()


pin_rate_limiter = PinRateLimiter()

# Ephemeral WebSocket tickets store: ticket -> expires_at
_ws_tickets: Dict[str, float] = {}


def create_ws_ticket(lifetime_seconds: float = 30.0) -> str:
    """Generate a single-use cryptographically secure ticket for WebSocket connection."""
    now = time.time()
    # Expire old tickets
    expired = [t for t, exp in _ws_tickets.items() if now > exp]
    for t in expired:
        _ws_tickets.pop(t, None)

    ticket = secrets.token_urlsafe(32)
    _ws_tickets[ticket] = now + lifetime_seconds
    return ticket


def validate_and_consume_ws_ticket(ticket: str) -> bool:
    """Validate and consume a single-use ticket."""
    now = time.time()
    exp = _ws_tickets.pop(ticket, None)
    if exp and now <= exp:
        return True
    return False


def verify_access_pin(
    x_beacon_pin: Optional[str] = Header(None, alias="X-Beacon-PIN"),
) -> bool:
    """Validate access PIN header if BEACON_PIN environment variable is configured."""
    required_pin = get_configured_pin()
    if not required_pin:
        return True
    if x_beacon_pin and hmac.compare_digest(x_beacon_pin.encode("utf-8"), required_pin.encode("utf-8")):
        return True
    raise HTTPException(
        status_code=401,
        detail="Valid Beacon access PIN required to perform this action. Send via X-Beacon-PIN header.",
    )

# Persistent catalog directory
from beacon.utils.paths import get_beacon_cache_dir
catalog_dir = get_beacon_cache_dir()
catalog_dir.mkdir(parents=True, exist_ok=True)
catalog_file = catalog_dir / "catalog.json"

upload_dir = Path(tempfile.gettempdir()) / "beacon_uploads"
upload_dir.mkdir(exist_ok=True)

# In-memory store initialized from catalog
analyses: Dict[str, Dict[str, Any]] = {}


def load_catalog() -> None:
    """Load persistent capture history catalog."""
    global analyses
    if catalog_file.exists():
        try:
            data = json.loads(catalog_file.read_text(encoding="utf-8"))
            analyses = data.get("analyses", {})
        except Exception as e:
            logger.error(f"Failed to load catalog: {e}")
            analyses = {}


def save_catalog() -> None:
    """Save capture history to persistent catalog."""
    try:
        catalog_file.write_text(json.dumps({"analyses": analyses}, indent=2, default=str), encoding="utf-8")
    except Exception as e:
        logger.error(f"Failed to save catalog: {e}")


# Initialize catalog on load
load_catalog()


class AnalysisRequest(BaseModel):
    mode: str = "blue"
    packet_limit: Optional[int] = None


class ModeChangeRequest(BaseModel):
    mode: str


class AuthVerifyRequest(BaseModel):
    pin: str


@app.get("/api/auth/status")
async def get_auth_status(
    x_beacon_pin: Optional[str] = Header(None, alias="X-Beacon-PIN"),
    pin: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Check whether access protection is active and if current client is authenticated."""
    required_pin = get_configured_pin()
    if not required_pin:
        return {"auth_required": False, "authenticated": True}
    provided = x_beacon_pin or pin
    return {"auth_required": True, "authenticated": provided == required_pin}


@app.post("/api/auth/verify")
async def verify_auth_pin_endpoint(req: AuthVerifyRequest) -> Dict[str, Any]:
    """Verify access PIN provided by remote client."""
    required_pin = get_configured_pin()
    if not required_pin:
        return {"success": True, "auth_required": False}
    if req.pin == required_pin:
        return {"success": True, "auth_required": True}
    raise HTTPException(status_code=401, detail="Invalid access PIN")


@app.get("/api/system/status")
async def get_system_status() -> Dict[str, Any]:
    """Return host and backend telemetry for low-resource profiling and remote monitoring."""
    service = get_live_service()
    stats = service.get_stats()
    is_low_res = os.environ.get("BEACON_LOW_RESOURCE", "0") in ("1", "true", "True")
    from beacon.live.service import get_current_process_memory_mb
    rss_mb = get_current_process_memory_mb()

    return {
        "status": "online",
        "low_resource_mode": is_low_res,
        "process_memory_mb": rss_mb,
        "live_capture_status": stats.status.value,
        "buffer_occupancy": service.buffer.occupancy,
        "buffer_capacity": service.buffer.capacity,
        "total_packets_ingested": service.buffer.total_ingested,
        "total_packets_evicted": service.buffer.total_evicted,
        "dropped_packets": service.dropped_packets,
        "incidents_count": service.evidence_store.incidents_count,
        "auth_required": bool(get_configured_pin()),
    }


@app.get("/api")
async def api_info() -> Dict[str, str]:
    """API info endpoint."""
    return {
        "name": "Beacon API",
        "version": "0.1.0",
        "status": "running",
        "description": "Cybersecurity Network Traffic Analysis Platform",
    }


@app.get("/api/health")
async def health_check() -> Dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/api/analyses")
async def list_analyses() -> Dict[str, List[Dict[str, Any]]]:
    """List capture history records."""
    summary_list = []

    # Check if live capture is active or has ingested packets
    live_service = get_live_service()
    if live_service.total_packets > 0 or live_service.status == LiveCaptureStatus.CAPTURING:
        live_findings = live_service.detection_engine.findings
        sev_counts = dict(live_service.detection_engine.findings_by_severity)
        now_ts = time.time()
        start_iso = datetime.fromtimestamp(live_service.start_time, tz=timezone.utc).isoformat() if live_service.start_time else ""
        dur = round(now_ts - live_service.start_time, 1) if live_service.start_time else 0.0

        summary_list.append({
            "id": "live",
            "filename": f"Live Network Capture ({live_service.selected_interface or 'active'})",
            "size": live_service.total_bytes,
            "upload_time": start_iso,
            "status": "complete",
            "mode": live_service.mode,
            "progress": 100.0,
            "packet_count": live_service.total_packets,
            "duration": dur,
            "findings_count": len(live_findings),
            "findings_by_severity": sev_counts,
            "is_live": True,
            "error": None,
        })

    for a in sorted(analyses.values(), key=lambda item: item.get("upload_time", ""), reverse=True):
        summary_list.append({
            "id": a["id"],
            "filename": a["filename"],
            "size": a.get("size", 0),
            "upload_time": a.get("upload_time"),
            "status": a["status"],
            "mode": a.get("mode", "white"),
            "progress": a.get("progress", 0.0),
            "packet_count": a.get("results", {}).get("total_packets", 0) if a.get("results") else 0,
            "duration": a.get("results", {}).get("duration_seconds", 0.0) if a.get("results") else 0.0,
            "findings_count": len(a.get("results", {}).get("findings", [])) if a.get("results") else 0,
            "findings_by_severity": a.get("results", {}).get("findings_by_severity", {}) if a.get("results") else {},
            "error": a.get("error"),
        })
    return {"analyses": summary_list}


@app.post("/api/upload", dependencies=[Depends(verify_access_pin)])
async def upload_pcap(file: UploadFile = File(...)) -> Dict[str, Any]:
    """Upload a PCAP/PCAPNG file and register it in catalog."""
    filename = file.filename or "capture.pcap"
    lower_name = filename.lower()
    if not (lower_name.endswith(".pcap") or lower_name.endswith(".pcapng") or lower_name.endswith(".cap")):
        raise HTTPException(status_code=400, detail="Only PCAP, PCAPNG, and CAP files are supported (.pcap, .pcapng, .cap)")

    analysis_id = str(uuid.uuid4())
    file_path = upload_dir / f"{analysis_id}_{filename}"

    try:
        contents = await file.read()
        with open(file_path, "wb") as f:
            f.write(contents)

        now_iso = datetime.now(timezone.utc).isoformat()
        record: Dict[str, Any] = {
            "id": analysis_id,
            "status": "pending",
            "progress": 0.0,
            "filename": filename,
            "file_path": str(file_path),
            "size": len(contents),
            "upload_time": now_iso,
            "mode": "blue",
            "results": None,
            "error": None,
        }
        analyses[analysis_id] = record
        save_catalog()

        return {
            "id": analysis_id,
            "filename": filename,
            "size": len(contents),
        }
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}") from e


@app.post("/api/analyze/{analysis_id}")
async def start_analysis(
    analysis_id: str,
    request: AnalysisRequest,
    background_tasks: BackgroundTasks,
) -> Dict[str, Any]:
    """Start background analysis of an uploaded capture."""
    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis record not found")

    analysis = analyses[analysis_id]
    analysis["mode"] = request.mode
    analysis["status"] = "running"
    analysis["progress"] = 0.1
    analysis["error"] = None
    save_catalog()

    background_tasks.add_task(run_analysis_job, analysis_id, request.mode, request.packet_limit)
    return {"id": analysis_id, "status": "running"}


def run_analysis_job(analysis_id: str, mode: str, packet_limit: Optional[int] = None) -> None:
    """Run analysis job in background."""
    if analysis_id not in analyses:
        return

    analysis = analyses[analysis_id]
    try:
        file_path = Path(analysis["file_path"])
        if not file_path.exists():
            raise FileNotFoundError(f"Capture file not found at {file_path}")

        mode_enum = {
            "blue": AnalysisMode.BLUE,
            "red": AnalysisMode.RED,
            "white": AnalysisMode.WHITE,
        }.get(mode.lower(), AnalysisMode.BLUE)

        analysis["progress"] = 0.2
        save_catalog()

        with AnalysisEngine(file_path, mode=mode_enum) as engine:
            results = engine.analyze(packet_limit=packet_limit)
            analysis["progress"] = 0.6
            save_catalog()

            # Host inventory
            hosts = HostAnalyzer.query(engine)
            analysis["progress"] = 0.7

            # Top conversations from SQLite
            cursor = engine.db_conn.cursor()
            conv_rows = cursor.execute(
                "SELECT * FROM conversations ORDER BY byte_count DESC LIMIT 100"
            ).fetchall()

            conversations = [
                {
                    "key": r["conversation_key"],
                    "host1": r["host1"],
                    "host2": r["host2"],
                    "port1": r["port1"],
                    "port2": r["port2"],
                    "protocol": r["protocol"],
                    "packet_count": r["packet_count"],
                    "byte_count": r["byte_count"],
                    "first_seen": r["first_seen"],
                    "last_seen": r["last_seen"],
                }
                for r in conv_rows
            ]

            # Timeline events
            timeline_events = engine.get_timeline_events()
            analysis["progress"] = 0.85

            # Extracted IOCs
            iocs = engine.get_iocs()
            analysis["progress"] = 0.95

            # Store aggregated results
            analysis["results"] = {
                **results,
                "hosts": [h.to_dict() for h in hosts],
                "conversations": conversations,
                "timeline": timeline_events,
                "iocs": iocs,
            }
            analysis["status"] = "complete"
            analysis["progress"] = 1.0
            save_catalog()

            # Record capture to Beacon Memory baseline
            try:
                engine.record_to_memory(capture_id=analysis_id)
            except Exception as mem_err:
                logger.error(f"Failed to index capture {analysis_id} in Beacon Memory: {mem_err}")

    except Exception as e:
        logger.error(f"Analysis failed for {analysis_id}: {e}")
        analysis["status"] = "error"
        analysis["error"] = str(e)
        analysis["progress"] = 0.0
        save_catalog()


@app.get("/api/analysis/{analysis_id}/status")
async def get_analysis_status(analysis_id: str) -> Dict[str, Any]:
    """Get status and progress of an analysis."""
    if analysis_id == "live":
        return get_live_service().get_status()

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis record not found")

    analysis = analyses[analysis_id]
    return {
        "id": analysis.get("id", analysis_id),
        "status": analysis.get("status", "unknown"),
        "progress": analysis.get("progress", 100 if analysis.get("status") == "complete" else 0),
        "filename": analysis.get("filename", "unknown"),
        "mode": analysis.get("mode", "blue"),
        "error": analysis.get("error"),
    }


@app.get("/api/analysis/{analysis_id}/results")
async def get_analysis_results(analysis_id: str) -> Dict[str, Any]:
    """Get complete analysis summary and results."""
    if analysis_id == "live":
        return get_live_service().get_results()

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis record not found")

    analysis = analyses[analysis_id]
    if analysis["status"] != "complete":
        raise HTTPException(status_code=400, detail=f"Analysis is not complete (current status: {analysis['status']})")

    return analysis["results"]


@app.get("/api/analysis/{analysis_id}/findings")
async def get_findings(
    analysis_id: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
) -> Dict[str, Any]:
    """Get evidence-backed findings with optional severity and category filtering."""
    if analysis_id == "live":
        findings = get_live_service().get_findings(severity=severity, category=category)
        return {"findings": findings, "total": len(findings), "is_live": True}

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analyses[analysis_id]
    if analysis["status"] != "complete":
        raise HTTPException(status_code=400, detail="Analysis not complete")

    findings = analysis["results"].get("findings", [])
    if severity and severity.lower() != "all":
        findings = [f for f in findings if str(f.get("severity", "")).lower() == severity.lower()]
    if category and category.lower() != "all":
        findings = [f for f in findings if category.lower() in str(f.get("category", "")).lower()]

    return {"findings": findings, "total": len(findings)}


@app.get("/api/analysis/{analysis_id}/hosts")
async def get_hosts(analysis_id: str, top: int = Query(50, ge=1, le=500)) -> Dict[str, Any]:
    """Get host inventory with traffic statistics."""
    if analysis_id == "live":
        service = get_live_service()
        hosts = service.get_hosts(top=top)
        return {"hosts": hosts, "total": len(service._host_stats), "is_live": True}

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analyses[analysis_id]
    if analysis["status"] != "complete":
        raise HTTPException(status_code=400, detail="Analysis not complete")

    hosts = analysis["results"].get("hosts", [])
    return {"hosts": hosts[:top], "total": len(hosts)}


@app.get("/api/analysis/{analysis_id}/conversations")
async def get_conversations(analysis_id: str, top: int = Query(50, ge=1, le=500)) -> Dict[str, Any]:
    """Get network conversations."""
    if analysis_id == "live":
        service = get_live_service()
        convs = service.get_conversations(top=top)
        return {"conversations": convs, "total": len(service._conversation_counts), "is_live": True}

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analyses[analysis_id]
    if analysis["status"] != "complete":
        raise HTTPException(status_code=400, detail="Analysis not complete")

    convs = analysis["results"].get("conversations", [])
    return {"conversations": convs[:top], "total": len(convs)}


@app.get("/api/analysis/{analysis_id}/timeline")
async def get_timeline(analysis_id: str, limit: int = Query(200, ge=1, le=2000)) -> Dict[str, Any]:
    """Get chronological event timeline."""
    if analysis_id == "live":
        service = get_live_service()
        timeline = service.get_timeline(limit=limit)
        return {"timeline": timeline, "total": len(service._timeline_events), "is_live": True}

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analyses[analysis_id]
    if analysis["status"] != "complete":
        raise HTTPException(status_code=400, detail="Analysis not complete")

    timeline = analysis["results"].get("timeline", [])
    return {"timeline": timeline[:limit], "total": len(timeline)}


@app.get("/api/analysis/{analysis_id}/iocs")
async def get_iocs(analysis_id: str) -> Dict[str, Any]:
    """Get extracted network indicators of interest (IOCs)."""
    if analysis_id == "live":
        service = get_live_service()
        iocs = service.get_iocs()
        return {"iocs": iocs, "total": len(iocs), "is_live": True}

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analyses[analysis_id]
    if analysis["status"] != "complete":
        raise HTTPException(status_code=400, detail="Analysis not complete")

    iocs = analysis["results"].get("iocs", [])
    return {"iocs": iocs, "total": len(iocs)}


@app.get("/api/analysis/{analysis_id}/packets")
async def get_packets(
    analysis_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    search: Optional[str] = None,
    protocol: Optional[str] = None,
    direction: Optional[str] = None,
    ip: Optional[str] = None,
    sort_by: str = "number",
    sort_dir: str = "asc",
) -> Dict[str, Any]:
    """Get paginated, searchable packets directly from SQLite cache or rolling buffer."""
    if analysis_id == "live":
        return get_live_service().get_packets(
            offset=offset,
            limit=limit,
            search=search,
            protocol=protocol,
            direction=direction,
            ip=ip,
            sort_by=sort_by,
            sort_dir=sort_dir,
        )

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analyses[analysis_id]
    file_path = Path(analysis["file_path"])

    with AnalysisEngine(file_path) as engine:
        return engine.get_packets(
            offset=offset,
            limit=limit,
            search=search,
            protocol=protocol,
            direction=direction,
            ip=ip,
            sort_by=sort_by,
            sort_dir=sort_dir,
        )


@app.get("/api/analysis/{analysis_id}/packet/{packet_number}")
async def get_packet_detail(analysis_id: str, packet_number: int) -> Dict[str, Any]:
    """Deep inspection of a single packet with correlated findings."""
    if analysis_id == "live":
        detail = get_live_service().get_packet_detail(packet_number)
        if not detail:
            raise HTTPException(
                status_code=404,
                detail=f"Packet #{packet_number} has been evicted from the rolling buffer and was not preserved in an incident.",
            )
        return detail

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analyses[analysis_id]
    file_path = Path(analysis["file_path"])

    with AnalysisEngine(file_path) as engine:
        detail = engine.get_packet_detail(packet_number)
        if not detail:
            raise HTTPException(status_code=404, detail=f"Packet #{packet_number} not found")

        # Correlate with analysis findings
        correlated = []
        for f in analysis.get("results", {}).get("findings", []):
            if packet_number in f.get("related_packets", []):
                correlated.append(f)
            elif f.get("source_ip") == detail.get("source") and (not f.get("destination_ip") or f.get("destination_ip") == detail.get("destination")):
                correlated.append(f)

        detail["findings"] = correlated
        return detail


@app.get("/api/analysis/{analysis_id}/graph")
async def get_network_graph(analysis_id: str, max_nodes: int = Query(40, ge=5, le=200)) -> Dict[str, Any]:
    """Get network topology nodes and edges for visualization."""
    if analysis_id == "live":
        return get_live_service().get_network_graph(max_nodes=max_nodes)

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analyses[analysis_id]
    file_path = Path(analysis["file_path"])

    with AnalysisEngine(file_path) as engine:
        return engine.get_network_graph(max_nodes=max_nodes)


@app.get("/api/analysis/{analysis_id}/evidence-graph")
async def get_evidence_graph(analysis_id: str, max_nodes: int = Query(60, ge=5, le=200)) -> Dict[str, Any]:
    """Get multi-entity investigation graph (hosts, domains, and security findings)."""
    if analysis_id == "live":
        return get_live_service().get_evidence_graph(max_nodes=max_nodes)

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analyses[analysis_id]
    file_path = Path(analysis["file_path"])
    findings = analysis.get("results", {}).get("findings", [])

    with AnalysisEngine(file_path) as engine:
        return engine.get_evidence_graph(max_nodes=max_nodes, findings=findings)


@app.get("/api/analysis/{analysis_id}/storyline")
async def get_storyline(analysis_id: str) -> Dict[str, Any]:
    """Get chronological investigation storyline with milestones across capture phases."""
    if analysis_id == "live":
        milestones = get_live_service().get_storyline()
        return {"storyline": milestones, "total": len(milestones), "is_live": True}

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analyses[analysis_id]
    file_path = Path(analysis["file_path"])
    findings = analysis.get("results", {}).get("findings", [])

    with AnalysisEngine(file_path) as engine:
        milestones = engine.get_investigation_storyline(findings=findings)
        return {"storyline": milestones, "total": len(milestones)}


@app.get("/api/analysis/{analysis_id}/stream/{conversation_key:path}")
async def get_conversation_stream(analysis_id: str, conversation_key: str, limit: int = Query(150, ge=1, le=500)) -> Dict[str, Any]:
    """Reconstruct message turns and formatted hex/ascii payload preview for a conversation."""
    if analysis_id == "live":
        return get_live_service().get_conversation_stream(conversation_key=conversation_key, limit=limit)

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analyses[analysis_id]
    file_path = Path(analysis["file_path"])

    with AnalysisEngine(file_path) as engine:
        return engine.get_conversation_stream(conversation_key=conversation_key, limit=limit)


@app.get("/api/analysis/compare")
async def compare_captures(
    baseline_id: str = Query(..., description="ID of baseline analysis"),
    target_id: str = Query(..., description="ID of target analysis to compare against baseline"),
) -> Dict[str, Any]:
    """Compare two capture analyses and report differences in hosts, findings, protocols, and volume."""
    b_is_live = (baseline_id == "live")
    t_is_live = (target_id == "live")

    if not b_is_live and baseline_id not in analyses:
        raise HTTPException(status_code=404, detail="Baseline analysis not found")
    if not t_is_live and target_id not in analyses:
        raise HTTPException(status_code=404, detail="Target analysis not found")

    b_res = get_live_service().get_results() if b_is_live else analyses[baseline_id].get("results", {})
    t_res = get_live_service().get_results() if t_is_live else analyses[target_id].get("results", {})

    return AnalysisEngine.compare_analyses(b_res, t_res)


@app.get("/api/analysis/{analysis_id}/search")
async def global_search(analysis_id: str, q: str = Query(..., min_length=1)) -> Dict[str, Any]:
    """Search across packets, hosts, conversations, and findings."""
    if analysis_id == "live":
        return get_live_service().global_search(query=q)

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analyses[analysis_id]
    file_path = Path(analysis["file_path"])

    with AnalysisEngine(file_path) as engine:
        results = engine.global_search(query=q)
        # Search in memory findings and IOCs too
        f_matches = [
            f for f in analysis.get("results", {}).get("findings", [])
            if q.lower() in f.get("title", "").lower() or q.lower() in f.get("description", "").lower() or (f.get("source_ip") and q in f.get("source_ip"))
        ]
        ioc_matches = [
            i for i in analysis.get("results", {}).get("iocs", [])
            if q.lower() in i.get("value", "").lower()
        ]
        results["findings"] = f_matches
        results["iocs"] = ioc_matches
        return results


@app.post("/api/analysis/{analysis_id}/mode")
async def switch_mode(analysis_id: str, request: ModeChangeRequest) -> Dict[str, Any]:
    """Switch analysis mode (Blue, Red, White) and re-run detections instantly from cache."""
    new_mode = request.mode.lower()
    if analysis_id == "live":
        service = get_live_service()
        service.mode = new_mode
        service.detection_engine.mode = new_mode
        return service.get_results()

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analyses[analysis_id]
    mode_enum = {
        "blue": AnalysisMode.BLUE,
        "red": AnalysisMode.RED,
        "white": AnalysisMode.WHITE,
    }.get(new_mode, AnalysisMode.BLUE)

    file_path = Path(analysis["file_path"])
    with AnalysisEngine(file_path, mode=mode_enum) as engine:
        results = engine.analyze()
        analysis["mode"] = new_mode
        if analysis.get("results"):
            analysis["results"]["mode"] = new_mode
            analysis["results"]["findings"] = results.get("findings", [])
            analysis["results"]["findings_count"] = results.get("findings_count", 0)
            analysis["results"]["findings_by_severity"] = results.get("findings_by_severity", {})

    save_catalog()
    return analysis["results"]


@app.get("/api/analysis/{analysis_id}/export", dependencies=[Depends(verify_access_pin)])
async def export_report(analysis_id: str, format: str = Query("html", pattern="^(html|json|csv|findings_csv|hosts_csv|convs_csv)$")) -> Response:
    """Export investigation report in HTML, JSON, or CSV format."""
    if analysis_id == "live":
        service = get_live_service()
        data = service.get_results()
        filename_base = "beacon_live_capture"
    else:
        if analysis_id not in analyses:
            raise HTTPException(status_code=404, detail="Analysis not found")

        analysis = analyses[analysis_id]
        if analysis["status"] != "complete" or not analysis.get("results"):
            raise HTTPException(status_code=400, detail="Analysis is not complete")

        data = analysis["results"]
        filename_base = Path(analysis["filename"]).stem

    if format == "html":
        content = ReportGenerator.generate_html(data)
        return HTMLResponse(
            content=content,
            headers={"Content-Disposition": f'attachment; filename="beacon_report_{filename_base}.html"'},
        )
    elif format == "json":
        content = ReportGenerator.generate_json(data)
        return JSONResponse(
            content=json.loads(content),
            headers={"Content-Disposition": f'attachment; filename="beacon_report_{filename_base}.json"'},
        )
    elif format in ("csv", "findings_csv"):
        content = ReportGenerator.generate_findings_csv(data.get("findings", []))
        return PlainTextResponse(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="beacon_findings_{filename_base}.csv"'},
        )
    elif format == "hosts_csv":
        content = ReportGenerator.generate_hosts_csv(data.get("hosts", []))
        return PlainTextResponse(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="beacon_hosts_{filename_base}.csv"'},
        )
    elif format == "convs_csv":
        content = ReportGenerator.generate_conversations_csv(data.get("conversations", []))
        return PlainTextResponse(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="beacon_conversations_{filename_base}.csv"'},
        )
    raise HTTPException(status_code=400, detail="Unsupported format")


@app.delete("/api/analysis/{analysis_id}", dependencies=[Depends(verify_access_pin)])
async def delete_analysis(analysis_id: str) -> Dict[str, str]:
    """Delete an analysis record and its uploaded capture file."""
    if analysis_id == "live":
        raise HTTPException(status_code=400, detail="Live capture cannot be deleted. Stop capture from the Live page.")

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analyses[analysis_id]
    try:
        file_path = Path(analysis["file_path"])
        if file_path.exists():
            file_path.unlink()
    except Exception as e:
        logger.error(f"Failed to delete capture file: {e}")

    del analyses[analysis_id]
    save_catalog()
    return {"status": "deleted"}


# -------------------------------------------------------------------------
# Beacon Memory & Historical Baseline API Endpoints
# -------------------------------------------------------------------------

class MemoryFeedbackRequest(BaseModel):
    target_key: str
    target_type: str = "host"
    status: str = "expected"
    is_expected: bool = True
    note: str = ""


@app.get("/api/memory/status")
async def get_memory_status() -> Dict[str, Any]:
    """Get status and metrics of the Beacon Memory historical baseline."""
    from beacon.memory.store import MemoryStore
    store = MemoryStore()
    return store.get_baseline_summary()


@app.get("/api/analysis/{analysis_id}/memory")
async def get_analysis_memory_briefing(analysis_id: str) -> Dict[str, Any]:
    """Get explainable change briefing and ranked investigation candidates for a capture."""
    if analysis_id == "live":
        return get_live_service().get_memory_briefing()

    if analysis_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis record not found")

    analysis = analyses[analysis_id]
    if analysis.get("status") != "complete" or not analysis.get("results"):
        raise HTTPException(status_code=400, detail="Analysis is not yet complete")

    file_path = Path(analysis["file_path"])
    with AnalysisEngine(file_path) as engine:
        return engine.get_memory_briefing(capture_id=analysis_id)


@app.post("/api/memory/feedback")
async def submit_memory_feedback(request: MemoryFeedbackRequest) -> Dict[str, Any]:
    """Submit analyst review feedback to mark behavior as expected or add investigation notes."""
    from beacon.memory.store import MemoryStore
    store = MemoryStore()
    return store.save_analyst_feedback(
        target_key=request.target_key,
        target_type=request.target_type,
        status=request.status,
        is_expected=request.is_expected,
        note=request.note,
    )


@app.get("/api/memory/recurring")
async def get_recurring_anomalies() -> Dict[str, Any]:
    """List anomalies observed across multiple captures in memory."""
    from beacon.memory.store import MemoryStore
    store = MemoryStore()
    anomalies = store.get_recurring_anomalies()
    return {"recurring_anomalies": anomalies, "total": len(anomalies)}


@app.get("/api/memory/history")
async def get_memory_history() -> Dict[str, Any]:
    """Get chronological history of all captures indexed in memory."""
    from beacon.memory.store import MemoryStore
    store = MemoryStore()
    return {"captures": store.get_captures_history()}


# -------------------------------------------------------------------------
# Beacon Live — Continuous Network Capture & Smart Evidence Retention
# -------------------------------------------------------------------------

class LiveStartRequest(BaseModel):
    interface: str
    capture_filter: Optional[str] = None
    buffer_capacity: int = 1000
    mode: str = "white"


class LivePinRequest(BaseModel):
    pinned: bool = True


class LiveNotesRequest(BaseModel):
    notes: str


@app.get("/api/live/interfaces")
async def get_live_interfaces() -> Dict[str, Any]:
    """List available network interfaces for live capture."""
    service = get_live_service()
    interfaces = service.get_available_interfaces()
    return {
        "interfaces": [iface.to_dict() for iface in interfaces],
        "total": len(interfaces),
    }


@app.post("/api/live/start", dependencies=[Depends(verify_access_pin)])
async def start_live_capture(req: LiveStartRequest) -> Dict[str, Any]:
    """Start continuous live network capture on the designated interface."""
    service = get_live_service()
    success = service.start_capture(
        interface_id=req.interface,
        capture_filter=req.capture_filter,
        buffer_capacity=req.buffer_capacity,
        mode=req.mode,
    )
    if not success:
        raise HTTPException(
            status_code=400,
            detail=service.error_message or "Failed to start live network capture",
        )
    return {"status": "started", "stats": service.get_stats().to_dict()}


@app.post("/api/live/stop", dependencies=[Depends(verify_access_pin)])
async def stop_live_capture() -> Dict[str, Any]:
    """Stop continuous live network capture."""
    service = get_live_service()
    service.stop_capture()
    return {"status": "stopped", "stats": service.get_stats().to_dict()}


@app.post("/api/live/pause", dependencies=[Depends(verify_access_pin)])
async def pause_live_capture() -> Dict[str, Any]:
    """Pause detection and packet processing in live capture."""
    service = get_live_service()
    service.pause_capture()
    return {"status": "paused", "stats": service.get_stats().to_dict()}


@app.post("/api/live/resume", dependencies=[Depends(verify_access_pin)])
async def resume_live_capture() -> Dict[str, Any]:
    """Resume live capture after being paused."""
    service = get_live_service()
    service.resume_capture()
    return {"status": "capturing", "stats": service.get_stats().to_dict()}


@app.get("/api/live/status")
async def get_live_status() -> Dict[str, Any]:
    """Get current telemetry metrics and capture status."""
    service = get_live_service()
    return service.get_stats().to_dict()


@app.get("/api/live/packets")
async def get_live_packets(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """Get recent packets from the bounded rolling buffer."""
    service = get_live_service()
    all_recent = service.buffer.get_recent(limit=service.buffer.capacity)
    total = len(all_recent)
    sliced = all_recent[offset : offset + limit]
    return {
        "packets": [p.to_dict() for p in sliced],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@app.get("/api/live/incidents")
async def get_live_incidents(
    severity: Optional[str] = Query(None),
    pinned_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """Get list of preserved security incidents."""
    service = get_live_service()
    incidents = service.evidence_store.get_incidents(
        severity_filter=severity,
        pinned_only=pinned_only,
        limit=limit,
        offset=offset,
    )
    return {
        "incidents": [inc.to_dict() for inc in incidents],
        "total": service.evidence_store.incidents_count,
        "pinned_count": service.evidence_store.pinned_count,
    }


@app.get("/api/live/incidents/{incident_id}")
async def get_live_incident_details(incident_id: str) -> Dict[str, Any]:
    """Get detailed evidence for an incident including all ordered retained packets."""
    service = get_live_service()
    incident = service.evidence_store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    data = incident.to_dict()
    data["all_packets"] = [p.to_dict() for p in incident.get_all_packets_ordered()]
    return data


@app.post("/api/live/incidents/{incident_id}/pin")
async def pin_live_incident(incident_id: str, req: LivePinRequest) -> Dict[str, Any]:
    """Pin or unpin an incident to protect it from eviction."""
    service = get_live_service()
    success = service.evidence_store.set_incident_pin(incident_id, req.pinned)
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"incident_id": incident_id, "pinned": req.pinned}


@app.post("/api/live/incidents/{incident_id}/notes")
async def update_live_incident_notes(incident_id: str, req: LiveNotesRequest) -> Dict[str, Any]:
    """Update analyst notes on an incident."""
    service = get_live_service()
    success = service.evidence_store.update_incident_notes(incident_id, req.notes)
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"incident_id": incident_id, "notes": req.notes}


@app.get("/api/live/incidents/{incident_id}/export", dependencies=[Depends(verify_access_pin)])
async def export_live_incident_pcap(incident_id: str):
    """Export the retained packets for an incident to a standard PCAP file."""
    service = get_live_service()
    pcap_path = service.evidence_store.export_incident_pcap(incident_id)
    if not pcap_path or not pcap_path.exists():
        raise HTTPException(status_code=404, detail="Incident not found or PCAP generation failed")
    return FileResponse(
        path=str(pcap_path),
        media_type="application/vnd.tcpdump.pcap",
        filename=f"incident_{incident_id}.pcap",
    )


@app.websocket("/api/live/ws")
@app.websocket("/ws/live")
async def websocket_live_endpoint(websocket: WebSocket):
    """WebSocket endpoint streaming real-time live capture telemetry and alerts."""
    required_pin = get_configured_pin()
    if required_pin:
        pin = websocket.query_params.get("pin") or websocket.headers.get("x-beacon-pin")
        if pin != required_pin:
            await websocket.close(code=1008)
            return

    await websocket.accept()
    service = get_live_service()
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)

    def on_broadcast(event: Dict[str, Any]) -> None:
        try:
            loop.call_soon_threadsafe(queue.put_nowait, event)
        except Exception:
            pass

    service.subscribe(on_broadcast)

    async def sender_task() -> None:
        last_telemetry_time = time.time()
        # Send initial snapshot immediately
        await websocket.send_json({
            "type": "initial",
            "stats": service.get_stats().to_dict(),
            "recent_packets": [p.to_dict() for p in service.buffer.get_recent(limit=30)],
        })
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=1.0)
                await websocket.send_json(event)
            except asyncio.TimeoutError:
                pass

            now = time.time()
            if now - last_telemetry_time >= 1.0:
                stats = service.get_stats().to_dict()
                recent_pkts = [p.to_dict() for p in service.buffer.get_recent(limit=30)]
                await websocket.send_json({
                    "type": "telemetry",
                    "stats": stats,
                    "recent_packets": recent_pkts,
                })
                last_telemetry_time = now

    async def receiver_task() -> None:
        while True:
            text = await websocket.receive_text()
            if text == "ping":
                await websocket.send_text("pong")

    sender = asyncio.create_task(sender_task())
    receiver = asyncio.create_task(receiver_task())

    try:
        done, pending = await asyncio.wait(
            [sender, receiver],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug(f"Live WebSocket connection closed: {e}")
    finally:
        sender.cancel()
        receiver.cancel()
        service.unsubscribe(on_broadcast)


# Mount pre-built React frontend if present (Production single-process deployment)
from beacon.utils.paths import find_frontend_dist

frontend_dist = find_frontend_dist()
if frontend_dist and (frontend_dist / "index.html").exists():
    if (frontend_dist / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(frontend_dist / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        """Serve built React single page application for browser clients."""
        if full_path.startswith("api/") or full_path == "api":
            raise HTTPException(status_code=404, detail="API route not found")
        target = frontend_dist / full_path
        if target.is_file():
            return FileResponse(str(target))
        return FileResponse(str(frontend_dist / "index.html"))
else:
    @app.get("/")
    async def serve_missing_frontend():
        """Helpful fallback response when frontend production build is not yet generated."""
        return HTMLResponse(
            """<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Beacon — Production Frontend Assets Missing</title>
                <style>
                    body { background: #080c14; color: #e2e8f0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, monospace; padding: 3rem; text-align: center; }
                    .card { max-width: 650px; margin: 4rem auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 2rem; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
                    h1 { color: #38bdf8; font-size: 1.5rem; margin-bottom: 1rem; }
                    p { color: #94a3b8; font-size: 0.95rem; line-height: 1.6; }
                    code { background: #1e293b; color: #f1f5f9; padding: 0.2rem 0.5rem; border-radius: 4px; }
                    pre { background: #020617; border: 1px solid #334155; padding: 1rem; border-radius: 6px; text-align: left; overflow-x: auto; color: #a5f3fc; }
                    a { color: #38bdf8; text-decoration: none; }
                </style>
            </head>
            <body>
                <div class="card">
                    <h1>Beacon API Online — Frontend Assets Missing</h1>
                    <p>The Beacon backend is active and healthy, but pre-built React production assets (<code>web/dist/index.html</code>) were not found.</p>
                    <p>To compile the production frontend:</p>
                    <pre>cd web && npm install && npm run build</pre>
                    <p>Backend API status is available at <a href="/api/health">/api/health</a>.</p>
                </div>
            </body>
            </html>""",
            status_code=503,
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
