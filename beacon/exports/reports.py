"""Professional cybersecurity investigation reports in HTML, JSON, and CSV formats."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def _normalize_to_dict(item: Any) -> Dict[str, Any]:
    """Convert dataclass, model, or dict item into a plain dictionary."""
    if hasattr(item, "to_dict"):
        return item.to_dict()
    elif isinstance(item, dict):
        return dict(item)
    elif hasattr(item, "__dict__"):
        return item.__dict__
    return {}


class ReportGenerator:
    """Generate professional cybersecurity investigation reports."""

    @staticmethod
    def generate_json(analysis_data: Dict[str, Any]) -> str:
        """Export analysis data as formatted JSON."""
        # Deep normalize dataclasses
        normalized: Dict[str, Any] = {}
        for k, v in analysis_data.items():
            if isinstance(v, list):
                normalized[k] = [_normalize_to_dict(item) if hasattr(item, "to_dict") or hasattr(item, "__dict__") else item for item in v]
            else:
                normalized[k] = v
        return json.dumps(normalized, indent=2, default=str)

    @staticmethod
    def generate_csv(analysis_data: Dict[str, Any], csv_type: str = "findings") -> str:
        """Export analysis data as CSV based on csv_type ('findings', 'hosts', 'conversations')."""
        if csv_type == "hosts":
            hosts = [_normalize_to_dict(h) for h in analysis_data.get("hosts", [])]
            return ReportGenerator.generate_hosts_csv(hosts)
        elif csv_type in ("conversations", "convs"):
            convs = [_normalize_to_dict(c) for c in analysis_data.get("conversations", [])]
            return ReportGenerator.generate_conversations_csv(convs)
        else:
            findings = [_normalize_to_dict(f) for f in analysis_data.get("findings", [])]
            return ReportGenerator.generate_findings_csv(findings)

    @staticmethod
    def generate_findings_csv(findings: List[Any]) -> str:
        """Export findings as CSV."""
        output = io.StringIO()
        fieldnames = [
            "id", "severity", "confidence", "category", "title",
            "source_ip", "destination_ip", "protocol", "evidence",
            "detection_rationale", "recommendation", "next_step"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for f in findings:
            row = _normalize_to_dict(f)
            if isinstance(row.get("evidence"), list):
                row["evidence"] = " | ".join(str(e) for e in row["evidence"])
            writer.writerow(row)
        return output.getvalue()

    @staticmethod
    def generate_hosts_csv(hosts: List[Any]) -> str:
        """Export host inventory as CSV."""
        output = io.StringIO()
        fieldnames = [
            "ip", "is_internal", "packets_sent", "packets_received",
            "bytes_sent", "bytes_received", "total_bytes", "protocols",
            "first_seen", "last_seen"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for h in hosts:
            row = _normalize_to_dict(h)
            if isinstance(row.get("protocols"), (list, set)):
                row["protocols"] = ",".join(str(p) for p in row["protocols"])
            writer.writerow(row)
        return output.getvalue()

    @staticmethod
    def generate_conversations_csv(conversations: List[Any]) -> str:
        """Export conversations as CSV."""
        output = io.StringIO()
        fieldnames = [
            "key", "host1", "port1", "host2", "port2",
            "protocol", "packet_count", "byte_count", "first_seen", "last_seen"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for c in conversations:
            writer.writerow(_normalize_to_dict(c))
        return output.getvalue()

    @staticmethod
    def generate_html(analysis_data: Dict[str, Any]) -> str:
        """Generate a standalone, beautifully styled HTML investigation report."""
        capture_file = analysis_data.get("pcap_file", "Network Capture")
        file_name = Path(capture_file).name
        mode = analysis_data.get("mode", "blue").capitalize()
        total_packets = analysis_data.get("total_packets", 0)
        total_bytes = analysis_data.get("total_bytes", 0)
        duration = analysis_data.get("duration_seconds", 0.0)
        unique_hosts = analysis_data.get("unique_hosts", 0)
        findings = [_normalize_to_dict(f) for f in analysis_data.get("findings", [])]
        hosts = [_normalize_to_dict(h) for h in analysis_data.get("hosts", [])]
        conversations = [_normalize_to_dict(c) for c in analysis_data.get("conversations", [])]
        iocs = [_normalize_to_dict(i) for i in analysis_data.get("iocs", [])]
        timeline = [_normalize_to_dict(t) for t in analysis_data.get("timeline", [])]

        # Format bytes
        def fmt_bytes(b: float) -> str:
            val = float(b or 0)
            for unit in ["B", "KB", "MB", "GB"]:
                if val < 1024 or unit == "GB":
                    return f"{val:.1f} {unit}" if unit != "B" else f"{int(val)} B"
                val /= 1024
            return f"{val:.1f} GB"

        # Severity count
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            s = str(f.get("severity", "info")).lower()
            if s in sev_counts:
                sev_counts[s] += 1

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

        # HTML template
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Beacon Investigation Report — {file_name}</title>
<style>
  :root {{
    --bg: #0f172a;
    --card: #1e293b;
    --border: #334155;
    --text: #f8fafc;
    --text-muted: #94a3b8;
    --primary: #38bdf8;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #f59e0b;
    --low: #3b82f6;
    --info: #64748b;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 2.5rem;
    line-height: 1.6;
  }}
  .header {{
    border-bottom: 2px solid var(--border);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .title {{ font-size: 2rem; font-weight: 700; color: var(--primary); }}
  .subtitle {{ color: var(--text-muted); font-size: 0.95rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2.5rem; }}
  .stat-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
  }}
  .stat-label {{ font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.05em; }}
  .stat-val {{ font-size: 1.75rem; font-weight: 700; margin-top: 0.25rem; }}
  .section {{ margin-bottom: 3rem; }}
  .section-title {{
    font-size: 1.35rem;
    font-weight: 600;
    margin-bottom: 1rem;
    border-left: 4px solid var(--primary);
    padding-left: 0.75rem;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--card);
    border-radius: 8px;
    overflow: hidden;
    margin-bottom: 1.5rem;
  }}
  th, td {{
    padding: 0.85rem 1rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
    font-size: 0.9rem;
  }}
  th {{ background: #182234; color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
  tr:hover {{ background: #263348; }}
  .badge {{
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
  }}
  .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
  .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
  .badge-medium {{ background: rgba(245, 158, 11, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
  .badge-low {{ background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }}
  .badge-info {{ background: rgba(100, 116, 139, 0.2); color: var(--info); border: 1px solid var(--info); }}
  .finding-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
    margin-bottom: 1.25rem;
  }}
  .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }}
  .finding-title {{ font-size: 1.1rem; font-weight: 600; }}
  .finding-meta {{ color: var(--text-muted); font-size: 0.85rem; margin-bottom: 0.75rem; font-family: monospace; }}
  .evidence-box {{
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 0.75rem;
    font-family: monospace;
    font-size: 0.85rem;
    margin-top: 0.5rem;
    white-space: pre-wrap;
    word-break: break-all;
  }}
  .recommendation {{ margin-top: 0.75rem; font-size: 0.9rem; color: #a5f3fc; }}
  .next-step {{ margin-top: 0.35rem; font-size: 0.85rem; color: #fde047; font-style: italic; }}
  .footer {{
    border-top: 1px solid var(--border);
    padding-top: 1.5rem;
    color: var(--text-muted);
    font-size: 0.85rem;
    text-align: center;
  }}
</style>
</head>
<body>

<div class="header">
  <div>
    <h1 class="title">Beacon Investigation Report</h1>
    <div class="subtitle">Capture: <strong>{file_name}</strong> | Generated: {now_str} | Mode: <strong>{mode}</strong></div>
  </div>
</div>

<div class="grid">
  <div class="stat-card">
    <div class="stat-label">Total Packets</div>
    <div class="stat-val">{total_packets:,}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Total Volume</div>
    <div class="stat-val">{fmt_bytes(total_bytes)}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Duration</div>
    <div class="stat-val">{duration:.1f}s</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Unique Hosts</div>
    <div class="stat-val">{unique_hosts}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Findings</div>
    <div class="stat-val" style="color: {'var(--critical)' if sev_counts['critical'] > 0 else ('var(--high)' if sev_counts['high'] > 0 else 'var(--primary)')}">
      {len(findings)}
    </div>
  </div>
</div>

<div class="section">
  <h2 class="section-title">Security Findings ({len(findings)})</h2>
"""
        if not findings:
            html += """  <div class="finding-card"><p style="color: var(--text-muted);">No security anomalies or exposures detected in this capture.</p></div>\n"""
        else:
            for f in findings:
                sev = str(f.get("severity", "info")).lower()
                conf = str(f.get("confidence", "medium")).capitalize()
                title = f.get("title", "Finding")
                desc = f.get("description", "")
                src = f.get("source_ip", "")
                dst = f.get("destination_ip", "")
                endpoints = f"{src} → {dst}" if src and dst else (src or dst or "Capture Wide")
                rec = f.get("recommendation", "")
                rationale = f.get("detection_rationale", "")
                next_step = f.get("next_step", "")
                evidence = f.get("evidence", [])

                html += f"""
  <div class="finding-card">
    <div class="finding-header">
      <div class="finding-title">{title}</div>
      <div>
        <span class="badge badge-{sev}">{sev}</span>
        <span class="badge badge-info" style="margin-left: 0.5rem;">{conf} Conf</span>
      </div>
    </div>
    <div class="finding-meta">Endpoints: {endpoints} | Category: {f.get('category', 'security')}</div>
    <p>{desc}</p>
    """
                if rationale:
                    html += f"""<div style="font-size: 0.85rem; color: #cbd5e1; margin-top: 0.5rem;"><strong>Rationale:</strong> {rationale}</div>"""

                if evidence:
                    ev_text = "\n".join(str(e) for e in evidence)
                    html += f"""<div class="evidence-box"><strong>Evidence:</strong>\n{ev_text}</div>"""

                if rec:
                    html += f"""<div class="recommendation"><strong>Recommendation:</strong> {rec}</div>"""
                if next_step:
                    html += f"""<div class="next-step"><strong>Next Step:</strong> {next_step}</div>"""

                html += "\n  </div>"

        html += f"""
</div>

<div class="section">
  <h2 class="section-title">Top Communicating Hosts</h2>
  <table>
    <thead>
      <tr>
        <th>Host IP</th>
        <th>Type</th>
        <th>Packets Sent</th>
        <th>Packets Rcvd</th>
        <th>Total Volume</th>
        <th>Protocols</th>
      </tr>
    </thead>
    <tbody>
"""
        for h in hosts[:15]:
            ip = h.get("ip", "")
            is_int = "Internal" if h.get("is_internal") else "External"
            badge_class = "badge-low" if h.get("is_internal") else "badge-info"
            psent = h.get("packets_sent", 0)
            prcvd = h.get("packets_received", 0)
            tot_b = h.get("total_bytes", 0)
            protos = ", ".join(h.get("protocols", []))
            html += f"""
      <tr>
        <td style="font-family: monospace; font-weight: 600;">{ip}</td>
        <td><span class="badge {badge_class}">{is_int}</span></td>
        <td style="font-family: monospace;">{psent:,}</td>
        <td style="font-family: monospace;">{prcvd:,}</td>
        <td style="font-family: monospace;">{fmt_bytes(tot_b)}</td>
        <td>{protos}</td>
      </tr>
"""
        html += """
    </tbody>
  </table>
</div>

<div class="footer">
  Beacon Cybersecurity Network Traffic Analysis Platform • Powered by TShark
</div>
</body>
</html>
"""
        return html
