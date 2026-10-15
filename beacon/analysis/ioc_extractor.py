"""Evidence-backed extraction of network indicators of interest."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, Iterable, List, Optional

from beacon.core.packet_parser import ParsedPacket
from beacon.models import IOC
from beacon.utils.formatters import iter_text


IP_PATTERN = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
DOMAIN_PATTERN = re.compile(r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])")
URL_PATTERN = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
HASH_PATTERN = re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{32,64}(?![a-f0-9])")


class IOCExtractor:
    """Extract IPs, domains, URLs, and hashes from packet metadata."""

    @staticmethod
    def extract(packets: Iterable[ParsedPacket]) -> List[IOC]:
        counts: Counter[tuple[str, str]] = Counter()
        first_seen: Dict[tuple[str, str], datetime] = {}
        last_seen: Dict[tuple[str, str], datetime] = {}
        contexts: Dict[tuple[str, str], set[str]] = defaultdict(set)
        for packet in packets:
            text = "\n".join(iter_text(packet.raw_data))
            values = {
                "ip": IP_PATTERN.findall(text),
                "domain": DOMAIN_PATTERN.findall(text),
                "url": URL_PATTERN.findall(text),
                "hash": HASH_PATTERN.findall(text),
            }
            for ioc_type, found in values.items():
                for value in found:
                    if ioc_type == "ip":
                        try:
                            normalized = str(ipaddress.ip_address(value))
                        except ValueError:
                            continue
                    else:
                        normalized = value.lower() if ioc_type == "domain" else value
                    key = (ioc_type, normalized)
                    counts[key] += 1
                    first_seen[key] = packet.timestamp or first_seen.get(key)
                    last_seen[key] = packet.timestamp or last_seen.get(key)
                    contexts[key].add(f"packet {packet.number}")
        return [
            IOC(
                type=ioc_type,
                value=value,
                count=count,
                first_seen=first_seen.get((ioc_type, value)),
                last_seen=last_seen.get((ioc_type, value)),
                context=sorted(contexts[(ioc_type, value)])[:3],
            )
            for (ioc_type, value), count in counts.most_common()
        ]
