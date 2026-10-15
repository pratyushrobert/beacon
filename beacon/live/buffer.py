"""Bounded rolling in-memory packet buffer for Beacon Live."""

from __future__ import annotations

import collections
import threading
from typing import Dict, List, Optional, Set, Tuple

from beacon.live.models import RollingPacket


class RollingPacketBuffer:
    """
    Thread-safe, bounded ring buffer of recent packets.
    Enforces a strict maximum capacity (default 1,000 packets) and evicts
    the oldest packet when capacity is reached.
    """

    def __init__(self, capacity: int = 1000):
        if capacity <= 0:
            raise ValueError("Buffer capacity must be a positive integer")
        self._capacity = capacity
        self._buffer: collections.deque[RollingPacket] = collections.deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._total_ingested = 0
        self._total_evicted = 0
        self._estimated_bytes = 0

    @property
    def capacity(self) -> int:
        return self._capacity

    @capacity.setter
    def capacity(self, new_capacity: int) -> None:
        if new_capacity <= 0:
            raise ValueError("Buffer capacity must be a positive integer")
        with self._lock:
            self._capacity = new_capacity
            # Create new deque with new capacity preserving recent items
            old_items = list(self._buffer)
            self._buffer = collections.deque(old_items[-new_capacity:], maxlen=new_capacity)

    @property
    def occupancy(self) -> int:
        with self._lock:
            return len(self._buffer)

    @property
    def total_ingested(self) -> int:
        with self._lock:
            return self._total_ingested

    @property
    def total_evicted(self) -> int:
        with self._lock:
            return self._total_evicted

    @property
    def estimated_bytes(self) -> int:
        with self._lock:
            return self._estimated_bytes

    def append(self, packet: RollingPacket) -> None:
        """
        Append a new packet to the rolling buffer.
        If buffer is full, the oldest packet is evicted automatically.
        """
        with self._lock:
            if len(self._buffer) == self._capacity:
                evicted = self._buffer[0]
                self._total_evicted += 1
                self._estimated_bytes = max(0, self._estimated_bytes - evicted.estimated_bytes)

            self._buffer.append(packet)
            self._total_ingested += 1
            self._estimated_bytes += packet.estimated_bytes

    def get_recent(self, limit: int = 50, offset: int = 0) -> List[RollingPacket]:
        """Return the most recent packets in reverse chronological order (newest first)."""
        with self._lock:
            items = list(self._buffer)
            items.reverse()
            return items[offset : offset + limit]

    def get_packet_by_number(self, packet_number: int) -> Optional[RollingPacket]:
        """Look up a specific packet by sequence number if still present in buffer."""
        with self._lock:
            for p in self._buffer:
                if p.number == packet_number:
                    return p
            return None

    def get_pre_trigger_window(
        self,
        trigger_number: int,
        window_count: int = 25,
        window_seconds: float = 10.0,
    ) -> Tuple[List[RollingPacket], bool]:
        """
        Extract packets preceding the trigger packet within count and time bounds.
        Returns (pre_trigger_packets, is_partial).
        is_partial is True if earlier packets were already evicted from the buffer.
        """
        with self._lock:
            if not self._buffer:
                return [], False

            oldest_available_num = self._buffer[0].number
            oldest_available_ts = self._buffer[0].timestamp

            # Find the trigger packet or its temporal position
            trigger_ts: Optional[float] = None
            preceding: List[RollingPacket] = []

            for p in self._buffer:
                if p.number == trigger_number:
                    trigger_ts = p.timestamp
                    break
                if p.number < trigger_number:
                    preceding.append(p)

            if trigger_ts is None and preceding:
                trigger_ts = preceding[-1].timestamp
            elif trigger_ts is None:
                trigger_ts = oldest_available_ts

            # Filter by window_seconds
            cutoff_ts = trigger_ts - window_seconds
            windowed = [p for p in preceding if p.timestamp >= cutoff_ts]

            # Slice to max window_count
            result = windowed[-window_count:]

            # If the oldest packet in the buffer is newer than cutoff_ts,
            # or if we ingested more packets than capacity, some context was evicted
            is_partial = False
            if self._total_evicted > 0 and len(result) < window_count:
                # Check if buffer wrapped around before our desired window
                if oldest_available_num > (trigger_number - window_count):
                    is_partial = True

            return result, is_partial

    def get_packets_for_conversation(self, conv_key: str, max_count: int = 50) -> List[RollingPacket]:
        """Return packets matching a specific conversation key."""
        with self._lock:
            matched = [p for p in self._buffer if p.conversation_key == conv_key]
            return matched[-max_count:]

    def get_packets_for_host(self, ip: str, max_count: int = 50) -> List[RollingPacket]:
        """Return packets involving a specific host IP."""
        with self._lock:
            matched = [p for p in self._buffer if p.ip_src == ip or p.ip_dst == ip]
            return matched[-max_count:]

    def clear(self) -> None:
        """Reset the buffer."""
        with self._lock:
            self._buffer.clear()
            self._estimated_bytes = 0
