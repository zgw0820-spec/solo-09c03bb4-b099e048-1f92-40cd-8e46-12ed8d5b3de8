"""Bounded admission control for in-zone UDP DNS queries.

A single faulty source must never be able to starve the rest of the
network, and the server must never react to a flood by spawning an
unbounded number of threads or queue entries, nor by accumulating
unbounded per-source state. This module enforces all three bounds in a
fixed amount of memory with plain in-process data structures:

* **per-source token bucket** — a sustained rate plus a burst allowance;
  excess queries are rejected immediately (SERVFAIL);
* **per-source inflight cap** — how many queries of one source may be
  processed at the same time, so one source cannot occupy every worker;
* **global inflight cap** — a hard ceiling on concurrent processing,
  which also bounds the thread-pool work queue;
* **bounded LRU source table** — at most ``max_sources`` entries ever.
  A rotating source address therefore cannot grow state without limit:
  the least recently used entry is evicted (idle entries first).

All checks run in the single UDP listener thread *before* any work is
handed to a thread, so a rejected query creates neither a thread nor a
queue entry. Only the small, lock-protected bookkeeping is shared.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, Optional

# Rejection reason codes (also exposed through the REST API).
REJECT_RATE_LIMITED = "rate_limited"
REJECT_SOURCE_INFLIGHT = "source_inflight_full"
REJECT_GLOBAL_INFLIGHT = "global_inflight_full"
REJECT_REASONS = (
    REJECT_RATE_LIMITED,
    REJECT_SOURCE_INFLIGHT,
    REJECT_GLOBAL_INFLIGHT,
)


@dataclass
class _SourceState:
    tokens: float
    last_refill: float
    inflight: int
    seen: int          # total in-zone queries observed from this source
    rejected: int      # rejections charged to this source


@dataclass(frozen=True)
class AdmissionDecision:
    allowed: bool
    reason: Optional[str]
    source: str


class AdmissionController:
    """Thread-safe, fixed-memory per-source admission controller."""

    def __init__(
        self,
        rate_per_source: int,
        burst_per_source: int,
        inflight_per_source: int,
        inflight_global: int,
        max_sources: int,
        enabled: bool = True,
    ) -> None:
        # Defensive clamping: a bad environment value can never disable a
        # bound or create a zero/negative limit that denies all traffic.
        self.rate = max(1, int(rate_per_source))
        self.burst = max(1, int(burst_per_source))
        self.per_source_cap = max(1, int(inflight_per_source))
        self.global_cap = max(1, int(inflight_global))
        self.max_sources = max(1, int(max_sources))
        self.enabled = bool(enabled)

        self._lock = threading.Lock()
        self._sources: "OrderedDict[str, _SourceState]" = OrderedDict()
        self._global_inflight = 0
        self._peak_global_inflight = 0
        self._total_allowed = 0
        self._total_rejected = 0
        self._rejections: Dict[str, int] = {r: 0 for r in REJECT_REASONS}
        self._start = time.monotonic()

    # ------------------------------------------------------------------
    def _refill(self, st: _SourceState, now: float) -> None:
        elapsed = now - st.last_refill
        if elapsed > 0:
            st.tokens = min(
                float(self.burst), st.tokens + elapsed * self.rate
            )
            st.last_refill = now

    def _evict_if_needed(self) -> None:
        """Keep the source table bounded (LRU, idle entries first)."""
        while len(self._sources) >= self.max_sources:
            victim: Optional[str] = None
            # Prefer an entry with no in-flight work so eviction never
            # disturbs accounting of a query currently being processed.
            for key, st in self._sources.items():
                if st.inflight == 0:
                    victim = key
                    break
            if victim is None:
                # Every tracked source is busy: drop the oldest LRU entry.
                victim, _ = self._sources.popitem(last=False)
            else:
                self._sources.pop(victim)

    def check(self, source: str) -> AdmissionDecision:
        """Admit one in-zone query from ``source``.

        Must be paired with :meth:`complete` for every allowed query.
        Runs in O(1) amortised time; the LRU scan only happens when the
        fixed table is full.
        """
        now = time.monotonic()
        with self._lock:
            st = self._sources.get(source)
            if st is None:
                self._evict_if_needed()
                st = _SourceState(
                    tokens=float(self.burst),
                    last_refill=now,
                    inflight=0,
                    seen=0,
                    rejected=0,
                )
                self._sources[source] = st
            else:
                # Mark this source as most-recently-used.
                self._sources.move_to_end(source)
                self._refill(st, now)

            st.seen += 1

            # 1) per-source concurrency cap protects the worker pool.
            if st.inflight >= self.per_source_cap:
                return self._reject(st, source, REJECT_SOURCE_INFLIGHT)

            # 2) token bucket bounds the sustained/burst query rate.
            if st.tokens < 1.0:
                return self._reject(st, source, REJECT_RATE_LIMITED)

            # 3) global concurrency cap bounds pool + queue for all sources.
            if self._global_inflight >= self.global_cap:
                return self._reject(st, source, REJECT_GLOBAL_INFLIGHT)

            st.tokens -= 1.0
            st.inflight += 1
            self._global_inflight += 1
            if self._global_inflight > self._peak_global_inflight:
                self._peak_global_inflight = self._global_inflight
            self._total_allowed += 1
            return AdmissionDecision(True, None, source)

    def _reject(
        self, st: _SourceState, source: str, reason: str
    ) -> AdmissionDecision:
        st.rejected += 1
        self._total_rejected += 1
        self._rejections[reason] += 1
        return AdmissionDecision(False, reason, source)

    def complete(self, source: str) -> None:
        """Release the inflight slots held by an allowed query."""
        with self._lock:
            self._global_inflight = max(0, self._global_inflight - 1)
            st = self._sources.get(source)
            if st is not None:
                st.inflight = max(0, st.inflight - 1)
                # Completion counts as recent activity for LRU ordering.
                self._sources.move_to_end(source)

    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        """Point-in-time view for the local admission REST API."""
        now = time.monotonic()
        with self._lock:
            sources = [
                {
                    "source": src,
                    "inflight": st.inflight,
                    "tokens": round(st.tokens, 3),
                    "seen": st.seen,
                    "rejected": st.rejected,
                }
                for src, st in self._sources.items()
            ]
            return {
                "enabled": self.enabled,
                "config": {
                    "rate_per_source": self.rate,
                    "burst_per_source": self.burst,
                    "inflight_per_source": self.per_source_cap,
                    "inflight_global": self.global_cap,
                    "max_tracked_sources": self.max_sources,
                },
                "uptime_seconds": round(now - self._start, 3),
                "tracked_sources": len(self._sources),
                "global_inflight": self._global_inflight,
                "peak_global_inflight": self._peak_global_inflight,
                "total_allowed": self._total_allowed,
                "total_rejected": self._total_rejected,
                "rejections": dict(self._rejections),
                "sources": sources,
            }

    def reset_counters(self) -> None:
        """Zero the counters (and per-source table); limits stay in force."""
        with self._lock:
            self._sources.clear()
            self._global_inflight = 0
            self._peak_global_inflight = 0
            self._total_allowed = 0
            self._total_rejected = 0
            self._rejections = {r: 0 for r in REJECT_REASONS}
            self._start = time.monotonic()


class _LazyAdmission:
    """Construct the real controller on first use from current settings.

    Delaying construction keeps ``import app.admission`` free of any
    environment/config binding.
    """

    def __init__(self) -> None:
        self._obj: "Optional[AdmissionController]" = None
        self._guard = threading.Lock()

    def _get(self) -> "AdmissionController":
        obj = self._obj
        if obj is None:
            with self._guard:
                if self._obj is None:
                    from .config import settings

                    self._obj = AdmissionController(
                        rate_per_source=settings.rate_per_source,
                        burst_per_source=settings.burst_per_source,
                        inflight_per_source=settings.inflight_per_source,
                        inflight_global=settings.inflight_global,
                        max_sources=settings.max_sources,
                        enabled=settings.admission_enabled,
                    )
                obj = self._obj
        return obj

    def __getattr__(self, name: str):
        return getattr(self._get(), name)


# One process-wide controller, matching the single embedded DNS listener.
admission = _LazyAdmission()
