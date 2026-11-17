"""Authoritative UDP DNS service for the fixed intranet zone.

Every answer is built from one immutable version snapshot fetched in a
single storage read, so a reply can never mix records of two versions.
While a transfer is in progress the old version stays active and keeps
being answered.

Concurrency / overload model
----------------------------
The stock dnslib UDP server uses ``ThreadingMixIn``: it spawns one new
thread per datagram into an unbounded queue, so a single flooding source
can exhaust the process and starve everyone else. This service instead
uses:

* one fixed listener thread that owns the socket and performs *all*
  admission checks up-front — a rejected query is answered with
  SERVFAIL right there and never reaches a worker or a queue;
* one fixed-size worker pool (``DNS_WORKERS``) plus a global inflight
  ceiling, so the number of threads and queued work items is bounded
  regardless of the packet rate;
* per-source token-bucket, per-source inflight and bounded LRU source
  state implemented in :mod:`app.admission`.

Out-of-zone queries are answered inline (REFUSED) by the listener and do
not consume any worker capacity, while admitted in-zone queries are still
resolved from the local immutable full-zone version.
"""
from __future__ import annotations

import logging
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple

from dnslib import A, DNSRecord, RR, QTYPE, RCODE

from .admission import admission
from .config import settings
from .storage import storage

log = logging.getLogger("dns")


def _normalise(qname: str) -> str:
    return qname.rstrip(".").lower()


def _is_in_zone(qname: str) -> bool:
    zone = settings.dns_zone.rstrip(".").lower()
    return qname == zone or qname.endswith("." + zone)


def _servfail(raw: bytes) -> bytes:
    try:
        request = DNSRecord.parse(raw)
        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        return reply.pack()
    except Exception:
        return b""


class ZoneResolver:
    """Pure, side-effect-free zone lookup; safe to run in a worker thread."""

    def resolve(self, request: DNSRecord) -> DNSRecord:
        reply = request.reply()
        q = request.q
        qname = _normalise(str(q.qname))

        if not _is_in_zone(qname):
            # This service is authoritative only for the fixed zone.
            reply.header.rcode = RCODE.REFUSED
            return reply

        if QTYPE[q.qtype] != "A":
            # In-zone but not an A query: authoritative NOERROR/NODATA.
            reply.header.rcode = RCODE.NOERROR
            return reply

        # One consistent snapshot -> one version per answer.
        serial, records, _ = storage.get_active_version()
        name_map = {}
        for rec in records:
            name_map.setdefault(rec["name"], []).append(rec["ip"])

        ips: List[str] = name_map.get(qname, [])
        if not ips:
            reply.header.rcode = RCODE.NXDOMAIN
            log.debug("NXDOMAIN %s (serial=%s)", qname, serial)
            return reply

        for ip in ips:
            reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(ip), ttl=30))
        log.debug("ANSWER %s -> %s (serial=%s)", qname, ips, serial)
        return reply


class DnsService:
    """Bounded threaded UDP DNS service with local admission control."""

    def __init__(self) -> None:
        self._sock: Optional[socket.socket] = None
        self._listener: Optional[threading.Thread] = None
        self._pool: Optional[ThreadPoolExecutor] = None
        self._stopping = threading.Event()
        # Packets that cannot even be parsed as DNS; counted separately and
        # never fed to admission (no trustworthy source identity/query).
        self._malformed = 0
        self._internal_errors = 0
        self._stat_lock = threading.Lock()

    # -------------------------------------------------------------- start
    def start(self) -> None:
        resolver = ZoneResolver()
        # The pool size never exceeds the global inflight ceiling, so the
        # maximum queued work is (global_cap - workers): a fixed bound.
        workers = max(1, min(settings.dns_workers, admission.global_cap))
        self._pool = ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="dns-worker",
        )
        self._stopping.clear()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        except OSError:  # pragma: no cover - tuning hint only
            pass
        sock.bind((settings.dns_host, settings.dns_port))
        self._sock = sock

        self._listener = threading.Thread(
            target=self._serve_loop,
            name="dns-udp-listener",
            args=(sock, resolver),
            daemon=True,
        )
        self._listener.start()
        log.info(
            "UDP DNS listener on %s:%s (zone=%s, role=%s, workers=%s, "
            "admission=%s rate=%s/s burst=%s per_src_inflight=%s "
            "global_inflight=%s max_sources=%s)",
            settings.dns_host,
            settings.dns_port,
            settings.dns_zone,
            settings.role,
            workers,
            settings.admission_enabled,
            admission.rate,
            admission.burst,
            admission.per_source_cap,
            admission.global_cap,
            admission.max_sources,
        )

    # ------------------------------------------------------- listener loop
    def _serve_loop(self, sock: socket.socket, resolver: ZoneResolver) -> None:
        while not self._stopping.is_set():
            try:
                data, addr = sock.recvfrom(65535)
            except OSError:
                if self._stopping.is_set():
                    return
                continue
            self._dispatch(sock, data, addr, resolver)

    def _dispatch(
        self,
        sock: socket.socket,
        data: bytes,
        addr: Tuple[str, int],
        resolver: ZoneResolver,
    ) -> None:
        # Identity is the source IP address only. Rotating ephemeral source
        # ports from one host therefore cannot dodge the per-source limits.
        source = addr[0]
        try:
            request = DNSRecord.parse(data)
            qname = _normalise(str(request.q.qname))
        except Exception:
            with self._stat_lock:
                self._malformed += 1
            log.warning("malformed datagram from %s (%d bytes)", addr, len(data))
            return

        # Out-of-zone traffic is cheap and handled inline by the listener,
        # so it neither consumes workers nor enters admission bookkeeping.
        if not _is_in_zone(qname):
            try:
                sock.sendto(resolver.resolve(request).pack(), addr)
            except OSError:
                pass
            return

        # Admission happens BEFORE any thread/queue allocation.
        counted = False
        if settings.admission_enabled:
            decision = admission.check(source)
            if not decision.allowed:
                log.info(
                    "SERVFAIL admission reject source=%s reason=%s qname=%s",
                    source,
                    decision.reason,
                    qname,
                )
                payload = _servfail(data)
                if payload:
                    try:
                        sock.sendto(payload, addr)
                    except OSError:
                        pass
                return
            counted = True

        # Bounded hand-off: admission already guarantees global inflight is
        # below the fixed ceiling, so this queue can never grow unbounded.
        assert self._pool is not None
        try:
            self._pool.submit(self._worker, resolver, request, addr, source,
                              counted)
        except RuntimeError:
            # Pool shut down while draining: release the slot and answer
            # SERVFAIL best-effort instead of dropping silently.
            if counted:
                admission.complete(source)
            payload = _servfail(data)
            if payload:
                try:
                    sock.sendto(payload, addr)
                except OSError:
                    pass

    # -------------------------------------------------------------- worker
    def _worker(
        self,
        resolver: ZoneResolver,
        request: DNSRecord,
        addr: Tuple[str, int],
        source: str,
        counted: bool,
    ) -> None:
        payload: Optional[bytes] = None
        try:
            payload = resolver.resolve(request).pack()
        except Exception:
            with self._stat_lock:
                self._internal_errors += 1
            log.exception("resolver failure for source=%s", source)
            payload = _servfail(request.pack())
        finally:
            if counted:
                admission.complete(source)
        if payload and self._sock is not None:
            try:
                self._sock.sendto(payload, addr)
            except OSError:
                pass

    # --------------------------------------------------------------- stats
    def stats(self) -> dict:
        with self._stat_lock:
            return {
                "malformed_packets": self._malformed,
                "internal_errors": self._internal_errors,
            }

    def reset_stats(self) -> None:
        with self._stat_lock:
            self._malformed = 0
            self._internal_errors = 0

    # ---------------------------------------------------------------- stop
    def stop(self) -> None:
        self._stopping.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._listener is not None:
            self._listener.join(timeout=5)
        if self._pool is not None:
            # Drain already-admitted queries briefly, then cancel the rest.
            self._pool.shutdown(wait=True, cancel_futures=True)
        self._sock = None
        self._listener = None
        self._pool = None


dns_service = DnsService()
