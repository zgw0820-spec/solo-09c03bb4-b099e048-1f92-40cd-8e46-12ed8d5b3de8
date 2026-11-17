"""Overload self-test for UDP admission control (real uvicorn process).

Run with the project venv:  .venv/bin/python -I tests/admission_overload_test.py

Scenarios:
  1. flood from one source -> excess queries get SERVFAIL, not silence;
  2. while the flood runs, OTHER source IPs still get authoritative answers
     (a single source cannot occupy the service);
  3. rotating source addresses cannot grow state past MAX_TRACKED_SOURCES;
  4. worker/thread count stays bounded during and after the flood;
  5. reject counters are exposed on GET /api/admission and can be reset;
  6. an admitted query is still answered from the local full-zone version,
     and zone publishing (primary) keeps working under the flood.

Multiple 127.0.0.0/8 loopback addresses are used as distinct source IPs
(an unprivileged process cannot spoof non-loopback source addresses).
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
from dnslib import DNSRecord, RCODE

ROOT = Path(__file__).resolve().parent.parent
PY = str(ROOT / ".venv" / "bin" / "python")
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)

ZONE = "internal.local"
API = "http://127.0.0.1:18020"
DNS = ("127.0.0.1", 15060)

# Tight, deterministic limits for the test instance.
RATE, BURST = 5, 8
SRC_CAP, GLOBAL_CAP, MAX_SRC, WORKERS = 2, 12, 8, 4

failures = []


def check(name, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + name +
          (" " + detail if not cond and detail else ""))
    if not cond:
        failures.append(name)


def wait_http(url, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=1.5).status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.3)
    raise RuntimeError(url)


def start_primary():
    env = os.environ.copy()
    env.update({
        "DNS_ROLE": "primary", "DNS_ZONE": ZONE,
        "DB_PATH": str(DATA / "primary-overload.db"),
        "DNS_HOST": "127.0.0.1", "DNS_PORT": str(DNS[1]),
        "API_HOST": "127.0.0.1", "API_PORT": "18020",
        "ADMISSION_ENABLED": "true",
        "RATE_LIMIT_PER_SOURCE": str(RATE),
        "RATE_BURST_PER_SOURCE": str(BURST),
        "INFLIGHT_PER_SOURCE": str(SRC_CAP),
        "INFLIGHT_GLOBAL": str(GLOBAL_CAP),
        "MAX_TRACKED_SOURCES": str(MAX_SRC),
        "DNS_WORKERS": str(WORKERS),
        "PYTHONUNBUFFERED": "1",
    })
    log = open(DATA / "primary-overload.log", "w")
    return subprocess.Popen(
        [PY, "-I", "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", "18020"],
        cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT)


def stop(p):
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()


def query_from(source_ip, name, qtype="A", timeout=2.0):
    """Send one UDP query with an explicit loopback source IP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.bind((source_ip, 0))
        sock.sendto(DNSRecord.question(name, qtype).pack(), DNS)
        data, _ = sock.recvfrom(65535)
        return DNSRecord.parse(data)
    finally:
        sock.close()


def count_threads(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/task"))
    except OSError:
        return -1


def flood(source_ip, datagrams):
    """Best-effort UDP flood from one source; collect rcode histogram."""
    hist = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    try:
        sock.bind((source_ip, 0))
        q = DNSRecord.question(f"db.{ZONE}").pack()
        for _ in range(datagrams):
            try:
                sock.sendto(q, DNS)
            except OSError:
                pass
        # Drain whatever replies arrive within a short window.
        sock.settimeout(0.3)
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                data, _ = sock.recvfrom(65535)
                rc = DNSRecord.parse(data).header.rcode
                hist[rc] = hist.get(rc, 0) + 1
            except socket.timeout:
                break
            except OSError:
                break
    finally:
        sock.close()
    return hist


def main():
    for suffix in ("", "-wal", "-shm"):
        p = DATA / ("primary-overload.db" + suffix)
        if p.exists():
            p.unlink()

    proc = start_primary()
    try:
        wait_http(f"{API}/health")
        time.sleep(0.5)
        pid = proc.pid
        threads_idle = count_threads(pid)

        print("[1] publish a zone, then verify a normal authoritative answer")
        r = httpx.post(f"{API}/api/zone", json={"records": [
            {"name": f"db.{ZONE}", "ip": "10.0.0.11"}]}, timeout=5)
        check("publish 201 serial 1", r.status_code == 201
              and r.json()["serial"] == 1, r.text)
        ans = query_from("127.0.0.2", f"db.{ZONE}")
        check("normal query answered from local full version",
              ans.header.rcode == RCODE.NOERROR
              and [str(x.rdata) for x in ans.rr] == ["10.0.0.11"], str(ans))

        print("[2] one-source flood: excess must be SERVFAIL, not silence")
        httpx.post(f"{API}/api/admission/reset", timeout=5)
        hist = flood("127.0.0.1", 400)
        servfail = hist.get(RCODE.SERVFAIL, 0)
        noerror = hist.get(RCODE.NOERROR, 0)
        check("flood produces SERVFAIL replies", servfail > 0,
              f"hist={hist}")
        check("some flood queries are still admitted (NOERROR)",
              noerror > 0, f"hist={hist}")
        snap = httpx.get(f"{API}/api/admission", timeout=5).json()
        check("API total_rejected matches SERVFAIL behaviour",
              snap["total_rejected"] >= servfail and snap["total_rejected"] > 0,
              json.dumps(snap["rejections"]))
        check("rejection reasons are enumerated per cause",
              all(k in snap["rejections"] for k in (
                  "rate_limited", "source_inflight_full",
                  "global_inflight_full")))
        check("at least one rejection reason counter is non-zero",
              any(v > 0 for v in snap["rejections"].values()))
        check("global inflight returns to zero after flood drains",
              snap["global_inflight"] == 0, str(snap["global_inflight"]))

        print("[3] fairness: other sources keep getting answers DURING flood")
        httpx.post(f"{API}/api/admission/reset", timeout=5)
        ok_other = 0
        rounds = 4
        for i in range(rounds):
            # Kick a flood from the bad source, then query from other IPs.
            flood("127.0.0.1", 200)
            for src in ("127.0.0.2", "127.0.0.3", "127.0.0.4"):
                try:
                    rep = query_from(src, f"db.{ZONE}", timeout=2.0)
                    if rep.header.rcode == RCODE.NOERROR and \
                            [str(x.rdata) for x in rep.rr] == ["10.0.0.11"]:
                        ok_other += 1
                except Exception:
                    pass
        check(f"other sources answered {ok_other}/{rounds * 3} under flood",
              ok_other == rounds * 3, f"only {ok_other}")

        print("[4] bounded source state despite rotating source addresses")
        httpx.post(f"{API}/api/admission/reset", timeout=5)
        # Use far more distinct loopback source IPs than MAX_TRACKED_SOURCES.
        for i in range(2, 32):  # 127.0.0.2 .. 127.0.0.31 (30 sources)
            try:
                query_from(f"127.0.0.{i}", f"host{i}.{ZONE}", timeout=1.0)
            except Exception:
                pass
        snap = httpx.get(f"{API}/api/admission", timeout=5).json()
        check("tracked_sources never exceeds the fixed bound",
              snap["tracked_sources"] <= MAX_SRC
              and len(snap["sources"]) <= MAX_SRC,
              f"tracked={snap['tracked_sources']} bound={MAX_SRC}")
        check("reject counters survive the churn",
              snap["total_allowed"] > 0)

        print("[5] thread/worker count stays bounded")
        # Snapshot thread count during an active flood.
        import threading
        t = threading.Thread(target=lambda: flood("127.0.0.1", 300))
        t.start()
        time.sleep(0.4)
        threads_flood = count_threads(pid)
        t.join()
        time.sleep(0.5)
        threads_after = count_threads(pid)
        # Listener + worker pool + uvicorn/main threads; allow small slack.
        bound = threads_idle + WORKERS + 3
        check(f"threads bounded during flood ({threads_flood} <= {bound})",
              0 < threads_flood <= bound,
              f"idle={threads_idle} flood={threads_flood}")
        check("thread count does not keep growing after flood",
              0 < threads_after <= bound, f"after={threads_after}")

        print("[6] publishing stays available while UDP is flooded")
        t = threading.Thread(target=lambda: flood("127.0.0.1", 300))
        t.start()
        t0 = time.time()
        r = httpx.post(f"{API}/api/zone", json={"records": [
            {"name": f"db.{ZONE}", "ip": "10.0.0.12"},
            {"name": f"web.{ZONE}", "ip": "10.0.0.22"}]}, timeout=8)
        elapsed = time.time() - t0
        t.join()
        check("publish succeeds during flood (serial 2)",
              r.status_code == 201 and r.json()["serial"] == 2
              and elapsed < 5.0, f"{r.status_code} {elapsed:.2f}s")
        # Admitted queries now reflect the new full version (no mixed answers).
        rep = query_from("127.0.0.5", f"web.{ZONE}", timeout=2.0)
        check("new version answered atomically after publish",
              rep.header.rcode == RCODE.NOERROR
              and [str(x.rdata) for x in rep.rr] == ["10.0.0.22"], str(rep))

        print("[7] reset endpoint zeroes the counters")
        httpx.post(f"{API}/api/admission/reset", timeout=5)
        snap = httpx.get(f"{API}/api/admission", timeout=5).json()
        check("counters and source table reset",
              snap["total_rejected"] == 0 and snap["total_allowed"] == 0
              and snap["tracked_sources"] == 0
              and snap["global_inflight"] == 0, json.dumps(snap))
        check("limits remain configured after reset",
              snap["config"]["max_tracked_sources"] == MAX_SRC
              and snap["config"]["inflight_global"] == GLOBAL_CAP)

        print("[8] malformed packets are counted but never crash the service")
        before = httpx.get(f"{API}/api/admission", timeout=5).json()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"\x12\x34not-a-dns-packet", DNS)
        sock.sendto(b"", DNS)
        sock.close()
        time.sleep(0.5)
        after = httpx.get(f"{API}/api/admission", timeout=5).json()
        check("malformed_packets counter advanced",
              after["malformed_packets"] >= before["malformed_packets"] + 1,
              f"{before['malformed_packets']} -> {after['malformed_packets']}")
        check("service still healthy after garbage input",
              httpx.get(f"{API}/health", timeout=3).status_code == 200)
    finally:
        stop(proc)

    print(f"\n==== overload checks: {len(failures)} failures ====")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
