"""Unit tests for the bounded UDP admission controller.

Covers the token-bucket rate limit, per-source and global inflight
caps, bounded LRU source state (no unbounded accumulation even when the
source address keeps changing), counter/reset behaviour, and release
accounting.
"""
import time

from app.admission import (
    AdmissionController,
    REJECT_GLOBAL_INFLIGHT,
    REJECT_RATE_LIMITED,
    REJECT_SOURCE_INFLIGHT,
)


def make(**kw):
    defaults = dict(
        rate_per_source=10,
        burst_per_source=5,
        inflight_per_source=2,
        inflight_global=4,
        max_sources=3,
    )
    defaults.update(kw)
    return AdmissionController(**defaults)


def test_burst_then_rate_limit_and_refill():
    ac = make(inflight_per_source=100, inflight_global=100)
    # The burst allowance admits exactly burst queries up front.
    for _ in range(5):
        d = ac.check("10.0.0.1")
        assert d.allowed, d
    d = ac.check("10.0.0.1")
    assert not d.allowed and d.reason == REJECT_RATE_LIMITED
    snap = ac.snapshot()
    assert snap["total_allowed"] == 5
    assert snap["total_rejected"] == 1
    assert snap["rejections"][REJECT_RATE_LIMITED] == 1
    # Tokens refill at rate_per_source; wait for roughly one token.
    time.sleep(0.12)  # 10 tokens/sec -> ~1.2 tokens
    assert ac.check("10.0.0.1").allowed
    # The source's own rejected counter is charged.
    src = next(s for s in snap["sources"] if s["source"] == "10.0.0.1")
    assert src["rejected"] == 1 and src["seen"] == 6


def test_per_source_inflight_cap_then_release():
    ac = make(rate_per_source=1000, burst_per_source=1000)
    assert ac.check("a").allowed
    assert ac.check("a").allowed
    third = ac.check("a")
    assert not third.allowed and third.reason == REJECT_SOURCE_INFLIGHT
    # Another source is unaffected: one source cannot starve others.
    assert ac.check("b").allowed
    # Releasing a slot lets the blocked source through again.
    ac.complete("a")
    assert ac.check("a").allowed


def test_global_inflight_cap_is_independent_of_source():
    ac = make(
        rate_per_source=1000,
        burst_per_source=1000,
        inflight_per_source=10,
        inflight_global=2,
        max_sources=10,
    )
    assert ac.check("s1").allowed
    assert ac.check("s2").allowed
    d = ac.check("s3")
    assert not d.allowed and d.reason == REJECT_GLOBAL_INFLIGHT
    assert ac.snapshot()["global_inflight"] == 2
    assert ac.snapshot()["peak_global_inflight"] == 2
    ac.complete("s1")
    assert ac.check("s3").allowed


def test_source_table_is_bounded_under_rotating_addresses():
    ac = make(
        rate_per_source=1000,
        burst_per_source=1000,
        inflight_per_source=10,
        inflight_global=100,
        max_sources=3,
    )
    # Far more distinct sources than the table can hold.
    for i in range(50):
        assert ac.check(f"10.1.{i // 256}.{i % 256}").allowed
    snap = ac.snapshot()
    # State can never grow past the fixed bound despite address churn.
    assert snap["tracked_sources"] == 3
    assert len(snap["sources"]) == 3
    assert ac.snapshot()["tracked_sources"] <= 3


def test_eviction_prefers_idle_entries_and_keeps_inflight_accounting():
    ac = make(
        rate_per_source=1000,
        burst_per_source=1000,
        inflight_per_source=10,
        inflight_global=100,
        max_sources=2,
    )
    assert ac.check("busy1").allowed          # busy1 inflight=1
    assert ac.check("idle1").allowed
    ac.complete("idle1")                       # idle1 inflight=0
    assert ac.check("idle2").allowed           # table full -> evict idle1
    keys = {s["source"] for s in ac.snapshot()["sources"]}
    assert keys == {"busy1", "idle2"}
    # Global inflight still reflects only the two outstanding queries.
    assert ac.snapshot()["global_inflight"] == 2
    ac.complete("busy1")
    ac.complete("idle2")
    assert ac.snapshot()["global_inflight"] == 0


def test_reset_clears_counters_and_table_but_keeps_limits():
    ac = make(max_sources=4)
    ac.check("x")
    ac.check("x")
    ac.reset_counters()
    snap = ac.snapshot()
    assert snap["tracked_sources"] == 0
    assert snap["total_allowed"] == 0
    assert snap["total_rejected"] == 0
    assert snap["global_inflight"] == 0
    # Limits are still in force after reset.
    assert ac.check("y").allowed
    assert snap["config"]["max_tracked_sources"] == 4


def test_complete_on_unknown_or_over_released_source_is_safe():
    ac = make()
    ac.complete("never-seen")   # must not raise
    ac.complete("never-seen")
    assert ac.snapshot()["global_inflight"] == 0


def test_lru_recently_used_source_is_not_evicted_first():
    ac = make(
        rate_per_source=1000,
        burst_per_source=1000,
        inflight_per_source=10,
        inflight_global=100,
        max_sources=2,
    )
    ac.check("old")
    ac.check("new")
    ac.complete("old")
    ac.complete("new")
    # Touch "old" so "new" becomes the LRU; both are idle on eviction.
    ac.check("old")
    ac.complete("old")
    ac.check("third")  # forces one eviction
    keys = {s["source"] for s in ac.snapshot()["sources"]}
    assert "old" in keys and "new" not in keys
