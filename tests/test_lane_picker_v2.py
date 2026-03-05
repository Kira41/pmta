import random

import shiva


class _StubLaneRegistry:
    def __init__(self, states=None):
        self.states = states or {}

    def get_lane_info(self, lane_key):
        return self.states.get(tuple(lane_key), {"state": "HEALTHY", "next_allowed_ts": 0.0})


class _StubBudget:
    def __init__(self, denies=None):
        self.denies = denies or {}

    def can_start(self, lane_key, now_ts, is_retry, is_probe):
        key = (tuple(lane_key), bool(is_retry), bool(is_probe))
        if key in self.denies:
            return False, self.denies[key]
        return True, "allow"


def test_lane_picker_v2_prefers_retry_ready_first():
    picker = shiva.LanePickerV2(scheduler_rng=random.Random(7), use_soft_bias=False)

    sender_buckets = {
        0: {"gmail.com": ["a@gmail.com", "b@gmail.com"], "yahoo.com": ["a@yahoo.com"]},
        1: {"gmail.com": ["c@gmail.com"]},
    }
    retries = {
        "0|yahoo.com": [{"next_retry_ts": 10.0, "chunk": ["retry@yahoo.com"]}],
        "1|gmail.com": [{"next_retry_ts": 999.0, "chunk": ["later@gmail.com"]}],
    }

    lane, meta = picker.pick_next(
        now_ts=15.0,
        sender_cursor=0,
        sender_buckets=sender_buckets,
        provider_retry_chunks=retries,
    )

    assert lane == (0, "yahoo.com")
    assert meta["pick_type"] == "retry"


def test_lane_picker_v2_skips_quarantine_and_budget_denials_then_picks_weighted():
    reg = _StubLaneRegistry({
        (0, "gmail.com"): {"state": "QUARANTINED", "next_allowed_ts": 100.0},
        (0, "yahoo.com"): {"state": "HEALTHY", "next_allowed_ts": 0.0},
    })
    budget = _StubBudget({
        ((0, "yahoo.com"), False, False): "provider_min_gap",
    })
    picker = shiva.LanePickerV2(
        scheduler_rng=random.Random(2),
        lane_registry=reg,
        budget_mgr=budget,
        respect_lane_states=True,
        use_budgets=True,
        use_soft_bias=False,
    )

    sender_buckets = {
        0: {
            "gmail.com": ["a@gmail.com", "b@gmail.com"],
            "yahoo.com": ["a@yahoo.com"],
        },
        1: {
            "hotmail.com": ["h1@hotmail.com", "h2@hotmail.com"],
        },
    }

    lane, meta = picker.pick_next(
        now_ts=20.0,
        sender_cursor=0,
        sender_buckets=sender_buckets,
        provider_retry_chunks={},
        probe_active=False,
    )

    assert lane == (1, "hotmail.com")
    assert meta["pick_type"] == "weighted"
    reasons = {f"{x['lane']}:{x['reason']}" for x in meta.get("denied_reasons", [])}
    assert "0|gmail.com:lane_quarantine_until" in reasons
    assert "0|yahoo.com:provider_min_gap" in reasons
