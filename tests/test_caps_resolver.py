import shiva


class _LaneReg:
    def __init__(self, caps):
        self._caps = caps

    def get_lane_info(self, _lane_key):
        return {"state": "THROTTLED", "recommended_caps": dict(self._caps)}


def test_caps_resolver_disabled_learning_lane_probe_clamps(monkeypatch):
    monkeypatch.setenv("SHIVA_LEARNING_CAPS_ENFORCE", "1")
    monkeypatch.setenv("SHIVA_LANE_STATE_CAPS_ENFORCE", "1")
    monkeypatch.setenv("SHIVA_LANE_STATE_CAPS_ONLY_IN_LANE_V2", "1")

    caps, meta = shiva.resolve_caps_for_attempt(
        job=None,
        now_ts=1.0,
        lane_key=(0, "gmail.com"),
        base_caps={"chunk_size": 800, "thread_workers": 12, "delay_s": 0.0, "sleep_chunks": 0.0},
        runtime_overrides={"chunk_size": 700, "thread_workers": 10, "delay_s": 0.05, "sleep_chunks": 0.1, "__scheduler_mode_runtime": "lane_v2"},
        pressure_caps={"level": 2, "chunk_size_max": 600, "workers_max": 8, "delay_min": 0.2, "sleep_min": 0.4},
        health_caps={"level": 2, "applied": {"chunk_size": 500, "workers": 7, "delay_s": 0.3, "sleep_chunks": 0.5}},
        lane_registry=_LaneReg({"chunk_size_cap": 300, "workers_cap": 3, "delay_floor": 0.8, "sleep_floor": 1.1}),
        learning_engine={"chunk_size_cap": 400, "workers_cap": 4, "delay_floor": 0.6},
        probe_selected=True,
    )

    assert caps["chunk_size"] == 80
    assert caps["thread_workers"] == 2
    assert caps["delay_s"] >= 0.8
    assert caps["sleep_chunks"] >= 2.0
    assert meta["lane_state"]["state"] == "THROTTLED"


def test_caps_resolver_lane_caps_respect_scheduler_mode(monkeypatch):
    monkeypatch.setenv("SHIVA_LEARNING_CAPS_ENFORCE", "0")
    monkeypatch.setenv("SHIVA_LANE_STATE_CAPS_ENFORCE", "1")
    monkeypatch.setenv("SHIVA_LANE_STATE_CAPS_ONLY_IN_LANE_V2", "1")

    caps, _ = shiva.resolve_caps_for_attempt(
        job=None,
        now_ts=1.0,
        lane_key=(0, "gmail.com"),
        base_caps={"chunk_size": 500, "thread_workers": 10, "delay_s": 0.0, "sleep_chunks": 0.0},
        runtime_overrides={"chunk_size": 500, "thread_workers": 10, "delay_s": 0.0, "sleep_chunks": 0.0, "__scheduler_mode_runtime": "legacy"},
        pressure_caps={},
        health_caps={},
        lane_registry=_LaneReg({"chunk_size_cap": 120, "workers_cap": 1, "delay_floor": 1.0, "sleep_floor": 2.0}),
        learning_engine={},
        probe_selected=False,
    )

    assert caps["chunk_size"] == 500
    assert caps["thread_workers"] == 10


def test_caps_resolver_tolerates_list_like_numeric_values(monkeypatch):
    monkeypatch.setenv("SHIVA_LEARNING_CAPS_ENFORCE", "0")
    monkeypatch.setenv("SHIVA_LANE_STATE_CAPS_ENFORCE", "0")

    caps, _ = shiva.resolve_caps_for_attempt(
        job=None,
        now_ts=1.0,
        lane_key=(0, "gmail.com"),
        base_caps={"chunk_size": ["400"], "thread_workers": ["6"], "delay_s": ["0.2"], "sleep_chunks": ["0.3"]},
        runtime_overrides={"chunk_size": ["300"], "thread_workers": ["4"], "delay_s": ["0.4"], "sleep_chunks": ["0.5"]},
        pressure_caps={"chunk_size_max": ["200"], "workers_max": ["3"], "delay_min": ["0.8"], "sleep_min": ["1.2"]},
        health_caps={"applied": {"chunk_size": ["150"], "workers": ["2"], "delay_s": ["1.0"], "sleep_chunks": ["2.0"]}},
        lane_registry=None,
    )

    assert caps["chunk_size"] == 150
    assert caps["thread_workers"] == 2
    assert caps["delay_s"] == 1.0
    assert caps["sleep_chunks"] == 2.0
