import shiva


def test_policy_pack_loader_falls_back_to_builtin_on_invalid_json():
    packs = shiva.PolicyPackLoader.load("{bad", "default")
    assert "default" in packs
    google = packs["default"]["provider_defaults"]["google"]
    assert google["max_inflight"] == 1
    assert google["chunk_cap"] <= 200


def test_policy_pack_applier_clamp_only_budget_and_caps():
    cfg = shiva.BudgetConfig(
        enabled=True,
        provider_max_inflight_default=3,
        provider_max_inflight_map={"google": 3},
        provider_min_gap_s_default=0.0,
        provider_min_gap_s_map={"google": 2.0},
        provider_cooldown_s_default=0.0,
        provider_cooldown_s_map={"google": 30.0},
    )
    pack = {
        "provider_defaults": {
            "google": {"max_inflight": 1, "min_gap_s": 20, "cooldown_s": 120, "delay_floor": 1.0, "chunk_cap": 150, "workers_cap": 3},
            "other": {"max_inflight": 2, "min_gap_s": 0, "cooldown_s": 0, "delay_floor": 0.4, "chunk_cap": 300, "workers_cap": 5},
        }
    }
    applier = shiva.PolicyPackApplier(pack, enforce=True)
    ctx = {"provider_keys": ["google"], "budget_config": cfg, "policy_pack_caps_clamps": {}}
    applied = applier.apply_job_local_overrides(ctx)

    assert cfg.provider_max_inflight_map["google"] == 1
    assert cfg.provider_min_gap_s_map["google"] == 20.0
    assert cfg.provider_cooldown_s_map["google"] == 120.0
    assert ctx["policy_pack_caps_clamps"]["google"]["chunk_size_cap"] == 150
    assert ctx["policy_pack_caps_clamps"]["google"]["delay_floor"] == 1.0
    assert applied["budget_manager"]["google"]["max_inflight"] == 1


def test_resolve_caps_applies_policy_pack_clamps(monkeypatch):
    monkeypatch.setenv("SHIVA_LEARNING_CAPS_ENFORCE", "0")
    monkeypatch.setenv("SHIVA_LANE_STATE_CAPS_ENFORCE", "0")

    caps, meta = shiva.resolve_caps_for_attempt(
        job=None,
        now_ts=1.0,
        lane_key=(0, "gmail.com"),
        base_caps={"chunk_size": 500, "thread_workers": 10, "delay_s": 0.0, "sleep_chunks": 0.0},
        runtime_overrides={"chunk_size": 500, "thread_workers": 10, "delay_s": 0.0, "sleep_chunks": 0.0},
        pressure_caps={},
        health_caps={},
        lane_registry=None,
        learning_engine={},
        probe_selected=False,
        policy_pack_clamps={"chunk_size_cap": 100, "workers_cap": 2, "delay_floor": 0.9},
    )

    assert caps["chunk_size"] == 100
    assert caps["thread_workers"] == 2
    assert caps["delay_s"] >= 0.9
    assert any(step.get("step") == "policy_pack" for step in meta.get("steps") or [])


def test_resolve_caps_tolerates_list_like_numeric_values(monkeypatch):
    monkeypatch.setenv("SHIVA_LEARNING_CAPS_ENFORCE", "0")
    monkeypatch.setenv("SHIVA_LANE_STATE_CAPS_ENFORCE", "0")

    caps, meta = shiva.resolve_caps_for_attempt(
        job=None,
        now_ts=1.0,
        lane_key=(0, "gmail.com"),
        base_caps={"chunk_size": 500, "thread_workers": 10, "delay_s": 0.1, "sleep_chunks": 0.0},
        runtime_overrides={"chunk_size": ["400"], "thread_workers": ["8"], "delay_s": ["0.2"], "sleep_chunks": ["1"]},
        pressure_caps={"level": ["2"], "chunk_size_max": ["200"], "workers_max": ["3"], "delay_min": ["0.5"], "sleep_min": ["2"]},
        health_caps={"level": ["1"], "applied": {"chunk_size": ["150"], "workers": ["2"], "delay_s": ["0.7"], "sleep_chunks": ["3"]}},
        lane_registry=None,
        learning_engine={},
        probe_selected=False,
        policy_pack_clamps={},
    )

    assert caps["chunk_size"] == 150
    assert caps["thread_workers"] == 2
    assert caps["delay_s"] >= 0.7
    assert caps["sleep_chunks"] >= 3.0
    assert any("pmta_level=2" in str(step.get("reason")) for step in (meta.get("steps") or []))
    assert any("health_level=1" in str(step.get("reason")) for step in (meta.get("steps") or []))


def test_policy_pack_applier_tolerates_list_values_in_pack():
    cfg = shiva.BudgetConfig(
        enabled=True,
        provider_max_inflight_default=3,
        provider_max_inflight_map={"google": 3},
        provider_min_gap_s_default=0.0,
        provider_min_gap_s_map={"google": 2.0},
        provider_cooldown_s_default=0.0,
        provider_cooldown_s_map={"google": 30.0},
    )
    pack = {
        "provider_defaults": {
            "google": {
                "max_inflight": ["1"],
                "min_gap_s": 20,
                "cooldown_s": 120,
                "delay_floor": 1.0,
                "chunk_cap": ["150"],
                "workers_cap": ["3"],
            }
        },
        "resource_governor": {"max_total_workers": ["6"]},
    }

    class _Gov:
        max_total_workers = 10

    applier = shiva.PolicyPackApplier(pack, enforce=True)
    ctx = {
        "provider_keys": ["google"],
        "budget_config": cfg,
        "policy_pack_caps_clamps": {},
        "resource_governor": _Gov(),
    }
    applied = applier.apply_job_local_overrides(ctx)

    assert cfg.provider_max_inflight_map["google"] == 1
    assert ctx["policy_pack_caps_clamps"]["google"]["chunk_size_cap"] == 150
    assert ctx["policy_pack_caps_clamps"]["google"]["workers_cap"] == 3
    assert applied["resource_governor"]["max_total_workers"] == 6
