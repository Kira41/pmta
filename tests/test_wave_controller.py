import shiva


def test_wave_controller_stagger_and_tokens_gate():
    wc = shiva.WaveController(
        enabled=True,
        provider_domain="gmail.com",
        burst_tokens=100,
        refill_per_sec=2.0,
        min_tokens_to_start_chunk=20,
        adaptive_config={"enabled": True, "token_cost_per_msg": 1},
        stagger_config={"enabled": True, "step_s": 10, "seed_mode": "static"},
    )
    wc.start(job_start_ts=100.0, num_senders=3, partition_seed="seed")

    allow0, _ = wc.can_start_lane((0, "gmail.com"), 100.0, planned_chunk_size=20)
    allow1, reason1 = wc.can_start_lane((1, "gmail.com"), 100.0, planned_chunk_size=20)
    assert allow0 is True
    assert allow1 is False
    assert reason1 == "stagger_wait"

    wc.reserve_tokens((0, "gmail.com"), 100.0, planned_cost=90)
    allow2, reason2 = wc.can_start_lane((0, "gmail.com"), 101.0, planned_chunk_size=20)
    assert allow2 is False
    assert reason2 == "wave_tokens"


def test_budget_manager_external_gate_works_with_hint():
    cfg = shiva.BudgetConfig(enabled=True)
    bm = shiva.BudgetManager(cfg)
    bm.register_external_gate(
        "test_gate",
        lambda lane_key, _now, _is_retry, _is_probe, planned_hint: (False, "too_big") if int(planned_hint or 0) > 10 else (True, "allow"),
    )

    ok, _ = bm.can_start((0, "gmail.com"), 1.0, False, False, planned_chunk_size_hint=5)
    deny, reason = bm.can_start((0, "gmail.com"), 1.0, False, False, planned_chunk_size_hint=50)

    assert ok is True
    assert deny is False
    assert reason == "too_big"


def test_budget_manager_sender_inflight_cap_can_be_raised_at_runtime():
    cfg = shiva.BudgetConfig(enabled=True, sender_max_inflight=1, provider_max_inflight_default=5)
    bm = shiva.BudgetManager(cfg)

    bm.on_start((0, "gmail.com"), 1.0)
    deny, reason = bm.can_start((0, "yahoo.com"), 1.1, False, False)
    assert deny is False
    assert reason == "sender_inflight_cap"

    bm.set_sender_max_inflight(3)
    ok, reason2 = bm.can_start((0, "yahoo.com"), 1.2, False, False)
    assert ok is True
    assert reason2 == "allow"
