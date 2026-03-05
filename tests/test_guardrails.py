import shiva


def _plan(**kwargs):
    p = shiva.EffectivePlan(
        scheduler_mode="lane_v2",
        concurrency_enabled=True,
        waves_enabled=True,
        fallback_controller_enabled=False,
        resource_governor_enabled=False,
        backoff_jitter_mode="random",
    )
    for k, v in kwargs.items():
        setattr(p, k, v)
    return p


def test_guardrails_non_strict_clamps_and_warnings():
    validator = shiva.GuardrailsValidator(
        limits={
            "max_parallel_lanes": 8,
            "max_total_workers": 80,
            "max_workers_per_lane": 12,
            "max_chunk_size": 1000,
            "max_delay_s": 5.0,
            "max_min_gap_s": 300.0,
            "max_cooldown_s": 3600,
        },
        strict=False,
    )
    result = validator.validate_plan(
        _plan(),
        {
            "lane_max_parallel": 20,
            "max_total_workers": 120,
            "caps_max_workers": 40,
            "caps_max_chunk": 5000,
            "caps_max_delay_s": 8.0,
            "provider_min_gap_s": 600,
            "provider_cooldown_s": 7200,
            "wave_max_parallel_single_domain": 3,
            "wave_burst_tokens": 900,
            "wave_refill_per_sec": 10.0,
            "backoff_jitter_mode": "random",
            "backoff_jitter_pct": 0.55,
            "rollout_effective_mode": "canary",
            "fallback_controller_enabled_requested": False,
            "resource_governor_enabled_requested": False,
            "guardrails_export": False,
        },
    )

    assert result.ok is True
    assert result.critical_issues
    assert any(c.get("field") == "plan.fallback_controller_enabled" for c in result.clamps_applied)
    assert any(c.get("field") == "backoff_jitter_pct" and c.get("after") == 0.30 for c in result.clamps_applied)


def test_guardrails_strict_blocks_critical():
    validator = shiva.GuardrailsValidator(limits={"max_total_workers": 80}, strict=True)
    result = validator.validate_plan(
        _plan(waves_enabled=False),
        {
            "lane_max_parallel": 5,
            "max_total_workers": 200,
            "caps_max_workers": 10,
            "caps_max_chunk": 100,
            "caps_max_delay_s": 1.0,
            "provider_min_gap_s": 1,
            "provider_cooldown_s": 90,
            "wave_max_parallel_single_domain": 1,
            "wave_burst_tokens": 100,
            "wave_refill_per_sec": 1.0,
            "backoff_jitter_mode": "deterministic",
            "backoff_jitter_pct": 0.1,
            "rollout_effective_mode": "legacy",
            "fallback_controller_enabled_requested": False,
            "resource_governor_enabled_requested": False,
            "guardrails_export": True,
        },
    )

    assert result.ok is False
    assert any("Concurrency" in issue for issue in result.critical_issues)


def test_guardrails_accepts_list_like_numeric_inputs():
    validator = shiva.GuardrailsValidator(limits={"max_total_workers": 80}, strict=True)
    result = validator.validate_plan(
        _plan(waves_enabled=False),
        {
            "lane_max_parallel": ["5"],
            "max_total_workers": ["200"],
            "caps_max_workers": ["10"],
            "caps_max_chunk": ["100"],
            "caps_max_delay_s": ["1.0"],
            "provider_min_gap_s": ["1"],
            "provider_cooldown_s": ["90"],
            "wave_max_parallel_single_domain": ["1"],
            "wave_burst_tokens": ["100"],
            "wave_refill_per_sec": ["1.0"],
            "backoff_jitter_mode": "deterministic",
            "backoff_jitter_pct": ["0.1"],
            "rollout_effective_mode": "legacy",
            "fallback_controller_enabled_requested": False,
            "resource_governor_enabled_requested": False,
            "guardrails_export": True,
        },
    )

    assert result.ok is False
    assert any("Concurrency" in issue for issue in result.critical_issues)
