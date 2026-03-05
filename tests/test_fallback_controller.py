import shiva


class _ActionRecorder:
    def __init__(self):
        self.calls = []

    def disable_concurrency(self):
        self.calls.append("disable_concurrency")

    def disable_probe(self):
        self.calls.append("disable_probe")

    def switch_scheduler_legacy(self):
        self.calls.append("switch_scheduler_legacy")


def _controller(disable_reenable=True):
    return shiva.FallbackController(
        thresholds={
            "deferral_rate": 0.3,
            "hardfail_rate": 0.1,
            "timeout_rate": 0.1,
            "blocked_per_min": 10,
            "pmta_pressure_level": 3,
            "exceptions_per_min": 3,
        },
        window_s=300,
        debug=False,
        disable_reenable=disable_reenable,
        min_active_s=10,
        recovery_s=20,
        actions_config={
            "step1_disable_concurrency": True,
            "step2_disable_probe": True,
            "step3_switch_to_legacy": True,
        },
    )


def test_fallback_triggers_on_deferral_rate_and_applies_ordered_actions():
    fc = _controller()
    fc.observe(0.0, {"attempts_total": 0, "deferrals_4xx": 0}, 0)
    fc.observe(60.0, {"attempts_total": 10, "deferrals_4xx": 5}, 0)

    should, reasons = fc.should_trigger(60.0)
    assert should is True
    assert any("deferral_rate=" in r for r in reasons)

    actions = _ActionRecorder()
    fc.apply_actions(
        {
            "disable_concurrency": actions.disable_concurrency,
            "disable_probe": actions.disable_probe,
            "switch_scheduler_legacy": actions.switch_scheduler_legacy,
        }
    )
    assert actions.calls == ["disable_concurrency", "disable_probe", "switch_scheduler_legacy"]


def test_fallback_disable_reenable_stays_active_for_job():
    fc = _controller(disable_reenable=True)
    fc.observe(0.0, {"attempts_total": 0}, 0)
    fc.observe(60.0, {"attempts_total": 10, "deferrals_4xx": 4}, 0)
    should, _ = fc.should_trigger(60.0)
    assert should is True
    assert fc.is_in_fallback(61.0) is True

    fc.observe(500.0, {"attempts_total": 200, "deferrals_4xx": 4}, 0)
    should2, _ = fc.should_trigger(500.0)
    assert should2 is False
    assert fc.is_in_fallback(500.0) is True


def test_fallback_pmta_pressure_sustained_trigger():
    fc = _controller()
    fc.observe(0.0, {"attempts_total": 0}, 0)
    fc.observe(100.0, {"attempts_total": 0}, 3)
    fc.observe(260.0, {"attempts_total": 0}, 3)

    should, reasons = fc.should_trigger(260.0)
    assert should is True
    assert any("pmta_pressure_high_seconds" in r for r in reasons)
