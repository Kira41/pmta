import shiva


def test_global_resource_governor_budget_and_release():
    gov = shiva.GlobalResourceGovernor(
        max_total_workers=10,
        pmta_scale_config={"enabled": True, "level2_factor": 0.75, "level3_factor": 0.5},
    )

    ok, _ = gov.can_reserve(8, 1.0, pmta_pressure_level=0)
    assert ok is True
    gov.reserve(8, (0, "gmail.com"), 1.0)

    deny, reason = gov.can_reserve(3, 2.0, pmta_pressure_level=0)
    assert deny is False
    assert "workers_budget" in reason

    deny_l2, _ = gov.can_reserve(1, 2.0, pmta_pressure_level=2)
    assert deny_l2 is False

    gov.release(8, (0, "gmail.com"), 3.0)
    snap = gov.snapshot()
    assert snap["total_workers_inflight"] == 0


def test_lane_executor_releases_budget_and_governor_on_exception():
    cfg = shiva.BudgetConfig(enabled=True)
    bm = shiva.BudgetManager(cfg)
    gov = shiva.GlobalResourceGovernor(max_total_workers=20)
    ex = shiva.LaneExecutor(max_parallel_lanes=1, lane_picker_v2=None, budget_mgr=bm, locks={}, governor=gov)

    picks = [((0, "gmail.com"), {"pick_type": "normal"})]

    def pick_lane(_now):
        if picks:
            return picks.pop(0)
        return None, {}

    def task_fn(*_args, **_kwargs):
        raise RuntimeError("boom")

    ex.submit_ready_tasks(
        1.0,
        {
            "pick_lane": pick_lane,
            "task_fn": task_fn,
            "thread_workers_default": 5,
            "resolve_caps": lambda *_: ({"thread_workers": 5}, {}),
        },
    )
    ex.poll_completed_tasks(5.0, lambda *_: None, lambda *_: None)

    assert bm.snapshot()["inflight_by_provider"] == {}
    assert gov.snapshot()["total_workers_inflight"] == 0
