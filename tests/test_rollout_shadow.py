import shiva


def test_rollout_decider_canary_deterministic():
    decider = shiva.RolloutDecider(
        mode="canary",
        canary_percent=100,
        allowlists={"campaigns": set(), "senders": set()},
        denylists={"campaigns": {"camp-deny"}},
        seed_mode="job_id",
    )
    job = type("JobStub", (), {"id": "job-123", "campaign_id": "camp-ok"})()
    out = decider.decide(job, sender_emails=["s@sender.com"], force_legacy=False)
    assert out["effective_mode"] == "v2"

    denied = type("JobStub", (), {"id": "job-123", "campaign_id": "camp-deny"})()
    out_denied = decider.decide(denied, sender_emails=["s@sender.com"], force_legacy=False)
    assert out_denied["effective_mode"] == "legacy"


def test_shadow_recorder_ring_buffer_bound():
    recorder = shiva.ShadowRecorder(max_events=3)
    for idx in range(5):
        recorder.record("e", {"i": idx})
    snap = recorder.snapshot()
    assert len(snap) == 3
    assert [x["payload"]["i"] for x in snap] == [2, 3, 4]


def test_rollout_selftests_smoke():
    logs = shiva._run_rollout_selftests()
    assert "determinism_ok" in logs
    assert "legacy_off_mode_ok" in logs
    assert "shadow_purity_ok" in logs
