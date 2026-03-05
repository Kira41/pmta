import shiva


def test_normalize_accounting_event_maps_outcomes():
    ev = shiva.normalize_accounting_event({"job_id": "J1", "rcpt": "u@gmail.com", "outcome": "D"})
    assert ev is not None
    assert ev["outcome"] == "DELIVERED"
    assert ev["rcpt_domain"] == "gmail.com"


def test_accounting_recon_dedupes_repeated_polls(tmp_path, monkeypatch):
    dbp = tmp_path / "recon.sqlite"
    monkeypatch.setenv("SHIVA_DB_PATH", str(dbp))
    monkeypatch.setenv("DB_PATH", str(dbp))
    shiva.db_init()

    jid = "job-recon-1"
    event = {
        "event_id": "evt-1",
        "job_id": jid,
        "rcpt": "a@gmail.com",
        "outcome": "delivered",
        "time_logged": shiva.now_iso(),
        "message_id": "",
        "dsn_status": "",
        "dsn_diag": "ok",
        "source_file": "acct.csv",
        "source_offset_or_line": "1",
        "raw_json": '{"sender":"sender@example.com"}',
    }
    assert shiva.db_insert_accounting_event(event) is True

    lm = shiva.LaneMetrics(window=20, use_ema=False)
    lr = shiva.LaneRegistry(thresholds={}, quarantine_base_s=60, quarantine_max_s=300)
    engine = shiva.AccountingReconEngine(
        job_id=jid,
        lane_metrics=lm,
        lane_registry=lr,
        sender_idx_by_rcpt={"a@gmail.com": 2},
        export=True,
    )

    job = shiva.SendJob(id=jid, created_at=shiva.now_iso())
    d1 = engine.poll_and_update(job, 1.0)
    d2 = engine.poll_and_update(job, 2.0)

    assert d1["delivered"] == 1
    assert d2["delivered"] == 0
    snap = lm.snapshot()
    lane = snap["lanes"]["2|gmail.com"]
    assert lane["acct_delivered"] == 1
    assert lane["acct_total"] == 1
