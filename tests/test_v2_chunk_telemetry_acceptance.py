import shiva


def _new_v2_job(job_id: str) -> shiva.SendJob:
    job = shiva.SendJob(id=job_id, created_at=shiva.now_iso(), campaign_id=f"camp-{job_id}")
    job.status = "running"
    job.debug_parallel_lanes_snapshot = {
        "mode": "v2",
        "lanes": {
            "0|gmail.com": {"status": "running", "lane_state": "processing"},
            "1|yahoo.com": {"status": "running", "lane_state": "processing"},
        },
    }
    return job


def test_v2_multi_sender_parallel_happy_path_transitions_and_live_rows():
    job = _new_v2_job("v2-happy")
    job.chunks_total = 6

    job.begin_chunk_telemetry_v2(
        lane_id="0|gmail.com",
        chunk_id=101,
        sender_idx=0,
        sender_mail="s0@example.com",
        target_domain="gmail.com",
        attempt=0,
        size=10,
        chunk_size=10,
        workers=2,
        delay_s=0.1,
        sleep_chunks=0.0,
        body_format="text",
        reply_to="",
    )
    job.begin_chunk_telemetry_v2(
        lane_id="1|yahoo.com",
        chunk_id=102,
        sender_idx=1,
        sender_mail="s1@example.com",
        target_domain="yahoo.com",
        attempt=0,
        size=10,
        chunk_size=10,
        workers=2,
        delay_s=0.1,
        sleep_chunks=0.0,
        body_format="text",
        reply_to="",
    )

    assert len(job.active_chunks_info) >= 1

    before_done = job.chunks_done
    job.mark_chunk_done_v2(
        lane_id="0|gmail.com",
        chunk_id=101,
        sender_idx=0,
        sender_mail="s0@example.com",
        target_domain="gmail.com",
        attempt=0,
        size=10,
        subject="sub",
        spam_score=1.2,
        blacklist="",
    )

    assert job.chunks_done > before_done
    assert any(str(x.get("status")) == "done" for x in job.chunk_states)


def test_v2_single_provider_multiple_senders_keeps_parallel_lanes_not_sequential():
    job = _new_v2_job("v2-single-provider")
    job.debug_parallel_lanes_snapshot = {
        "mode": "v2",
        "lanes": {
            "0|gmail.com": {"status": "running", "lane_state": "processing"},
            "1|gmail.com": {"status": "running", "lane_state": "processing"},
            "2|gmail.com": {"status": "running", "lane_state": "processing"},
        },
    }
    job.chunks_total = 3

    for sender_idx in range(3):
        job.begin_chunk_telemetry_v2(
            lane_id=f"{sender_idx}|gmail.com",
            chunk_id=200 + sender_idx,
            sender_idx=sender_idx,
            sender_mail=f"s{sender_idx}@example.com",
            target_domain="gmail.com",
            attempt=0,
            size=6,
            chunk_size=6,
            workers=2,
            delay_s=0.1,
            sleep_chunks=0.0,
            body_format="text",
            reply_to="",
        )

    lane_ids = {str(x.get("lane_id") or x.get("lane")) for x in job.active_chunks_info}
    assert len(lane_ids) >= 2
    assert all(lane.endswith("|gmail.com") for lane in lane_ids)


def test_v2_backoff_then_retry_success_done_after_backoff():
    job = _new_v2_job("v2-backoff")
    job.chunks_total = 1

    job.begin_chunk_telemetry_v2(
        lane_id="0|hotmail.com",
        chunk_id=301,
        sender_idx=0,
        sender_mail="s0@example.com",
        target_domain="hotmail.com",
        attempt=0,
        size=5,
        chunk_size=5,
        workers=1,
        delay_s=0.1,
        sleep_chunks=0.0,
        body_format="text",
        reply_to="",
    )
    job.mark_chunk_backoff_v2(
        lane_id="0|hotmail.com",
        chunk_id=301,
        sender_idx=0,
        sender_mail="s0@example.com",
        target_domain="hotmail.com",
        attempt=1,
        size=5,
        reason="preflight_block",
        next_retry_ts=999999,
        spam_score=2.0,
        blacklist="",
    )

    assert job.chunks_backoff == 1
    assert len(job.backoff_items) == 1
    assert any(str(x.get("status")) == "backoff" for x in job.active_chunks_info)

    job.mark_chunk_done_v2(
        lane_id="0|hotmail.com",
        chunk_id=301,
        sender_idx=0,
        sender_mail="s0@example.com",
        target_domain="hotmail.com",
        attempt=1,
        size=5,
        subject="sub",
        spam_score=1.0,
        blacklist="",
    )

    assert any(str(x.get("status")) == "done_after_backoff" for x in job.chunk_states)


def test_v2_abandoned_transition_removes_live_row_and_tracks_counter():
    job = _new_v2_job("v2-abandoned")
    job.chunks_total = 1

    job.begin_chunk_telemetry_v2(
        lane_id="0|outlook.com",
        chunk_id=401,
        sender_idx=0,
        sender_mail="s0@example.com",
        target_domain="outlook.com",
        attempt=2,
        size=4,
        chunk_size=4,
        workers=1,
        delay_s=0.1,
        sleep_chunks=0.0,
        body_format="text",
        reply_to="",
    )
    assert len(job.active_chunks_info) == 1

    job.mark_chunk_abandoned_v2(
        lane_id="0|outlook.com",
        chunk_id=401,
        sender_idx=0,
        sender_mail="s0@example.com",
        target_domain="outlook.com",
        attempt=2,
        size=4,
        reason="sender_domains_exhausted",
        subject="sub",
        spam_score=3.0,
        blacklist="",
        next_retry_ts=0,
    )

    assert job.chunks_abandoned == 1
    assert len(job.active_chunks_info) == 0
    assert any(str(x.get("status")) == "abandoned" for x in job.chunk_states)


def test_v2_job_api_payload_contract_live_and_history_are_renderable():
    client = shiva.app.test_client()
    job = _new_v2_job("v2-api-contract")
    job.chunks_total = 2

    job.begin_chunk_telemetry_v2(
        lane_id="0|gmail.com",
        chunk_id=501,
        sender_idx=0,
        sender_mail="s0@example.com",
        target_domain="gmail.com",
        attempt=0,
        size=8,
        chunk_size=8,
        workers=2,
        delay_s=0.1,
        sleep_chunks=0.0,
        body_format="text",
        reply_to="",
    )
    job.mark_chunk_done_v2(
        lane_id="0|gmail.com",
        chunk_id=501,
        sender_idx=0,
        sender_mail="s0@example.com",
        target_domain="gmail.com",
        attempt=0,
        size=8,
        subject="sub",
        spam_score=1.0,
        blacklist="",
    )

    with shiva.JOBS_LOCK:
        shiva.JOBS[job.id] = job

    try:
        resp = client.get(f"/api/job/{job.id}")
        assert resp.status_code == 200
        body = resp.get_json()

        for required in (
            "chunks_total",
            "chunks_done",
            "chunks_backoff",
            "chunks_abandoned",
            "active_chunks_info",
            "chunk_states",
            "backoff_items",
            "chunk_unique_total",
            "chunk_unique_done",
            "chunk_attempts_total",
            "telemetry_source",
            "v2_telemetry_assertions",
        ):
            assert required in body

        assert isinstance(body["active_chunks_info"], list)
        assert isinstance(body["chunk_states"], list)
        assert isinstance(body["backoff_items"], list)
        assert body["telemetry_source"] == "v2"
        assert body["chunk_unique_total"] >= body["chunk_unique_done"] >= 1
    finally:
        with shiva.JOBS_LOCK:
            shiva.JOBS.pop(job.id, None)


def test_v2_runtime_assertion_flags_empty_live_rows_when_lanes_active(monkeypatch):
    job = _new_v2_job("v2-runtime-assert")
    job.chunks_total = 10

    t = [1000.0]
    monkeypatch.setattr(shiva.time, "time", lambda: t[0])

    job._runtime_assert_v2_chunk_telemetry("first")
    assert job.v2_active_empty_since_ts == 1000.0

    t[0] = 1002.5
    job._runtime_assert_v2_chunk_telemetry("second")

    assert int(job.v2_telemetry_assertions.get("active_chunks_stuck_empty") or 0) >= 1


def test_v2_chunk_telemetry_structured_logs_can_be_enabled(monkeypatch):
    monkeypatch.setenv("SHIVA_V2_CHUNK_TELEMETRY_LOGS", "1")
    job = _new_v2_job("v2-log-flag")

    job.begin_chunk_telemetry_v2(
        lane_id="0|gmail.com",
        chunk_id=777,
        sender_idx=0,
        sender_mail="s0@example.com",
        target_domain="gmail.com",
        attempt=0,
        size=3,
        chunk_size=3,
        workers=1,
        delay_s=0.1,
        sleep_chunks=0.0,
        body_format="text",
        reply_to="",
    )
    job.update_chunk_preflight_v2(
        lane_id="0|gmail.com",
        chunk_id=777,
        sender_idx=0,
        sender_mail="s0@example.com",
        target_domain="gmail.com",
        attempt=0,
        subject="sub",
        body_variant=1,
        spam_score=0.1,
        blacklist="",
    )
    job.mark_chunk_done_v2(
        lane_id="0|gmail.com",
        chunk_id=777,
        sender_idx=0,
        sender_mail="s0@example.com",
        target_domain="gmail.com",
        attempt=0,
        size=3,
        subject="sub",
        spam_score=0.2,
        blacklist="",
    )

    events_blob = "\n".join(str(x.message) for x in (job.logs or []))
    shiva._chunk_telemetry_payload(job)

    events_blob = "\n".join(str(x.message) for x in (job.logs or []))
    assert "begin_chunk_telemetry" in events_blob
    assert "preflight_update" in events_blob
    assert "active_chunk_upsert" in events_blob
    assert "push_chunk_state" in events_blob
    assert "remove_active_chunk" in events_blob
    assert "counter_increment" in events_blob
    assert "api_chunk_telemetry_serialization" in events_blob
    assert '"job_id": "v2-log-flag"' in events_blob
