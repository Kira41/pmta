import shiva


def _init_test_db(tmp_path):
    shiva.DB_PATH = str(tmp_path / "recipient_indexing.sqlite")
    shiva.db_init()


def test_seed_recipients_create_initial_not_yet_and_can_transition(tmp_path):
    _init_test_db(tmp_path)
    jid = "job-seed-1"

    inserted = shiva.db_seed_job_recipient_index(jid, "camp-1", ["A@example.com", "a@example.com", "b@example.com"])
    assert inserted == 2

    assert shiva.db_get_outcome(jid, "a@example.com")["status"] == "not_yet"
    assert shiva.db_get_outcome(jid, "b@example.com")["status"] == "not_yet"

    job = shiva.SendJob(id=jid, created_at=shiva.now_iso(), campaign_id="camp-1", total=2)
    shiva._apply_outcome_to_job(job, "a@example.com", "delivered", {})

    assert job.delivered == 1
    assert shiva.db_get_outcome(jid, "a@example.com")["status"] == "delivered"


def test_bridge_sync_keeps_not_yet_recipients_when_partial_payload(tmp_path):
    _init_test_db(tmp_path)
    jid = "job-seed-2"
    shiva.db_seed_job_recipient_index(jid, "camp-2", ["a@example.com", "b@example.com"])

    shiva._bridge_sync_job_outcomes(jid, {"delivered": {"emails": ["a@example.com"]}})

    assert shiva.db_get_outcome(jid, "a@example.com")["status"] == "delivered"
    assert shiva.db_get_outcome(jid, "b@example.com")["status"] == "not_yet"


def test_done_job_with_pending_recipients_stays_in_bridge_poll_scope(tmp_path):
    _init_test_db(tmp_path)
    jid = "job-seed-3"
    shiva.db_seed_job_recipient_index(jid, "camp-3", ["a@example.com", "b@example.com"])
    shiva.db_set_outcome(jid, "a@example.com", "delivered")

    job = shiva.SendJob(id=jid, created_at=shiva.now_iso(), campaign_id="camp-3", total=2, status="done")
    with shiva.JOBS_LOCK:
        shiva.JOBS.clear()
        shiva.JOBS[jid] = job

    polled_ids = {j.id for j in shiva._active_jobs_for_bridge_poll()}
    assert jid in polled_ids
