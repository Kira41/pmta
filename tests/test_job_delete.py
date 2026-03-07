import shiva


def _init_test_db(tmp_path):
    shiva.DB_PATH = str(tmp_path / "job_delete.sqlite")
    shiva.db_init()


def test_db_delete_job_removes_job_and_related_rows_and_pending_snapshots(tmp_path):
    _init_test_db(tmp_path)
    jid = "job-del-1"

    job = shiva.SendJob(id=jid, created_at=shiva.now_iso(), campaign_id="camp-del", status="done")
    shiva.db_upsert_job(job)
    shiva.db_set_outcome(jid, "a@example.com", "delivered")
    shiva.db_seed_job_recipient_index(jid, "camp-del", ["a@example.com"])

    with shiva.DB_LOCK:
        conn = shiva._db_conn()
        try:
            conn.execute(
                "INSERT INTO accounting_events(event_id, job_id, rcpt, outcome, time_logged, message_id, dsn_status, dsn_diag, source_file, source_offset_or_line, created_at, raw_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "ev-del-1",
                    jid,
                    "a@example.com",
                    "delivered",
                    shiva.now_iso(),
                    "msg-1",
                    "",
                    "",
                    "file.csv",
                    "1",
                    shiva.now_iso(),
                    "{}",
                ),
            )
            conn.execute(
                "INSERT INTO email_attempt_logs(series_id, job_id, campaign_id, chunk_idx, sender_domain, provider_domain, attempt_number, outcome, attempt_ts, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("s1", jid, "camp-del", 0, "sender.tld", "provider.tld", 1, "delivered", shiva.now_iso(), shiva.now_iso()),
            )
            conn.execute(
                "INSERT INTO email_attempt_learning(series_id, job_id, campaign_id, chunk_idx, sender_domain, provider_domain, attempts_taken, outcome, first_attempt_ts, last_attempt_ts, duration_seconds, created_at, updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("s1", jid, "camp-del", 0, "sender.tld", "provider.tld", 1, "delivered", shiva.now_iso(), shiva.now_iso(), 1.0, shiva.now_iso(), shiva.now_iso()),
            )
            conn.commit()
        finally:
            conn.close()

    target_item = {
        "kind": "job_snapshot",
        "payload": {"id": jid, "campaign_id": "camp-del", "snapshot": "{}", "status": "done"},
    }
    other_item = {
        "kind": "job_snapshot",
        "payload": {"id": "job-keep", "campaign_id": "camp-del", "snapshot": "{}", "status": "done"},
    }

    with shiva._DB_WRITE_LOCK:
        shiva._DB_WRITE_RETRY.append(dict(target_item))
        shiva._DB_WRITE_RETRY.append(dict(other_item))

    q = shiva._DB_WRITE_QUEUE
    with q.mutex:
        q.queue.append(dict(target_item))
        q.queue.append(dict(other_item))
        q.unfinished_tasks = int(q.unfinished_tasks or 0) + 2

    shiva.db_delete_job(jid)

    with shiva.DB_LOCK:
        conn = shiva._db_conn()
        try:
            assert conn.execute("SELECT COUNT(*) FROM jobs WHERE id=?", (jid,)).fetchone()[0] == 0
            assert conn.execute("SELECT COUNT(*) FROM deleted_jobs WHERE job_id=?", (jid,)).fetchone()[0] == 1
            assert conn.execute("SELECT COUNT(*) FROM job_outcomes WHERE job_id=?", (jid,)).fetchone()[0] == 0
            assert conn.execute("SELECT COUNT(*) FROM job_recipients WHERE job_id=?", (jid,)).fetchone()[0] == 0
            assert conn.execute("SELECT COUNT(*) FROM accounting_events WHERE job_id=?", (jid,)).fetchone()[0] == 0
            assert conn.execute("SELECT COUNT(*) FROM email_attempt_logs WHERE job_id=?", (jid,)).fetchone()[0] == 0
            assert conn.execute("SELECT COUNT(*) FROM email_attempt_learning WHERE job_id=?", (jid,)).fetchone()[0] == 0
        finally:
            conn.close()

    # A stale snapshot write must never resurrect a deleted job id.
    shiva.db_upsert_job(job)
    with shiva.DB_LOCK:
        conn = shiva._db_conn()
        try:
            assert conn.execute("SELECT COUNT(*) FROM jobs WHERE id=?", (jid,)).fetchone()[0] == 0
        finally:
            conn.close()

    with shiva._DB_WRITE_LOCK:
        retry_ids = {
            (item.get("payload") or {}).get("id")
            for item in shiva._DB_WRITE_RETRY
            if isinstance(item, dict) and str(item.get("kind") or "") == "job_snapshot"
        }
    assert jid not in retry_ids

    with q.mutex:
        queue_ids = {
            (item.get("payload") or {}).get("id")
            for item in q.queue
            if isinstance(item, dict) and str(item.get("kind") or "") == "job_snapshot"
        }
    assert jid not in queue_ids
