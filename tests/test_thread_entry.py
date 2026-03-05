import shiva


def test_smtp_send_job_thread_entry_marks_job_error_on_unhandled_crash(monkeypatch):
    job = shiva.SendJob(id="jid123", created_at="", updated_at="", campaign_id="cid")
    with shiva.JOBS_LOCK:
        shiva.JOBS[job.id] = job

    def _boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(shiva, "smtp_send_job", _boom)
    shiva.smtp_send_job_thread_entry(job.id)

    with shiva.JOBS_LOCK:
        assert shiva.JOBS[job.id].status == "error"
        assert "boom" in (shiva.JOBS[job.id].last_error or "")
        shiva.JOBS.pop(job.id, None)
