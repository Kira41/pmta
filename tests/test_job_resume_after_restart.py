import shiva


def test_sendjob_snapshot_restore_keeps_job_paused_and_resumable():
    snap = {
        "id": "job-restore-1",
        "created_at": shiva.now_iso(),
        "updated_at": shiva.now_iso(),
        "status": "running",
        "paused": False,
        "stop_requested": False,
        "campaign_id": "camp-1",
        "resume_payload": {
            "recipients": ["a@example.com"],
            "smtp_host": "127.0.0.1",
        },
    }

    job = shiva._sendjob_from_snapshot(snap)

    assert job is not None
    assert job.status == "paused"
    assert job.paused is True
    assert job.stop_requested is False
    assert shiva._job_can_resume(job) is True


def test_api_job_resume_allows_paused_error_job_and_restarts_worker(monkeypatch):
    job_id = "job-resume-1"
    job = shiva.SendJob(
        id=job_id,
        created_at=shiva.now_iso(),
        status="error",
        paused=True,
        resume_payload={
            "recipients": ["a@example.com"],
            "smtp_host": "127.0.0.1",
            "smtp_port": 2525,
            "smtp_security": "none",
            "smtp_timeout": 10,
            "sender_names": ["Sender"],
            "sender_emails": ["sender@example.com"],
            "subjects": ["sub"],
            "body_format": "text",
            "body": "hi",
        },
    )

    original_jobs = shiva.JOBS
    shiva.JOBS = {job_id: job}
    called = {"count": 0}

    def _fake_resume_thread(j):
        called["count"] += 1
        return True

    monkeypatch.setattr(shiva, "_resume_job_thread", _fake_resume_thread)

    try:
        client = shiva.app.test_client()
        response = client.post(f"/api/job/{job_id}/control", json={"action": "resume"})
        data = response.get_json()

        assert response.status_code == 200
        assert data["ok"] is True
        assert called["count"] == 1
        assert shiva.JOBS[job_id].status == "running"
        assert shiva.JOBS[job_id].paused is False
    finally:
        shiva.JOBS = original_jobs
