import sqlite3
import tempfile

import shiva


def _mk_db_path_with_attempts(rows):
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    path = tmp.name
    tmp.close()
    conn = sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE email_attempt_logs(
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               series_id TEXT NOT NULL,
               job_id TEXT NOT NULL,
               campaign_id TEXT NOT NULL,
               chunk_idx INTEGER NOT NULL,
               sender_domain TEXT NOT NULL,
               provider_domain TEXT NOT NULL,
               attempt_number INTEGER NOT NULL,
               outcome TEXT NOT NULL,
               attempt_ts TEXT NOT NULL,
               created_at TEXT NOT NULL
           )"""
    )
    conn.executemany(
        "INSERT INTO email_attempt_logs(series_id, job_id, campaign_id, chunk_idx, sender_domain, provider_domain, attempt_number, outcome, attempt_ts, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    conn.commit()
    conn.close()
    return path


def test_learning_caps_engine_low_confidence_without_samples():
    path = _mk_db_path_with_attempts([])
    engine = shiva.LearningCapsEngine(db_getter=lambda: sqlite3.connect(path), min_samples=10, refresh_s=60, recency_days=14)

    policy = engine.compute_policy(job=None, senders=["a@sender.com"], providers=["gmail.com"])

    provider = policy.per_provider["gmail.com"]
    assert provider.confidence <= 0.1
    assert provider.provider_max_inflight_suggested is None


def test_learning_caps_engine_degrading_clamps_down():
    rows = []
    for i in range(120):
        outcome = "deferred_4xx" if i < 80 else "failed_5xx"
        rows.append((f"s{i}", "j", "c", 0, "sender.com", "gmail.com", 1, outcome, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"))
    path = _mk_db_path_with_attempts(rows)
    engine = shiva.LearningCapsEngine(db_getter=lambda: sqlite3.connect(path), min_samples=20, refresh_s=60, recency_days=365)

    policy = engine.compute_policy(job=None, senders=["a@sender.com"], providers=["gmail.com"])

    provider = policy.per_provider["gmail.com"]
    lane = policy.per_lane["sender.com|gmail.com"]
    assert provider.provider_max_inflight_suggested == 1
    assert provider.provider_min_gap_s_suggested >= 10
    assert lane.workers_cap == 1
    assert lane.chunk_cap <= 100
