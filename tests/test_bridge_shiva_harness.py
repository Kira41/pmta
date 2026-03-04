import os
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

os.environ.setdefault("PMTA_BRIDGE_PULL_ENABLED", "0")
os.environ.setdefault("SHIVA_DB_PATH", str(Path(__file__).resolve().parent / "test-harness.db"))

import pmta_accounting_bridge as bridge
import shiva


class BridgeShivaHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = Path(__file__).resolve().parent / "fixtures" / "acct-sample.csv"

    def setUp(self):
        shiva.db_clear_all()
        shiva.JOBS.clear()
        shiva._OUTCOME_CACHE.clear()

    def _prepare_job(self, job_id: str = "abcdef123456"):
        job = shiva.SendJob(id=job_id, created_at=shiva.now_iso(), campaign_id="camp001")
        shiva.JOBS[job_id] = job
        return job

    def _bridge_pull_items(self, log_dir: Path, cursor: str = "", limit: int = 500):
        bridge.PMTA_LOG_DIR = log_dir
        bridge._CSV_HEADER_STATE.clear()
        files = bridge._recent_matching_files(["acct-*.csv"])
        payload = bridge._decode_cursor(cursor) if cursor else None
        return bridge._read_from_cursor(files, payload, limit)

    def test_replay_saved_csv_through_bridge_and_shiva(self):
        with TemporaryDirectory() as td:
            log_dir = Path(td)
            (log_dir / "acct-20260101.csv").write_text(self.sample.read_text(), encoding="utf-8")
            result = self._bridge_pull_items(log_dir, limit=50)

            self.assertEqual(result["stats"]["parsed"], 5)
            self.assertEqual(result["stats"]["unknown_outcome"], 1)

            job = self._prepare_job()
            for ev in result["items"]:
                shiva.process_pmta_accounting_event(ev)

            self.assertEqual(job.delivered, 1)
            self.assertEqual(job.deferred, 1)
            self.assertEqual(job.bounced, 1)
            self.assertEqual(job.complained, 1)

    def test_restart_resumes_from_cursor_without_missing_outcomes(self):
        with TemporaryDirectory() as td:
            log_dir = Path(td)
            (log_dir / "acct-20260101.csv").write_text(self.sample.read_text(), encoding="utf-8")

            first = self._bridge_pull_items(log_dir, limit=2)
            self._prepare_job()
            for ev in first["items"]:
                shiva.process_pmta_accounting_event(ev)

            resumed = self._bridge_pull_items(log_dir, cursor=first["next_cursor"], limit=50)
            for ev in resumed["items"]:
                shiva.process_pmta_accounting_event(ev)

            job = shiva.JOBS["abcdef123456"]
            self.assertEqual(job.delivered, 1)
            self.assertEqual(job.deferred, 1)
            self.assertEqual(job.bounced, 1)
            self.assertEqual(job.complained, 1)

    def test_volume_ingestion_latency_is_stable(self):
        self._prepare_job()
        sample = {
            "type": "d",
            "rcpt": "user{}@example.com",
            "header_x-job-id": "abcdef123456",
            "header_x-campaign-id": "camp001",
        }
        timings = []
        for i in range(1200):
            ev = dict(sample)
            ev["rcpt"] = sample["rcpt"].format(i)
            t0 = time.perf_counter()
            shiva.process_pmta_accounting_event(ev)
            timings.append((time.perf_counter() - t0) * 1000.0)

        avg_ms = sum(timings) / len(timings)
        p95_ms = sorted(timings)[int(len(timings) * 0.95)]
        self.assertLess(avg_ms, 20.0)
        self.assertLess(p95_ms, 50.0)



    def test_backoff_failure_classification_types(self):
        t, i = shiva._classify_backoff_failure(spam_blocked=False, blacklist_blocked=False, pmta_reason="temporary timeout on provider")
        self.assertEqual(t, "transient_delay")
        self.assertEqual(i, "")

        t, i = shiva._classify_backoff_failure(spam_blocked=False, blacklist_blocked=False, pmta_reason="provider policy block")
        self.assertEqual(t, "reputation")
        self.assertIn("reputation", i)

        t, i = shiva._classify_backoff_failure(spam_blocked=False, blacklist_blocked=False, pmta_reason="hard blocked by remote")
        self.assertEqual(t, "block")

    def test_backoff_wait_is_shorter_for_transient_and_longer_for_reputation(self):
        transient = shiva._compute_backoff_wait_seconds(attempt=2, base_s=60.0, max_s=1800.0, failure_type="transient_delay")
        blocked = shiva._compute_backoff_wait_seconds(attempt=2, base_s=60.0, max_s=1800.0, failure_type="block")
        reputation = shiva._compute_backoff_wait_seconds(attempt=2, base_s=60.0, max_s=1800.0, failure_type="reputation")

        self.assertLess(transient, blocked)
        self.assertGreater(reputation, blocked)
    def test_bridge_url_resolution_uses_campaign_smtp_host_and_configured_port(self):
        old_host = os.environ.get("SHIVA_HOST")
        old_port = shiva.PMTA_BRIDGE_PULL_PORT
        old_limit = shiva.PMTA_BRIDGE_PULL_MAX_LINES
        old_mode = shiva.BRIDGE_MODE
        try:
            os.environ["SHIVA_HOST"] = "194.116.172.135"
            shiva.BRIDGE_MODE = "legacy"
            shiva.PMTA_BRIDGE_PULL_PORT = 18090
            shiva.PMTA_BRIDGE_PULL_MAX_LINES = 1234
            self._prepare_job(job_id="abcabc123456").smtp_host = "smtp.campaign.local"
            resolved = shiva._resolve_bridge_pull_url_runtime()
            self.assertEqual(
                resolved,
                "http://smtp.campaign.local:18090/api/v1/pull?kinds=acct&limit=1234",
            )
        finally:
            shiva.BRIDGE_MODE = old_mode
            shiva.PMTA_BRIDGE_PULL_PORT = old_port
            shiva.PMTA_BRIDGE_PULL_MAX_LINES = old_limit
            if old_host is None:
                os.environ.pop("SHIVA_HOST", None)
            else:
                os.environ["SHIVA_HOST"] = old_host

    def test_bridge_counts_mode_disables_legacy_pull_components(self):
        old_mode = shiva.BRIDGE_MODE
        try:
            shiva.BRIDGE_MODE = "counts"
            self.assertEqual(shiva._resolve_bridge_pull_url_runtime(), "")
            self.assertEqual(shiva._normalize_bridge_pull_urls("http://bridge/api/v1/pull"), [])
            self.assertEqual(shiva._db_get_bridge_cursor(), "")
            shiva._db_set_bridge_cursor("cursor-will-be-ignored")
            self.assertEqual(shiva._db_get_bridge_cursor(), "")
        finally:
            shiva.BRIDGE_MODE = old_mode



    def test_bridge_poller_uses_job_count_and_job_outcomes(self):
        old_port = shiva.PMTA_BRIDGE_PULL_PORT
        old_host = os.environ.get("SHIVA_HOST")

        seen = []

        def _fake_bridge_get_json(path, params):
            url = "{}{}?{}".format(shiva.BRIDGE_BASE_URL, path, shiva.urlencode(params or {}, doseq=True))
            seen.append(url)
            if path == "/api/v1/job/count":
                return {
                    "ok": True,
                    "job_id": "abcdef123456",
                    "linked_emails_count": 3,
                    "delivered_count": 1,
                    "deferred_count": 1,
                    "bounced_count": 1,
                    "complained_count": 0,
                }
            if path == "/api/v1/job/outcomes":
                return {
                    "ok": True,
                    "job_id": "abcdef123456",
                    "delivered": {"count": 1, "emails": ["d@example.com"]},
                    "deferred": {"count": 1, "emails": ["t@example.com"]},
                    "bounced": {"count": 1, "emails": ["b@example.com"]},
                    "complained": {"count": 0, "emails": []},
                }
            raise AssertionError("unexpected path: {}".format(path))

        try:
            os.environ["SHIVA_HOST"] = "194.116.172.135"
            shiva.PMTA_BRIDGE_PULL_PORT = 18090
            self._prepare_job().smtp_host = "smtp.campaign.local"

            old_bridge_get_json = shiva.bridge_get_json
            shiva.bridge_get_json = _fake_bridge_get_json
            result = shiva._poll_accounting_bridge_once()

            self.assertTrue(result["ok"])
            self.assertTrue(any("/api/v1/job/count" in u for u in seen))
            self.assertTrue(any("/api/v1/job/outcomes" in u for u in seen))

            job = shiva.JOBS["abcdef123456"]
            self.assertEqual(job.delivered, 1)
            self.assertEqual(job.deferred, 1)
            self.assertEqual(job.bounced, 1)
            self.assertEqual(job.complained, 0)
        finally:
            shiva.bridge_get_json = old_bridge_get_json
            shiva.PMTA_BRIDGE_PULL_PORT = old_port
            if old_host is None:
                os.environ.pop("SHIVA_HOST", None)
            else:
                os.environ["SHIVA_HOST"] = old_host

    def test_bridge_sync_outcomes_flattens_and_upserts_without_duplicates(self):
        self._prepare_job()
        first = {
            "ok": True,
            "job_id": "abcdef123456",
            "delivered": {"count": 1, "emails": ["A@example.com"]},
            "deferred.emails": ["b@example.com"],
            "emails": [
                {"email": "c@example.com", "outcome": "bounced"},
                {"rcpt": "ignored@example.com"},
                "ambiguous@example.com",
            ],
        }
        second = {
            "ok": True,
            "job_id": "abcdef123456",
            "delivered": {"count": 0, "emails": []},
            "bounced": {"count": 1, "emails": ["a@example.com"]},
            "deferred": {"count": 0, "emails": []},
            "complained": {"count": 1, "emails": ["d@example.com"]},
        }

        counts1 = shiva._bridge_sync_job_outcomes("abcdef123456", first)
        self.assertEqual(counts1["delivered"], 1)
        self.assertEqual(counts1["deferred"], 1)
        self.assertEqual(counts1["bounced"], 1)

        counts2 = shiva._bridge_sync_job_outcomes("abcdef123456", second)
        self.assertEqual(counts2["bounced"], 1)
        self.assertEqual(counts2["complained"], 1)

        conn = shiva._db_conn()
        try:
            rows = conn.execute(
                "SELECT rcpt, status FROM job_outcomes WHERE job_id=? ORDER BY rcpt",
                ("abcdef123456",),
            ).fetchall()
        finally:
            conn.close()

        # latest bridge payload wins; stale rcpts are removed.
        self.assertEqual(rows, [("a@example.com", "bounced"), ("d@example.com", "complained")])



    def test_bridge_outcomes_include_accounting_error_details(self):
        with TemporaryDirectory() as td:
            log_dir = Path(td)
            (log_dir / "acct-20260101.csv").write_text(self.sample.read_text(), encoding="utf-8")
            bridge.PMTA_LOG_DIR = log_dir
            bridge._CSV_HEADER_STATE.clear()

            payload = bridge.get_job_outcomes(job_id="abcdef123456", _=None)
            rows = payload.get("emails") or []
            bounced = next((x for x in rows if str(x.get("outcome") or "") == "bounced"), None)

            self.assertTrue(isinstance(rows, list) and rows)
            self.assertIsNotNone(bounced)
            self.assertTrue(str(bounced.get("dsn_status") or ""))
            self.assertTrue(str(bounced.get("dsn_diag") or ""))

    def test_bridge_sync_outcomes_persists_dsn_diag_for_error_rows(self):
        self._prepare_job()
        payload = {
            "ok": True,
            "job_id": "abcdef123456",
            "emails": [
                {
                    "email": "b@example.com",
                    "outcome": "bounced",
                    "dsn_status": "5.1.1",
                    "dsn_diag": "550 5.1.1 user unknown",
                }
            ],
            "bounced": {
                "count": 1,
                "emails": ["b@example.com"],
            },
        }

        shiva._bridge_sync_job_outcomes("abcdef123456", payload)

        conn = shiva._db_conn()
        try:
            row = conn.execute(
                "SELECT last_dsn_status, last_dsn_diag FROM job_outcomes WHERE job_id=? AND rcpt=?",
                ("abcdef123456", "b@example.com"),
            ).fetchone()
        finally:
            conn.close()

        self.assertEqual(row, ("5.1.1", "550 5.1.1 user unknown"))
    def test_bridge_poller_skips_outcomes_when_disabled(self):
        old_port = shiva.PMTA_BRIDGE_PULL_PORT
        old_host = os.environ.get("SHIVA_HOST")
        old_fetch_outcomes = shiva.BRIDGE_POLL_FETCH_OUTCOMES

        seen = []

        def _fake_bridge_get_json(path, params):
            url = "{}{}?{}".format(shiva.BRIDGE_BASE_URL, path, shiva.urlencode(params or {}, doseq=True))
            seen.append(url)
            if path == "/api/v1/job/count":
                return {
                    "ok": True,
                    "job_id": "abcdef123456",
                    "linked_emails_count": 1,
                    "delivered_count": 1,
                    "deferred_count": 0,
                    "bounced_count": 0,
                    "complained_count": 0,
                }
            raise AssertionError("unexpected path: {}".format(path))

        try:
            os.environ["SHIVA_HOST"] = "194.116.172.135"
            shiva.PMTA_BRIDGE_PULL_PORT = 18090
            shiva.BRIDGE_POLL_FETCH_OUTCOMES = False
            self._prepare_job().smtp_host = "smtp.campaign.local"

            old_bridge_get_json = shiva.bridge_get_json
            shiva.bridge_get_json = _fake_bridge_get_json
            result = shiva._poll_accounting_bridge_once()

            self.assertTrue(result["ok"])
            self.assertTrue(any("/api/v1/job/count" in u for u in seen))
            self.assertFalse(any("/api/v1/job/outcomes" in u for u in seen))
        finally:
            shiva.bridge_get_json = old_bridge_get_json
            shiva.BRIDGE_POLL_FETCH_OUTCOMES = old_fetch_outcomes
            shiva.PMTA_BRIDGE_PULL_PORT = old_port
            if old_host is None:
                os.environ.pop("SHIVA_HOST", None)
            else:
                os.environ["SHIVA_HOST"] = old_host


    def test_bridge_poller_replaces_counters_from_job_count_authoritatively(self):
        old_port = shiva.PMTA_BRIDGE_PULL_PORT
        old_host = os.environ.get("SHIVA_HOST")
        old_fetch_outcomes = shiva.BRIDGE_POLL_FETCH_OUTCOMES

        def _fake_bridge_get_json(path, params):
            if path == "/api/v1/job/count":
                return {
                    "ok": True,
                    "job_id": "abcdef123456",
                    "linked_emails_count": 11,
                    "delivered_count": 5,
                    "deferred_count": 3,
                    "bounced_count": 2,
                    "complained_count": 1,
                }
            if path == "/api/v1/job/outcomes":
                return {
                    "ok": True,
                    "job_id": "abcdef123456",
                    "delivered": {"count": 1, "emails": ["d@example.com"]},
                    "deferred": {"count": 1, "emails": ["t@example.com"]},
                    "bounced": {"count": 1, "emails": ["b@example.com"]},
                    "complained": {"count": 0, "emails": []},
                }
            raise AssertionError("unexpected path: {}".format(path))

        try:
            os.environ["SHIVA_HOST"] = "194.116.172.135"
            shiva.PMTA_BRIDGE_PULL_PORT = 18090
            shiva.BRIDGE_POLL_FETCH_OUTCOMES = True
            job = self._prepare_job()
            job.smtp_host = "smtp.campaign.local"
            job.delivered = 99
            job.deferred = 99
            job.bounced = 99
            job.complained = 99

            old_bridge_get_json = shiva.bridge_get_json
            shiva.bridge_get_json = _fake_bridge_get_json

            first = shiva._poll_accounting_bridge_once()
            second = shiva._poll_accounting_bridge_once()

            self.assertTrue(first["ok"])
            self.assertTrue(second["ok"])
            self.assertEqual(job.delivered, 5)
            self.assertEqual(job.deferred, 3)
            self.assertEqual(job.bounced, 2)
            self.assertEqual(job.complained, 1)
        finally:
            shiva.bridge_get_json = old_bridge_get_json
            shiva.BRIDGE_POLL_FETCH_OUTCOMES = old_fetch_outcomes
            shiva.PMTA_BRIDGE_PULL_PORT = old_port
            if old_host is None:
                os.environ.pop("SHIVA_HOST", None)
            else:
                os.environ["SHIVA_HOST"] = old_host

    def test_bridge_poll_failure_does_not_zero_existing_counters(self):
        old_port = shiva.PMTA_BRIDGE_PULL_PORT
        old_host = os.environ.get("SHIVA_HOST")

        ok_payload = {
            "linked_emails_count": 22,
            "delivered_count": 7,
            "deferred_count": 6,
            "bounced_count": 5,
            "complained_count": 4,
        }
        mode = {"fail": False}

        def _fake_bridge_get_json(path, params):
            if path == "/api/v1/job/count":
                if mode["fail"]:
                    raise RuntimeError("bridge unreachable")
                return dict(ok_payload)
            raise AssertionError("unexpected path: {}".format(path))

        try:
            os.environ["SHIVA_HOST"] = "194.116.172.135"
            shiva.PMTA_BRIDGE_PULL_PORT = 18090
            job = self._prepare_job()
            job.smtp_host = "smtp.campaign.local"

            old_bridge_get_json = shiva.bridge_get_json
            shiva.bridge_get_json = _fake_bridge_get_json

            first = shiva._poll_accounting_bridge_once()
            self.assertTrue(first["ok"])
            self.assertEqual(job.delivered, 7)
            self.assertEqual(job.deferred, 6)
            self.assertEqual(job.bounced, 5)
            self.assertEqual(job.complained, 4)

            first_debug_count = int(shiva._BRIDGE_DEBUG_STATE.get("last_bridge_count") or 0)
            first_ok_ts = str(shiva._BRIDGE_DEBUG_STATE.get("last_ok_ts") or "")
            self.assertEqual(first_debug_count, 22)
            self.assertTrue(first_ok_ts)

            mode["fail"] = True
            result = shiva._poll_accounting_bridge_once()

            self.assertFalse(result["ok"])
            self.assertEqual(job.delivered, 7)
            self.assertEqual(job.deferred, 6)
            self.assertEqual(job.bounced, 5)
            self.assertEqual(job.complained, 4)
            self.assertEqual(int(shiva._BRIDGE_DEBUG_STATE.get("last_bridge_count") or 0), 22)
            self.assertEqual(str(shiva._BRIDGE_DEBUG_STATE.get("last_ok_ts") or ""), first_ok_ts)
            self.assertTrue(str(shiva._BRIDGE_DEBUG_STATE.get("last_error_ts") or ""))
            self.assertIn("bridge unreachable", str(shiva._BRIDGE_DEBUG_STATE.get("last_error_message") or ""))
        finally:
            shiva.bridge_get_json = old_bridge_get_json
            shiva.PMTA_BRIDGE_PULL_PORT = old_port
            if old_host is None:
                os.environ.pop("SHIVA_HOST", None)
            else:
                os.environ["SHIVA_HOST"] = old_host

    def test_poll_cycle_returns_busy_when_lock_is_held(self):
        acquired = shiva._BRIDGE_POLL_CYCLE_LOCK.acquire(timeout=1.0)
        self.assertTrue(acquired)
        try:
            result = shiva._poll_accounting_bridge_once()
        finally:
            shiva._BRIDGE_POLL_CYCLE_LOCK.release()

        self.assertFalse(result["ok"])
        self.assertEqual(result.get("reason"), "busy")
        self.assertEqual(result.get("error"), "busy")

    def test_manual_bridge_pull_returns_busy_when_cycle_is_running(self):
        old_mode = shiva.BRIDGE_MODE
        client = shiva.app.test_client()
        acquired = shiva._BRIDGE_POLL_CYCLE_LOCK.acquire(timeout=1.0)
        self.assertTrue(acquired)
        try:
            shiva.BRIDGE_MODE = "counts"
            resp = client.post("/api/accounting/bridge/pull")
        finally:
            shiva.BRIDGE_MODE = old_mode
            shiva._BRIDGE_POLL_CYCLE_LOCK.release()

        self.assertEqual(resp.status_code, 409)
        body = resp.get_json()
        self.assertEqual(body.get("ok"), False)
        self.assertEqual(body.get("reason"), "busy")

    def test_no_overlapping_poll_cycles(self):
        old_fetch_outcomes = shiva.BRIDGE_POLL_FETCH_OUTCOMES
        old_timeout = shiva.BRIDGE_TIMEOUT_S
        old_host = os.environ.get("SHIVA_HOST")
        old_port = shiva.PMTA_BRIDGE_PULL_PORT

        active_calls = 0
        max_active = 0
        gate = threading.Event()
        lock = threading.Lock()

        def _fake_bridge_get_json(path, params):
            nonlocal active_calls, max_active
            with lock:
                active_calls += 1
                max_active = max(max_active, active_calls)
            gate.wait(timeout=2.0)
            with lock:
                active_calls -= 1
            return {
                "ok": True,
                "job_id": "abcdef123456",
                "linked_emails_count": 1,
                "delivered_count": 1,
                "deferred_count": 0,
                "bounced_count": 0,
                "complained_count": 0,
            }

        try:
            shiva.BRIDGE_POLL_FETCH_OUTCOMES = False
            shiva.BRIDGE_TIMEOUT_S = 1.0
            os.environ["SHIVA_HOST"] = "194.116.172.135"
            shiva.PMTA_BRIDGE_PULL_PORT = 18090
            self._prepare_job().smtp_host = "smtp.campaign.local"

            old_bridge_get_json = shiva.bridge_get_json
            shiva.bridge_get_json = _fake_bridge_get_json

            results = []

            def _run_poll():
                results.append(shiva._poll_accounting_bridge_once())

            t1 = threading.Thread(target=_run_poll)
            t2 = threading.Thread(target=_run_poll)
            t1.start()
            time.sleep(0.05)
            t2.start()
            time.sleep(0.05)
            gate.set()
            t1.join(timeout=3.0)
            t2.join(timeout=3.0)

            self.assertEqual(len(results), 2)
            busy = [r for r in results if r.get("reason") == "busy"]
            self.assertEqual(len(busy), 1)
            self.assertLessEqual(max_active, 1)
        finally:
            shiva.bridge_get_json = old_bridge_get_json
            shiva.BRIDGE_POLL_FETCH_OUTCOMES = old_fetch_outcomes
            shiva.BRIDGE_TIMEOUT_S = old_timeout
            shiva.PMTA_BRIDGE_PULL_PORT = old_port
            if old_host is None:
                os.environ.pop("SHIVA_HOST", None)
            else:
                os.environ["SHIVA_HOST"] = old_host

    def test_bridge_status_endpoint_exposes_lightweight_fields(self):
        client = shiva.app.test_client()
        job = self._prepare_job()
        job.smtp_host = "smtp.campaign.local"
        job.delivered = 2
        job.deferred = 1
        job.bounced = 1
        job.complained = 0
        job.accounting_last_ts = "2026-01-01T00:00:00Z"

        with shiva._BRIDGE_DEBUG_LOCK:
            shiva._BRIDGE_DEBUG_STATE["last_ok_ts"] = "2026-01-01T01:00:00Z"
            shiva._BRIDGE_DEBUG_STATE["last_error_ts"] = "2026-01-01T01:05:00Z"
            shiva._BRIDGE_DEBUG_STATE["last_error_message"] = "sample-error"

        resp = client.get("/api/accounting/bridge/status")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()

        self.assertTrue(body.get("ok"))
        self.assertIn("bridge_base_url", body)
        self.assertIn("poll_interval", body)
        self.assertIn("timeout", body)
        self.assertEqual(body.get("last_ok_ts"), "2026-01-01T01:00:00Z")
        self.assertEqual(body.get("last_error_ts"), "2026-01-01T01:05:00Z")
        self.assertEqual(body.get("last_error_message"), "sample-error")

        jobs = body.get("jobs") or []
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].get("pmta_job_id"), "abcdef123456")
        self.assertEqual(jobs[0].get("counts", {}).get("delivered_count"), 2)
        self.assertEqual(jobs[0].get("last_update_time"), "2026-01-01T00:00:00Z")
        self.assertIn("outcomes_sync_enabled", jobs[0])

    def test_job_api_exposes_mode_specific_snapshot_fields_counts(self):
        client = shiva.app.test_client()
        job = self._prepare_job()
        job.bridge_mode = "counts"
        job.accounting_last_ts = "2026-01-01T00:00:00Z"

        with shiva._BRIDGE_DEBUG_LOCK:
            shiva._BRIDGE_DEBUG_STATE["last_success_ts"] = "2026-01-01T01:00:00Z"
            shiva._BRIDGE_DEBUG_STATE["last_cursor"] = "cursor-hidden-in-counts"
            shiva._BRIDGE_DEBUG_STATE["has_more"] = True
            shiva._BRIDGE_DEBUG_STATE["events_received"] = 10
            shiva._BRIDGE_DEBUG_STATE["events_ingested"] = 8

        resp = client.get(f"/api/job/{job.id}")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()

        self.assertEqual(body.get("bridge_mode"), "counts")
        self.assertEqual(body.get("accounting_last_update_ts"), "2026-01-01T00:00:00Z")
        self.assertEqual(body.get("bridge_last_success_ts"), "2026-01-01T01:00:00Z")
        self.assertEqual(body.get("bridge_last_cursor"), "cursor-hidden-in-counts")
        self.assertTrue(body.get("bridge_has_more"))
        self.assertEqual(body.get("received"), 10)
        self.assertEqual(body.get("ingested"), 8)

    def test_job_api_exposes_mode_specific_snapshot_fields_legacy(self):
        client = shiva.app.test_client()
        job = self._prepare_job("deadbeef9999")
        job.bridge_mode = "legacy"
        job.accounting_last_ts = "2026-01-02T00:00:00Z"

        with shiva._BRIDGE_DEBUG_LOCK:
            shiva._BRIDGE_DEBUG_STATE["last_cursor"] = "legacy-cursor-value"
            shiva._BRIDGE_DEBUG_STATE["has_more"] = False
            shiva._BRIDGE_DEBUG_STATE["events_received"] = 77
            shiva._BRIDGE_DEBUG_STATE["events_ingested"] = 70
            shiva._BRIDGE_DEBUG_STATE["duplicates_dropped"] = 3
            shiva._BRIDGE_DEBUG_STATE["job_not_found"] = 2

        resp = client.get(f"/api/job/{job.id}")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()

        self.assertEqual(body.get("bridge_mode"), "legacy")
        self.assertEqual(body.get("bridge_last_cursor"), "legacy-cursor-value")
        self.assertFalse(body.get("bridge_has_more"))
        self.assertEqual(body.get("received"), 77)
        self.assertEqual(body.get("ingested"), 70)
        self.assertEqual(body.get("duplicates_dropped"), 3)
        self.assertEqual(body.get("job_not_found"), 2)

    def test_manual_bridge_pull_response_has_job_totals_and_per_job_details(self):
        old_port = shiva.PMTA_BRIDGE_PULL_PORT
        old_host = os.environ.get("SHIVA_HOST")
        old_fetch_outcomes = shiva.BRIDGE_POLL_FETCH_OUTCOMES

        def _fake_bridge_get_json(path, params):
            job_id = str((params or {}).get("job_id") or "")
            if path == "/api/v1/job/count" and job_id == "abcdef123456":
                return {
                    "ok": True,
                    "job_id": job_id,
                    "linked_emails_count": 2,
                    "delivered_count": 1,
                    "deferred_count": 1,
                    "bounced_count": 0,
                    "complained_count": 0,
                }
            if path == "/api/v1/job/count" and job_id == "deadbeef0001":
                raise RuntimeError("boom")
            raise AssertionError("unexpected path: {} params={}".format(path, params))

        try:
            os.environ["SHIVA_HOST"] = "194.116.172.135"
            shiva.PMTA_BRIDGE_PULL_PORT = 18090
            shiva.BRIDGE_POLL_FETCH_OUTCOMES = False
            self._prepare_job("abcdef123456").smtp_host = "smtp.campaign.local"
            self._prepare_job("deadbeef0001").smtp_host = "smtp.campaign.local"

            old_bridge_get_json = shiva.bridge_get_json
            shiva.bridge_get_json = _fake_bridge_get_json

            client = shiva.app.test_client()
            resp = client.post("/api/accounting/bridge/pull")

            self.assertEqual(resp.status_code, 200)
            body = resp.get_json()
            self.assertEqual(body.get("jobs_total"), 2)
            self.assertEqual(body.get("jobs_success"), 1)
            self.assertEqual(body.get("jobs_failed"), 1)
            self.assertEqual(len(body.get("jobs") or []), 2)

            ok_rows = [r for r in (body.get("jobs") or []) if r.get("pmta_job_id") == "abcdef123456"]
            fail_rows = [r for r in (body.get("jobs") or []) if r.get("pmta_job_id") == "deadbeef0001"]
            self.assertEqual(ok_rows[0].get("counts", {}).get("linked_emails_count"), 2)
            self.assertIn("error", fail_rows[0])
        finally:
            shiva.bridge_get_json = old_bridge_get_json
            shiva.BRIDGE_POLL_FETCH_OUTCOMES = old_fetch_outcomes
            shiva.PMTA_BRIDGE_PULL_PORT = old_port
            if old_host is None:
                os.environ.pop("SHIVA_HOST", None)
            else:
                os.environ["SHIVA_HOST"] = old_host

    def test_bridge_row_parser_accepts_json_and_rejects_csv_strings(self):
        self.assertEqual(
            shiva._parse_bridge_json_row({"type": "d", "rcpt": "x@example.com"}),
            {"type": "d", "rcpt": "x@example.com"},
        )
        self.assertEqual(
            shiva._parse_bridge_json_row('{"type":"d","rcpt":"x@example.com"}'),
            {"type": "d", "rcpt": "x@example.com"},
        )
        self.assertIsNone(shiva._parse_bridge_json_row('d,2026-01-01,mailfrom,x@example.com'))

    def test_bridge_host_normalization_strips_scheme_and_port(self):
        self.assertEqual(shiva._normalize_bridge_host("http://194.116.172.135:2525"), "194.116.172.135")
        self.assertEqual(shiva._normalize_bridge_host("smtp.campaign.local:2525"), "smtp.campaign.local")


if __name__ == "__main__":
    unittest.main(verbosity=2)
