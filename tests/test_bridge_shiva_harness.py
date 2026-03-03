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


    def test_bridge_url_resolution_uses_campaign_smtp_host_and_configured_port(self):
        old_host = os.environ.get("SHIVA_HOST")
        old_port = shiva.PMTA_BRIDGE_PULL_PORT
        old_limit = shiva.PMTA_BRIDGE_PULL_MAX_LINES
        try:
            os.environ["SHIVA_HOST"] = "194.116.172.135"
            shiva.PMTA_BRIDGE_PULL_PORT = 18090
            shiva.PMTA_BRIDGE_PULL_MAX_LINES = 1234
            self._prepare_job(job_id="abcabc123456").smtp_host = "smtp.campaign.local"
            resolved = shiva._resolve_bridge_pull_url_runtime()
            self.assertEqual(
                resolved,
                "http://smtp.campaign.local:18090/api/v1/pull?kinds=acct&limit=1234",
            )
        finally:
            shiva.PMTA_BRIDGE_PULL_PORT = old_port
            shiva.PMTA_BRIDGE_PULL_MAX_LINES = old_limit
            if old_host is None:
                os.environ.pop("SHIVA_HOST", None)
            else:
                os.environ["SHIVA_HOST"] = old_host



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

        def _fake_bridge_get_json(path, params):
            if path == "/api/v1/job/count":
                raise RuntimeError("bridge unreachable")
            raise AssertionError("unexpected path: {}".format(path))

        try:
            os.environ["SHIVA_HOST"] = "194.116.172.135"
            shiva.PMTA_BRIDGE_PULL_PORT = 18090
            job = self._prepare_job()
            job.smtp_host = "smtp.campaign.local"
            job.delivered = 7
            job.deferred = 6
            job.bounced = 5
            job.complained = 4

            old_bridge_get_json = shiva.bridge_get_json
            shiva.bridge_get_json = _fake_bridge_get_json
            result = shiva._poll_accounting_bridge_once()

            self.assertFalse(result["ok"])
            self.assertEqual(job.delivered, 7)
            self.assertEqual(job.deferred, 6)
            self.assertEqual(job.bounced, 5)
            self.assertEqual(job.complained, 4)
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
        client = shiva.app.test_client()
        acquired = shiva._BRIDGE_POLL_CYCLE_LOCK.acquire(timeout=1.0)
        self.assertTrue(acquired)
        try:
            resp = client.post("/api/accounting/bridge/pull")
        finally:
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
