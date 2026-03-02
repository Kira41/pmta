import os
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


    def test_bridge_url_resolution_falls_back_to_last_req_url(self):
        old_cfg = shiva.PMTA_BRIDGE_PULL_URL
        old_state = dict(shiva._BRIDGE_DEBUG_STATE)
        old_env = os.environ.get("PMTA_BRIDGE_PULL_URL")
        old_env_legacy = os.environ.get("PMTA_ACCOUNTING_BRIDGE_PULL_URL")
        old_env_bridge = os.environ.get("PMTA_BRIDGE_URL")
        try:
            shiva.PMTA_BRIDGE_PULL_URL = ""
            for k in ("PMTA_BRIDGE_PULL_URL", "PMTA_ACCOUNTING_BRIDGE_PULL_URL", "PMTA_BRIDGE_URL"):
                os.environ.pop(k, None)
            with shiva._BRIDGE_DEBUG_LOCK:
                shiva._BRIDGE_DEBUG_STATE["last_req_url"] = (
                    "http://194.116.172.135:8090/api/v1/pull/latest?kind=acct&max_lines=2000&cursor=abc123"
                )

            resolved = shiva._resolve_bridge_pull_url_runtime()
            self.assertEqual(
                resolved,
                "http://194.116.172.135:8090/api/v1/pull/latest?kind=acct",
            )
        finally:
            shiva.PMTA_BRIDGE_PULL_URL = old_cfg
            if old_env is None:
                os.environ.pop("PMTA_BRIDGE_PULL_URL", None)
            else:
                os.environ["PMTA_BRIDGE_PULL_URL"] = old_env
            if old_env_legacy is None:
                os.environ.pop("PMTA_ACCOUNTING_BRIDGE_PULL_URL", None)
            else:
                os.environ["PMTA_ACCOUNTING_BRIDGE_PULL_URL"] = old_env_legacy
            if old_env_bridge is None:
                os.environ.pop("PMTA_BRIDGE_URL", None)
            else:
                os.environ["PMTA_BRIDGE_URL"] = old_env_bridge
            with shiva._BRIDGE_DEBUG_LOCK:
                shiva._BRIDGE_DEBUG_STATE.clear()
                shiva._BRIDGE_DEBUG_STATE.update(old_state)

    def test_bridge_token_normalization_accepts_bearer_and_quotes(self):
        self.assertEqual(
            shiva._normalize_bridge_pull_token('"Bearer mxft0zDIEHkdoTHF94jhxtKe1hdXSjVW5hHskfmuFXEdwzHtt9foI7ZZCz303Jyx"'),
            "mxft0zDIEHkdoTHF94jhxtKe1hdXSjVW5hHskfmuFXEdwzHtt9foI7ZZCz303Jyx",
        )
        self.assertEqual(
            shiva._normalize_bridge_pull_token("Bearer abc123"),
            "abc123",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
