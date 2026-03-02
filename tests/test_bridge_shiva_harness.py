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

    def test_bridge_host_normalization_strips_scheme_and_port(self):
        self.assertEqual(shiva._normalize_bridge_host("http://194.116.172.135:2525"), "194.116.172.135")
        self.assertEqual(shiva._normalize_bridge_host("smtp.campaign.local:2525"), "smtp.campaign.local")


if __name__ == "__main__":
    unittest.main(verbosity=2)
