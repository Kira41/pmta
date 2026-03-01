import os
import unittest

import shiva_app


class FilterAccountingLinesTests(unittest.TestCase):
    def test_csv_quotes_and_dedupe(self):
        lines = [
            'D,"2026-03-01 10:00:01","recipient@example.com","<msgid,1>","a,b"',
            'D,"2026-03-01 10:00:01","recipient@example.com","<msgid,1>","a,b"',
            'B,2026-03-01 10:00:05,other@example.com,<msgid2>,x',
        ]
        out = shiva_app.filter_accounting_lines(lines, job_id="job_2026_001")
        self.assertEqual(out["received_lines"], 3)
        self.assertEqual(out["unique_lines"], 2)
        self.assertEqual(out["counts_by_outcome"]["delivered"], 1)
        self.assertEqual(out["counts_by_outcome"]["bounced"], 1)

    def test_mapping_from_env(self):
        prev = os.environ.get("PMTA_ACCT_TYPE_MAP")
        try:
            os.environ["PMTA_ACCT_TYPE_MAP"] = "D:deferred,B:bounced,C:complained,T:deferred"
            out = shiva_app.filter_accounting_lines(["D,2026-01-01,a@b.com,<m1>"])
            self.assertEqual(out["counts_by_outcome"]["deferred"], 1)
            self.assertEqual(out["counts_by_outcome"]["delivered"], 0)
        finally:
            if prev is None:
                os.environ.pop("PMTA_ACCT_TYPE_MAP", None)
            else:
                os.environ["PMTA_ACCT_TYPE_MAP"] = prev


if __name__ == "__main__":
    unittest.main()
