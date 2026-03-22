# PowerMTA Job Accounting Flow (Current Config)

This repository's current `config` file wires job-level accounting in PowerMTA using
three core pieces:

1. **Accounting outputs**
   - Main accounting stream is written to `/var/log/pmta/acct.csv` via `<acct-file ...>`.
   - Diagnostic accounting stream is written to `/var/log/pmta/diag.csv` and limited to
     transient (`t`) records.

2. **Job ID attribution from message headers**
   - In the localhost/API injection source (`<source 127.0.0.1>`), PowerMTA is configured to:
     - process incoming job headers: `process-x-job yes`
     - map an alternate header to job ID: `jobid-header X-Mailer-RecptId`
     - keep the original job header: `retain-x-job yes`

3. **Outcome generation rules**
   - Domain-level delivery behavior includes:
     - `bounce-upon-no-mx yes`
     - `retry-after 10m`
     - `bounce-after 24h`
   - These rules drive whether a recipient ends up recorded as delivered, bounced, or transient.

At runtime, PMTA writes one accounting record per recipient and (by default) records
delivery (`d`) and bounce (`b`) records, while this config additionally emits transient
diagnostics (`t`) in `diag.csv`.
