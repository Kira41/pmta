# Shiva ↔ PowerMTA Accounting Bridge flow

This repository supports two ways for Shiva (`shiva.py`) to ingest PowerMTA accounting outcomes:

1. **Direct webhook to Shiva** (`POST /pmta/accounting` on Shiva).
2. **Via bridge** (`pmta_accounting_bridge.py`) where the bridge reads PMTA logs and forwards NDJSON to Shiva webhook.

## How Shiva knows where to receive results

Shiva does **not** call the bridge directly. Shiva only exposes and secures this endpoint:

- `POST /pmta/accounting`
- token is checked from `X-Webhook-Token` header (or `?token=`)
- token value comes from `PMTA_ACCOUNTING_WEBHOOK_TOKEN`

So Shiva "knows" incoming accounting data by accepting webhook payloads and mapping each event to a job/campaign.

## How the bridge knows where to send

Bridge uses environment variables:

- `SHIVA_ACCOUNTING_URL` → full webhook URL (typically `http://<shiva-host>:<port>/pmta/accounting`)
- `SHIVA_WEBHOOK_TOKEN` → shared secret sent as `X-Webhook-Token`

Bridge reads latest matching file (acct/diag/log), builds NDJSON payload, then sends `POST` with:

- `Content-Type: application/x-ndjson`
- `X-Webhook-Token: <token>`

## How result is returned

- Bridge endpoint `POST /api/v1/push/latest` returns:
  - selected file name,
  - pushed line count,
  - upstream status/body returned by Shiva.
- Shiva webhook returns JSON such as processed/accepted counts.

## Event-to-job mapping in Shiva

For each accounting event Shiva tries in this order:

1. explicit `job_id` fields (`x-job-id`, `job-id`, etc.)
2. extract job id from Message-ID format
3. fallback by `campaign_id` lookup

If matched, Shiva updates per-recipient outcome (`delivered`, `bounced`, `deferred`, `complained`), updates counters, and persists state.
