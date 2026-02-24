# Accounting Flow (Shiva Pull Model)

This repository now supports pull-based accounting ingestion where **Shiva requests data from bridge**.

## Direction

1. Bridge (`pmta_accounting_bridge.py`) reads PMTA accounting files.
2. Shiva (`shiva.py`) periodically calls bridge API over server IP.
3. Bridge returns lines only.
4. Shiva parses and applies outcomes to matching jobs/campaigns.

This avoids requiring a public IP for Shiva.

## Bridge API for Shiva

New endpoint:

- `GET /api/v1/pull/latest?kind=acct&max_lines=<N>`
- Auth: `Authorization: Bearer <API_TOKEN>` (or `?token=` fallback)

Response shape:

```json
{
  "ok": true,
  "kind": "acct",
  "file": "acct-2026-02-24.csv",
  "from_offset": 12345,
  "to_offset": 14789,
  "has_more": false,
  "count": 120,
  "lines": ["{...}", "{...}"]
}
```

## Shiva env (pull mode)

```bash
export PMTA_BRIDGE_PULL_ENABLED=1
export PMTA_BRIDGE_PULL_URL="http://194.116.172.135:8090/api/v1/pull/latest?kind=acct"
export PMTA_BRIDGE_PULL_TOKEN="<API_TOKEN>"
export PMTA_BRIDGE_PULL_S=5
export PMTA_BRIDGE_PULL_MAX_LINES=2000
```

Optional manual pull on Shiva:

- `POST /api/accounting/bridge/pull`

## Notes

- Existing `/pmta/accounting` webhook remains available if needed.
- Pull mode is one-way request/response: Shiva requests, bridge responds.
