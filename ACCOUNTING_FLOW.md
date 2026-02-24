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

## Shiva env (with your current token)

```bash
export PMTA_BRIDGE_PULL_ENABLED=1
export PMTA_BRIDGE_PULL_URL="http://194.116.172.135:8090/api/v1/pull/latest?kind=acct"
export PMTA_BRIDGE_PULL_TOKEN="mxft0zDIEHkdoTHF94jhxtKe1hdXSjVW5hHskfmuFXEdwzHtt9foI7ZZCz303Jyx"
export PMTA_BRIDGE_PULL_S=5
export PMTA_BRIDGE_PULL_MAX_LINES=2000
```

After exporting these values, restart Shiva so the process picks up the token.

## Verify Shiva is ready to receive accounting from bridge

```bash
# 1) Bridge should answer with accounting lines when token is valid
curl -i -H "Authorization: Bearer mxft0zDIEHkdoTHF94jhxtKe1hdXSjVW5hHskfmuFXEdwzHtt9foI7ZZCz303Jyx" \
  "http://194.116.172.135:8090/api/v1/pull/latest?kind=acct&max_lines=5"

# 2) Shiva should show pull config/status
curl -s "http://127.0.0.1:5000/api/accounting/bridge/status"

# 3) Force one manual pull in Shiva (same pipeline as background poller)
curl -s -X POST "http://127.0.0.1:5000/api/accounting/bridge/pull"
```

Expected readiness signals:

- status endpoint returns `{"ok": true, "bridge": {...}}`
- `pull_enabled` is `true`
- `pull_url` is non-empty and points to `/api/v1/pull/latest`
- manual pull returns `{"ok": true, ...}` and increments accounting outcomes

Optional manual pull on Shiva:

- `POST /api/accounting/bridge/pull`

## Notes

- Existing `/pmta/accounting` webhook remains available if needed.
- Pull mode is one-way request/response: Shiva requests, bridge responds.
