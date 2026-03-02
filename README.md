# Shiva Accounting (New Bridge Flow)

This project now uses a simplified accounting ingestion flow.

## Flow

1. `pmta_accounting_bridge.py` tails PMTA accounting files and exposes pull/status APIs.
2. Shiva polls Bridge (`/api/v1/pull`) using a persisted cursor stored in `bridge_pull_state`.
3. Shiva parses and ingests rows, then applies outcome transitions per recipient.
4. Status endpoints show exactly where failures happen (bridge parse vs job lookup vs DB writer).

## Cursor behavior (new)

- Bridge returns `next_cursor` + `has_more` from `/api/v1/pull`.
- Shiva persists that cursor in SQLite (`bridge_pull_state.accounting_cursor`) and resumes after restart.
- If a bridge payload has no cursor fields, Shiva falls back to legacy behavior and logs a compatibility warning.

## Endpoints

### Bridge (`pmta_accounting_bridge.py`)

- `GET /api/v1/pull?kinds=acct&limit=<n>&cursor=<token>` (no auth token required)
- `GET /api/v1/status` (no auth token required):
  - `last_processed_file`, `last_cursor`, `parsed`, `skipped`, `unknown_outcome`, `last_error`, `server_time`

### Shiva (`shiva.py`)

- `GET /api/accounting/bridge/status`
  - Includes `last_poll_time`, `last_cursor`, `events_received`, `events_ingested`,
    `duplicates_dropped`, `job_not_found`, `db_write_failures`
- `POST /api/accounting/bridge/pull` (manual one-shot pull)

## Test harness

Run the ingestion harness tests:

```bash
python -m unittest -v tests/test_bridge_shiva_harness.py
```

Covers:
- replay of saved PMTA accounting CSV through Bridge + Shiva
- restart/resume from cursor without missing outcomes
- volume ingestion latency stability checks

## Recommended settings

- Bridge:
  - `DEFAULT_PULL_LIMIT=500`
  - `MAX_PULL_LIMIT=2000`
- Shiva:
  - `PMTA_BRIDGE_PULL_PORT=8090`
  - `PMTA_BRIDGE_PULL_MAX_LINES=2000`
  - `PMTA_BRIDGE_PULL_S=3..5` for near-real-time visibility
- SQLite:
  - Keep WAL enabled (`PRAGMA journal_mode=WAL`) for concurrent reads/writes.
  - Keep `busy_timeout` non-zero (already configured) to reduce transient lock failures.
