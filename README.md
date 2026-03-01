# Shiva Accounting (New Bridge Flow)

This project now uses a simplified accounting ingestion flow.

## Flow

1. `pmta_accounting_bridge.py` stays unchanged.
2. Shiva pulls raw lines from bridge using `X-Job-ID`.
3. Shiva applies:
   - CSV parse (`csv.reader`)
   - outcome mapping from first field (`D/B/C/T` by default)
   - dedupe by `line_hash = sha1(line.strip().replace("\r\n", "\n"))`
4. Shiva stores rows in `accounting_events`.

## ENV mapping

Default mapping:

- `D -> delivered`
- `B -> bounced`
- `C -> complained`
- `T -> deferred`
- anything else -> `unknown`

Override with:

```bash
export PMTA_ACCT_TYPE_MAP="D:delivered,B:bounced,C:complained,T:deferred"
```

## API

### Pull + Save

```bash
curl -X POST "http://localhost:5000/api/accounting/pull" \
  -H "Content-Type: application/json" \
  -d '{"job_id":"job_2026_001"}'
```

### Counts

```bash
curl "http://localhost:5000/api/accounting/job_2026_001/counts"
```

### Events list

```bash
curl "http://localhost:5000/api/accounting/job_2026_001/events?outcome=delivered&limit=200&offset=0"
```

## Runtime requirement

- Run Shiva with Python 3.9+ (`python3 shiva.py`).
- Using `python shiva.py` may invoke Python 2.x on some servers and fail with syntax errors.
