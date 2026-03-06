SECTION 1 — Remaining Gaps Closed
- `RECIPIENT_FILTER_ENABLE_SMTP_PROBE`: **CLOSED**. New proof now includes the actual `pre_send_recipient_filter()` branch gate plus the rejection rule that only executes when probe results exist.
- `RECIPIENT_FILTER_SMTP_PROBE_LIMIT`: **CLOSED**. New proof now shows it caps **eligible domains probed** (not recipients), via `probe_domains` fill-and-break logic.
- `SHIVA_DB_PATH`: **CLOSED**. New proof now traces `_resolve_db_path()` → `DB_PATH` → `_db_conn()` → all DB init/read/write entry points.
- `SHIVA_DB_WRITE_BATCH_SIZE`: **CLOSED**. New proof now shows exact writer-loop usage: cap on items per DB transaction batch (retry + queue drain), not queue capacity.
- `DB_CLEAR_ON_START`: **CLOSED**. New proof now shows startup call path (`db_init()` at import) and exact destructive action (`DELETE FROM ...` selected tables only).
- `SHIVA_BACKOFF_JITTER_PCT`: **CLOSED**. New proof now shows exact formula in `apply_backoff_jitter()` and where computed wait is used for retry scheduling.
- `SHIVA_BACKOFF_JITTER_EXPORT`: **CLOSED**. New proof now separates debug-export branch from execution wait computation.
- `BRIDGE_BASE_URL`: **CLOSED**. New proof now separates direct hard-required client path (`bridge_get_json`) from runtime-derived helper path (`_resolve_bridge_base_url_runtime`).
- `SHIVA_HOST`: **CLOSED**. New proof now separates bind host (`__main__`) from bridge helper fallback host (`_resolve_bridge_pull_host_from_campaign`) and wildcard handling difference.

SECTION 2 — Re-Proof of Unresolved Variables

### RECIPIENT_FILTER_ENABLE_SMTP_PROBE
- Previous weakness:
  - Read site was known, but effect-site proof was too shallow.
- Read-site proof:
  - Parsed once at import as boolean from `os.getenv("RECIPIENT_FILTER_ENABLE_SMTP_PROBE", "1")`.
- Effect-site proof:
  - In `pre_send_recipient_filter()`, probe execution is gated by `"smtp_probe": bool(smtp_probe and RECIPIENT_FILTER_ENABLE_SMTP_PROBE)` and only if this is true does code build `probe_domains`, call `_smtp_rcpt_probe()`, and possibly reject addresses on SMTP 5xx probe results.
- Call-chain proof:
  - `/start` endpoint submits `pre_send_recipient_filter(..., smtp_probe=True)` for both main and safe recipient lists; therefore this env var directly controls whether SMTP probe sub-flow runs in pre-send filtering.
- Lifecycle class:
  - Startup-only (restart required)
- Effect-type label(s):
  - Pre-send filtering
- What it really changes:
  - Enables/disables SMTP RCPT probing branch inside pre-send hygiene flow.
- What it does NOT change:
  - Does not disable syntax/domain route checks; does not alter SMTP send loop pacing/backoff logic.
- Misconfiguration consequence:
  - pre-send hygiene disabled
- Previous wording correction type:
  - Read site proven, effect site missing
- Updated assessment:
  - PROVEN
- Code quote(s):
```python
RECIPIENT_FILTER_ENABLE_SMTP_PROBE = (os.getenv("RECIPIENT_FILTER_ENABLE_SMTP_PROBE", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}

...

report: Dict[str, Any] = {
    "smtp_probe": bool(smtp_probe and RECIPIENT_FILTER_ENABLE_SMTP_PROBE),
    "smtp_probe_limit": int(max(0, RECIPIENT_FILTER_SMTP_PROBE_LIMIT or 0)),
}
...
if report["smtp_probe"] and int(report["smtp_probe_limit"] or 0) > 0:
    ...
    smtp_probe_by_domain[d] = _smtp_rcpt_probe(...)
...
if probe is not None and (not probe.get("ok")) and int(probe.get("code") or 0) >= 500:
    bad.append(em)
```

### RECIPIENT_FILTER_SMTP_PROBE_LIMIT
- Previous weakness:
  - Prior text implied generic “recipient cap” without proving actual unit.
- Read-site proof:
  - Parsed at import from `os.getenv("RECIPIENT_FILTER_SMTP_PROBE_LIMIT", "25")`.
- Effect-site proof:
  - Probe candidates are domains in `ordered_domains`; code appends domain to `probe_domains` only for `status in {"mx", "a_fallback"}` then `break` when `len(probe_domains) >= smtp_probe_limit`.
- Call-chain proof:
  - `pre_send_recipient_filter()` runs before job starts (`/start` submits it), so this limit bounds pre-send probe coverage only.
- Lifecycle class:
  - Startup-only (restart required)
- Effect-type label(s):
  - Pre-send filtering
- What it really changes:
  - Limits number of **domains probed** (first-seen recipient per domain), not total recipients.
- What it does NOT change:
  - Does not limit send-thread chunking, worker count, retries, or post-send execution.
- Misconfiguration consequence:
  - probe coverage too small
- Previous wording correction type:
  - Too broad
- Updated assessment:
  - PROVEN
- Code quote(s):
```python
RECIPIENT_FILTER_SMTP_PROBE_LIMIT = int((os.getenv("RECIPIENT_FILTER_SMTP_PROBE_LIMIT", "25") or "25").strip())

...
for d in ordered_domains:
    route = route_by_domain.get(d) or {"domain": d, "status": "unknown", "mx_hosts": []}
    if route.get("status") in {"mx", "a_fallback"}:
        probe_domains.append(d)
    if len(probe_domains) >= int(report["smtp_probe_limit"] or 0):
        break
```

### SHIVA_DB_PATH
- Previous weakness:
  - Read-site was documented, but not fully chained to actual sqlite opens.
- Read-site proof:
  - `_resolve_db_path()` resolves `SHIVA_DB_PATH` first, then `SMTP_SENDER_DB_PATH`, then default app-local DB file.
- Effect-site proof:
  - `DB_PATH = _resolve_db_path()` and `_db_conn()` uses `sqlite3.connect(DB_PATH, ...)`; all DB APIs call `_db_conn()`.
- Call-chain proof:
  - `db_init()` uses `_db_conn()` and is called at module load; writer thread also uses `_db_conn()`. So selected path is fixed globally from startup onward.
- Lifecycle class:
  - Startup-only (restart required)
- Effect-type label(s):
  - Persistence
- What it really changes:
  - Selects sqlite file location.
- What it does NOT change:
  - Does not control writer batch cadence/queueing.
- Misconfiguration consequence:
  - wrong DB file selected
- Previous wording correction type:
  - Read site proven, effect site missing
- Updated assessment:
  - PROVEN
- Code quote(s):
```python
def _resolve_db_path() -> str:
    raw = (
        os.getenv("SHIVA_DB_PATH")
        or os.getenv("SMTP_SENDER_DB_PATH")
        or str(APP_DIR / "smtp_sender.db")
    )
    ...
    return str(candidate)

DB_PATH = _resolve_db_path()

def _db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15.0)
```

### SHIVA_DB_WRITE_BATCH_SIZE
- Previous weakness:
  - Prior phrasing said “batching” but didn’t prove transaction boundary.
- Read-site proof:
  - Parsed at import from `os.getenv("SHIVA_DB_WRITE_BATCH_SIZE", "500")`, clamped to `[50, 1000]`.
- Effect-site proof:
  - `_db_writer_thread()` builds `batch` from retry list and queue until `len(batch) < DB_WRITE_BATCH_SIZE`, then performs one `BEGIN IMMEDIATE` and commits all items in that batch.
- Call-chain proof:
  - `start_db_writer_if_needed()` starts writer thread; called at module load immediately after `db_init()`.
- Lifecycle class:
  - Startup-only (restart required)
- Effect-type label(s):
  - Persistence
- What it really changes:
  - Max items processed per writer transaction loop iteration/commit.
- What it does NOT change:
  - Does not set queue max (`SHIVA_DB_WRITE_QUEUE_MAX` does that).
- Misconfiguration consequence:
  - queue flush delay misunderstood
- Previous wording correction type:
  - Too shallow
- Updated assessment:
  - PROVEN
- Code quote(s):
```python
DB_WRITE_BATCH_SIZE = max(50, min(1000, int((os.getenv("SHIVA_DB_WRITE_BATCH_SIZE", "500") or "500").strip())))

...
if _DB_WRITE_RETRY:
    batch.extend(_DB_WRITE_RETRY[:DB_WRITE_BATCH_SIZE])
...
while len(batch) < DB_WRITE_BATCH_SIZE:
    try:
        batch.append(_DB_WRITE_QUEUE.get_nowait())
...
conn.execute("BEGIN IMMEDIATE")
for item in batch:
    ...
conn.commit()
```

### DB_CLEAR_ON_START
- Previous weakness:
  - Destructive timing/path not clearly proven.
- Read-site proof:
  - `_DB_CLEAR_ON_START` parsed from `os.getenv("DB_CLEAR_ON_START", "0")` at import.
- Effect-site proof:
  - In `db_init()`, after schema creation and `conn.commit()`, conditional block issues `DELETE FROM` multiple tables and commits.
- Call-chain proof:
  - `db_init()` is invoked at module import (`db_init()` call near top-level), so wipe is startup-time/module-load behavior.
- Lifecycle class:
  - Startup-only (restart required)
- Effect-type label(s):
  - Persistence
- What it really changes:
  - Deletes rows from specific tables at startup.
- What it does NOT change:
  - Does not drop schema, does not delete DB file itself.
- Misconfiguration consequence:
  - destructive startup wipe
- Previous wording correction type:
  - Read site proven, effect site missing
- Updated assessment:
  - PROVEN
- Code quote(s):
```python
_DB_CLEAR_ON_START = (os.getenv("DB_CLEAR_ON_START", "0") or "0").strip().lower() in {"1", "true", "yes", "on"}

...
conn.commit()

# Optional: clear DB on startup (off by default)
if _DB_CLEAR_ON_START:
    conn.execute("DELETE FROM campaign_form")
    conn.execute("DELETE FROM campaigns")
    ...
    conn.execute("DELETE FROM sender_provider_stats")
    conn.commit()

...
db_init()
```

### SHIVA_BACKOFF_JITTER_PCT
- Previous weakness:
  - Formula-level proof and runtime interaction were incomplete.
- Read-site proof:
  - Parsed from env at import, and reloadable via `reload_runtime_config()`.
- Effect-site proof:
  - `apply_backoff_jitter()` computes `jitter_amp = min(max_jitter, max(min_jitter, base_wait * pct2))`, samples delta in `[-jitter_amp, +jitter_amp]`, then computes `wait_final = min(max(0.0, base_wait + jitter_delta), max_s)`.
- Call-chain proof:
  - Send loop computes base wait, then if jitter mode is enabled calls `apply_backoff_jitter(... pct=jitter_pct_runtime ...)`; resulting `wait_s` determines `next_ts = time.time() + wait_s` for retry scheduling.
- Lifecycle class:
  - Mixed (explain exactly which part is startup-only vs dynamic/reloadable)
- Effect-type label(s):
  - Backoff / pacing
- What it really changes:
  - Backoff variance amplitude as percent of computed base wait.
- What it does NOT change:
  - Does not change whether backoff happens; only wait variation magnitude.
- Misconfiguration consequence:
  - pacing variance too wide
- Previous wording correction type:
  - Too shallow
- Updated assessment:
  - PROVEN (mixed lifecycle nuance)
- Code quote(s):
```python
SHIVA_BACKOFF_JITTER_PCT = float((os.getenv("SHIVA_BACKOFF_JITTER_PCT", "0.15") or "0.15").strip())
...
SHIVA_BACKOFF_JITTER_PCT = max(0.0, float(cfg_get_float("SHIVA_BACKOFF_JITTER_PCT", SHIVA_BACKOFF_JITTER_PCT)))

...
jitter_amp = min(max_jitter, max(min_jitter, base_wait * pct2))
...
wait_final = min(max(0.0, base_wait + jitter_delta), max(0.0, float(max_s or base_wait)))

...
wait_s, jitter_delta = apply_backoff_jitter(... pct=jitter_pct_runtime, ...)
next_ts = time.time() + wait_s
```

### SHIVA_BACKOFF_JITTER_EXPORT
- Previous weakness:
  - Needed explicit proof that this does not alter pacing.
- Read-site proof:
  - Parsed at import; also reloadable in `reload_runtime_config()`.
- Effect-site proof:
  - Only gates debug payload list initialization and append to `job.debug_backoff_jitter`; timing `wait_s` is already computed before export branch and used regardless.
- Call-chain proof:
  - Backoff scheduling path computes `wait_s`/`next_ts` first; export branch executes later only for telemetry storage.
- Lifecycle class:
  - Reloadable
- Effect-type label(s):
  - Observability only
- What it really changes:
  - Presence/absence of jitter metadata in job debug payload.
- What it does NOT change:
  - No effect on delay math, retry decision, or send flow.
- Misconfiguration consequence:
  - jitter metadata missing but pacing unchanged
- Previous wording correction type:
  - Operational impact overstated
- Updated assessment:
  - PROVEN
- Code quote(s):
```python
SHIVA_BACKOFF_JITTER_EXPORT = (os.getenv("SHIVA_BACKOFF_JITTER_EXPORT", "0") or "0").strip().lower() in {"1", "true", "yes", "on"}
...
SHIVA_BACKOFF_JITTER_EXPORT = bool(cfg_get_bool("SHIVA_BACKOFF_JITTER_EXPORT", SHIVA_BACKOFF_JITTER_EXPORT))

...
next_ts = time.time() + wait_s
...
if backoff_jitter_mode_runtime != "off" and SHIVA_BACKOFF_JITTER_EXPORT:
    job.debug_backoff_jitter.append({
        "wait_base": float(wait_s_base),
        "jitter_delta": float(jitter_delta),
        "wait_final": float(wait_s),
    })
```

### BRIDGE_BASE_URL
- Previous weakness:
  - Mixed direct client requirement with runtime helper derivation.
- Read-site proof:
  - Parsed from env at import and updated by reload/config APIs.
- Effect-site proof:
  - `bridge_get_json()` directly requires non-empty `BRIDGE_BASE_URL` and rejects HTTPS/non-HTTP.
  - `_resolve_bridge_base_url_runtime()` can derive a fallback `http://<resolved_host>:<port>` when configured value is empty.
  - Poller path sets global `BRIDGE_BASE_URL = base_url` from runtime resolver before bridge calls.
- Call-chain proof:
  - `_poll_accounting_bridge_once()` calls runtime resolver, writes `BRIDGE_BASE_URL`, then downstream requests use `bridge_get_json()`.
- Lifecycle class:
  - Reloadable
- Effect-type label(s):
  - Bridge ingestion, Runtime URL resolution
- What it really changes:
  - Configured fixed bridge base for HTTP bridge client, with runtime-derived fallback when not explicitly configured.
- What it does NOT change:
  - Does not change SMTP delivery execution logic.
- Misconfiguration consequence:
  - bridge endpoint mismatch
- Previous wording correction type:
  - Mixed roles not separated
- Updated assessment:
  - PROVEN
- Code quote(s):
```python
BRIDGE_BASE_URL = (os.getenv("BRIDGE_BASE_URL", "") or "").strip()
...
def _resolve_bridge_base_url_runtime() -> str:
    configured = (BRIDGE_BASE_URL or "").strip().rstrip("/")
    if configured:
        return configured
    host = _normalize_bridge_host(_resolve_bridge_pull_host_from_campaign())
    return f"http://{host}:{PMTA_BRIDGE_PULL_PORT}"


def bridge_get_json(path: str, params: dict) -> dict:
    base = (BRIDGE_BASE_URL or "").strip()
    if not base:
        raise ValueError("bridge base url is not configured")
    if base.lower().startswith("https://"):
        raise ValueError("https is not allowed for bridge client")

...
base_url = _resolve_bridge_base_url_runtime()
global BRIDGE_BASE_URL
BRIDGE_BASE_URL = base_url
```

### SHIVA_HOST
- Previous weakness:
  - Two roles were conflated.
- Read-site proof:
  - Read in `__main__` bind path and separately in bridge-host fallback helper.
- Effect-site proof:
  - `__main__`: `app.run(host=host, port=port, ...)` uses `SHIVA_HOST` default `0.0.0.0`.
  - Bridge helper: `_resolve_bridge_pull_host_from_campaign()` uses `SHIVA_HOST` only when no job SMTP host exists; explicitly rejects wildcard `0.0.0.0` and `::`, then falls back to `127.0.0.1`.
- Call-chain proof:
  - Bridge runtime URL resolver calls `_resolve_bridge_pull_host_from_campaign()` each time; this helper does `os.getenv("SHIVA_HOST", "")` dynamically per call.
- Lifecycle class:
  - Mixed (explain exactly which part is startup-only vs dynamic/reloadable)
- Effect-type label(s):
  - Server bind, Runtime URL resolution
- What it really changes:
  - Role A bind interface in standalone run; Role B fallback host for bridge URL derivation when no campaign host is available.
- What it does NOT change:
  - Not a general SMTP target override for active jobs.
- Misconfiguration consequence:
  - wrong helper fallback host
- Previous wording correction type:
  - Mixed roles not separated
- Updated assessment:
  - PROVEN
- Code quote(s):
```python
def _resolve_bridge_pull_host_from_campaign() -> str:
    ...
    host = (os.getenv("SHIVA_HOST", "") or "").strip()
    if host and host not in {"0.0.0.0", "::"}:
        return host
    return "127.0.0.1"

...
if __name__ == "__main__":
    host = (os.getenv("SHIVA_HOST", "0.0.0.0") or "0.0.0.0").strip()
    ...
    app.run(host=host, port=port, debug=True)
```

SECTION 3 — Dual-Role and Split-Semantics Variables

### SHIVA_HOST
#### Role 1
- Meaning:
  - Flask bind host for standalone `app.run()`.
- Proof:
  - `if __name__ == "__main__": host = os.getenv("SHIVA_HOST", "0.0.0.0"); app.run(host=host, ...)`.
- Lifecycle:
  - Startup-only (restart required)
- Effect type:
  - Server bind

#### Role 2
- Meaning:
  - Runtime fallback host for bridge URL helper when no recent job SMTP host exists.
- Proof:
  - `_resolve_bridge_pull_host_from_campaign()` reads `os.getenv("SHIVA_HOST", "")` each call; wildcard values rejected; fallback to loopback.
- Lifecycle:
  - Dynamic read at call time
- Effect type:
  - Runtime URL resolution

#### Final note
- Earlier drafts were easy to misunderstand because they merged a process-bind setting and a helper fallback source under one statement.

### BRIDGE_BASE_URL
#### Role 1
- Meaning:
  - Explicit configured base URL used by direct bridge HTTP client helper.
- Proof:
  - `bridge_get_json()` reads `BRIDGE_BASE_URL` directly and errors if empty/https/non-http.
- Lifecycle:
  - Reloadable
- Effect type:
  - Bridge ingestion

#### Role 2
- Meaning:
  - Participates in runtime URL resolution fallback chain when unset.
- Proof:
  - `_resolve_bridge_base_url_runtime()` returns configured base if present; otherwise derives from runtime host helper and bridge port.
- Lifecycle:
  - Mixed (explain exactly which part is startup-only vs dynamic/reloadable)
- Effect type:
  - Runtime URL resolution

#### Final note
- Earlier drafts were easy to misunderstand because “bridge base URL” was described as single behavior while code has both strict direct-consumer path and computed fallback path.

SECTION 4 — Classification Snapshot

| Variable | Lifecycle class | Effect-type label(s) | Confidence | Correction needed? |
|---|---|---|---|---|
| RECIPIENT_FILTER_ENABLE_SMTP_PROBE | Startup-only (restart required) | Pre-send filtering | High | Read site proven, effect site missing |
| RECIPIENT_FILTER_SMTP_PROBE_LIMIT | Startup-only (restart required) | Pre-send filtering | High | Too broad |
| SHIVA_DB_PATH | Startup-only (restart required) | Persistence | High | Read site proven, effect site missing |
| SHIVA_DB_WRITE_BATCH_SIZE | Startup-only (restart required) | Persistence | High | Too shallow |
| DB_CLEAR_ON_START | Startup-only (restart required) | Persistence | High | Read site proven, effect site missing |
| SHIVA_BACKOFF_JITTER_PCT | Mixed (explain exactly which part is startup-only vs dynamic/reloadable) | Backoff / pacing | High | Too shallow |
| SHIVA_BACKOFF_JITTER_EXPORT | Reloadable | Observability only | High | Operational impact overstated |
| BRIDGE_BASE_URL | Reloadable | Bridge ingestion, Runtime URL resolution | High | Mixed roles not separated |
| SHIVA_HOST | Mixed (explain exactly which part is startup-only vs dynamic/reloadable) | Server bind, Runtime URL resolution | High | Mixed roles not separated |

SECTION 5 — Corrections to Earlier Variable Status
- `RECIPIENT_FILTER_ENABLE_SMTP_PROBE`: can now be upgraded to PROVEN (branch + rejection effect-site is now directly proven).
- `RECIPIENT_FILTER_SMTP_PROBE_LIMIT`: can now be upgraded to PROVEN (proven unit is “probe domains”, not recipients).
- `SHIVA_DB_PATH`: can now be upgraded to PROVEN (full chain to `sqlite3.connect(DB_PATH, ...)` shown).
- `SHIVA_DB_WRITE_BATCH_SIZE`: can now be upgraded to PROVEN (writer loop transaction cap behavior shown).
- `DB_CLEAR_ON_START`: can now be upgraded to PROVEN (startup invocation + exact delete scope shown).
- `SHIVA_BACKOFF_JITTER_PCT`: can now be upgraded to PROVEN (formula and `next_ts` scheduling effect shown).
- `SHIVA_BACKOFF_JITTER_EXPORT`: can now be upgraded to PROVEN (telemetry-only branch shown, no timing change).
- `BRIDGE_BASE_URL`: can now be upgraded to PROVEN (strict direct requirement + runtime fallback interaction both proven).
- `SHIVA_HOST`: can now be upgraded to PROVEN (dual role split and wildcard rejection in helper proven).

TASK B corrections (other misclassification checks):
- No additional downgrade found in this pass for non-target variables; previous unresolved set was concentrated in the nine variables above.

SECTION 6 — Final Residual Ambiguities
- None for the nine variables in this pass: read sites, effect sites, call chains, lifecycle class, and operational consequence are now directly evidenced from code.
- Remaining nuance (not ambiguity): `SHIVA_BACKOFF_JITTER_PCT` is reloadable globally but captured into `jitter_pct_runtime` at job thread start, so practical effect updates apply on subsequent job starts unless code path re-reads mid-job.
