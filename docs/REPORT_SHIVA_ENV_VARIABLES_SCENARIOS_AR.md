SECTION 1 — Final Cleanup Summary
- Finalized lifecycle wording by removing all placeholder text and replacing it with explicit classes, including:
  - `SHIVA_BACKOFF_JITTER_PCT`: **Mixed — global value is reloadable, but active jobs may continue using a per-job runtime snapshot captured at job/thread start**.
  - `BRIDGE_BASE_URL`: **Mixed — explicit configured base URL is reloadable; runtime fallback derivation is dynamic at poll-time**.
  - `SHIVA_HOST`: **Mixed — bind role is startup-only; helper fallback role is dynamic read at call time**.
- Finalized effect-type labels and operational impact language for the cleanup scope variables so each row now clearly distinguishes code-level effect, runtime effect, and system-level operational effect.
- Embedded practical timing nuances directly inside the relevant variable rows (especially `SHIVA_BACKOFF_JITTER_PCT`) rather than leaving critical behavior only in residual notes.
- Placeholder lifecycle phrases removed:
  - `Mixed (explain exactly which part is startup-only vs dynamic/reloadable)`
  - any equivalent intermediate wording.
- Ambiguity status: no code-proven ambiguity remains for the finalized scope in this cleanup pass.

SECTION 2 — Finalized Variable Rows

### RECIPIENT_FILTER_ENABLE_SMTP_PROBE
- Final lifecycle class: Startup-only (restart required)
- Final effect-type label(s): Pre-send filtering
- Code-level effect: Gates the SMTP probe branch in `pre_send_recipient_filter()` via `smtp_probe and RECIPIENT_FILTER_ENABLE_SMTP_PROBE`; when enabled, probe results can drive recipient rejection on 5xx responses.
- Runtime effect: Changes whether SMTP RCPT probe checks run before job execution begins.
- System-level operational effect: Controls pre-send hygiene strictness and can materially change which recipients are admitted into the send phase, affecting deliverability posture and bounce avoidance behavior.
- What it does NOT change: Does not alter syntax/domain checks that run independently; does not alter send-loop pacing, retry scheduling, or backoff math.
- Important nuance: This gate is import-time configuration, so toggling environment without restart does not flip behavior in a running process.
- Final correction note: Previously “read-site known, effect-site weak”; effect path is now fully tied to probe execution and rejection behavior.
- Final assessment: PROVEN

### RECIPIENT_FILTER_SMTP_PROBE_LIMIT
- Final lifecycle class: Startup-only (restart required)
- Final effect-type label(s): Pre-send filtering
- Code-level effect: Caps `probe_domains` growth (domain-level unit) and breaks once the domain probe limit is reached.
- Runtime effect: Limits breadth of domain probing during pre-send filtering.
- System-level operational effect: Tunes probe coverage depth vs latency/resource use in hygiene stage; low values reduce risk-screening coverage across domains.
- What it does NOT change: Does not cap total recipients sent, thread concurrency, retry counts, or post-send behavior.
- Important nuance: The limit applies to eligible domains (first-seen per domain path), not recipient count.
- Final correction note: Corrected from vague “recipient cap” wording to exact domain-scoped cap.
- Final assessment: PROVEN

### SHIVA_DB_PATH
- Final lifecycle class: Startup-only (restart required)
- Final effect-type label(s): Persistence
- Code-level effect: Selects the SQLite file path used by `DB_PATH`, which is consumed by `_db_conn()` for all DB init/read/write calls.
- Runtime effect: Directs all persistence I/O to the selected database file for the process lifetime.
- System-level operational effect: Determines data locality and persistence target, which affects retention continuity, backup scope, and operational recovery expectations.
- What it does NOT change: Does not change write batching logic, queue sizing, or send policy.
- Important nuance: Path is resolved once into global `DB_PATH`; runtime env changes are ignored until restart.
- Final correction note: Full read-to-connect chain is now explicit.
- Final assessment: PROVEN

### SHIVA_DB_WRITE_BATCH_SIZE
- Final lifecycle class: Startup-only (restart required)
- Final effect-type label(s): Persistence
- Code-level effect: Sets the max item count per writer loop batch before one DB transaction commit (`BEGIN IMMEDIATE` → write loop → `commit`).
- Runtime effect: Controls transaction granularity of queued writes.
- System-level operational effect: Larger batches improve write throughput but can increase per-commit latency and retry replay size; smaller batches reduce transaction burst size but can increase commit frequency and overhead.
- What it does NOT change: Does not set queue capacity (`SHIVA_DB_WRITE_QUEUE_MAX`), worker count, or recipient filtering behavior.
- Important nuance: Value is clamped and fixed after import; changes require process restart to alter writer behavior.
- Final correction note: Clarified from generic batching language to transaction-boundary semantics.
- Final assessment: PROVEN

### DB_CLEAR_ON_START
- Final lifecycle class: Startup-only (restart required)
- Final effect-type label(s): Persistence
- Code-level effect: When enabled, executes `DELETE FROM` against selected tables during `db_init()` after schema setup.
- Runtime effect: Performs destructive row clearing once during startup/module-load path.
- System-level operational effect: Resets operational state/history at startup for targeted tables, which can erase campaign tracking continuity and analytics/state baselines.
- What it does NOT change: Does not drop schema and does not delete the SQLite file itself.
- Important nuance: One-time startup action; changing env after process start has no effect until next startup.
- Final correction note: Timing and delete scope are now explicit and bounded.
- Final assessment: PROVEN

### SHIVA_BACKOFF_JITTER_PCT
- Final lifecycle class: Mixed — global value is reloadable, but active jobs may continue using a per-job runtime snapshot captured at job/thread start
- Final effect-type label(s): Backoff / pacing
- Code-level effect: Sets percent-based jitter amplitude in `apply_backoff_jitter()` (`jitter_amp` derived from base wait and bounded), which perturbs retry wait before `next_ts` scheduling.
- Runtime effect: Alters randomness width around base retry delay for pacing dispersion.
- System-level operational effect: Changes temporal spread of retries across workers/jobs, affecting burst smoothing and retry collision patterns at operational scale.
- What it does NOT change: Does not disable retries, alter base retry policy selection, or change non-backoff filtering/persistence logic.
- Important nuance: Even though reload updates the global config, active job threads may keep using the `jitter_pct_runtime` snapshot captured at job/thread start; practical effect may apply immediately only to newly started jobs/threads.
- Final correction note: Replaced placeholder mixed wording and embedded runtime-snapshot timing nuance directly in the row.
- Final assessment: PROVEN

### SHIVA_BACKOFF_JITTER_EXPORT
- Final lifecycle class: Reloadable
- Final effect-type label(s): Observability only
- Code-level effect: Gates debug payload export (`job.debug_backoff_jitter` append) without participating in wait computation.
- Runtime effect: Turns jitter telemetry visibility on/off.
- System-level operational effect: Affects troubleshooting observability for backoff behavior but does not alter delivery timing or retry execution.
- What it does NOT change: Does not change `wait_s`, `next_ts`, retry branch decisions, or throughput pacing.
- Important nuance: Runtime toggles can change debug payload generation without restart.
- Final correction note: Operational impact is narrowed to telemetry only.
- Final assessment: PROVEN

### BRIDGE_BASE_URL
- Final lifecycle class: Mixed — explicit configured base URL is reloadable; runtime fallback derivation is dynamic at poll-time
- Final effect-type label(s): Bridge ingestion, Runtime URL resolution
- Code-level effect: Direct client path (`bridge_get_json`) requires valid non-empty HTTP `BRIDGE_BASE_URL`; runtime resolver path can derive fallback URL when configured value is absent.
- Runtime effect: Determines whether bridge polling uses explicit configured endpoint or computed fallback endpoint.
- System-level operational effect: Governs external bridge connectivity target selection and can redirect ingestion traffic source dynamically when explicit base is unset.
- What it does NOT change: Does not modify SMTP send mechanics, retry jitter, or recipient filtering rules.
- Important nuance: Poller resolves URL at runtime and updates the global base used by downstream bridge calls; operational endpoint can change across polling cycles when fallback inputs change.
- Final correction note: Dual behavior is now explicitly split into configured-consumer semantics vs runtime fallback semantics.
- Final assessment: PROVEN

### SHIVA_HOST
- Final lifecycle class: Mixed — bind role is startup-only; helper fallback role is dynamic read at call time
- Final effect-type label(s): Server bind, Runtime URL resolution
- Code-level effect: In standalone mode, provides Flask bind host for `app.run(...)`; in bridge helper fallback path, provides candidate host when campaign-derived SMTP host is unavailable (with wildcard rejection).
- Runtime effect: Affects process listening interface at startup and helper URL host derivation during runtime resolution calls.
- System-level operational effect: Influences service reachability surface (bind interface) and bridge helper targetability when fallback resolution is needed.
- What it does NOT change: Does not globally override SMTP target host for active send jobs.
- Important nuance: Helper role uses dynamic `os.getenv` reads and rejects wildcard bind literals (`0.0.0.0`, `::`) before loopback fallback, while bind role is fixed after process start.
- Final correction note: Conflated dual-role wording is now fully separated with lifecycle and impact clarity.
- Final assessment: PROVEN

SECTION 3 — Final Dual-Role Variables

### SHIVA_HOST
#### Role 1
- Final meaning: Standalone Flask bind host used by `app.run(host=...)`.
- Lifecycle: Startup-only (restart required)
- Effect type: Server bind
- Operational impact: Determines which network interface the service listens on when run in standalone Flask mode.

#### Role 2
- Final meaning: Bridge helper fallback host source when no campaign SMTP host can be resolved.
- Lifecycle: Dynamic read at call time
- Effect type: Runtime URL resolution
- Operational impact: Influences fallback bridge URL host selection during runtime helper resolution (with wildcard values rejected, then loopback fallback).

#### Final wording note
- Clean interpretation: `SHIVA_HOST` is not a single-behavior variable; it has one startup bind role and one runtime helper-fallback role, and those roles must be reasoned about independently.

### BRIDGE_BASE_URL
#### Role 1
- Final meaning: Explicit configured bridge client base URL consumed by direct HTTP bridge calls.
- Lifecycle: Reloadable
- Effect type: Bridge ingestion
- Operational impact: Directly sets polling/ingestion endpoint target when configured.

#### Role 2
- Final meaning: Input to runtime bridge URL resolution chain where empty configured value triggers computed fallback URL derivation.
- Lifecycle: Dynamic read at poll-time resolution
- Effect type: Runtime URL resolution
- Operational impact: Allows bridge endpoint derivation to track runtime host-resolution conditions when explicit base is absent.

#### Final wording note
- Clean interpretation: `BRIDGE_BASE_URL` has both explicit configured-consumer semantics and runtime fallback-participation semantics; direct client behavior and fallback resolver behavior are distinct but coordinated.

SECTION 4 — Final Classification Snapshot

| Variable | Final lifecycle class | Final effect-type label(s) | Final confidence | Final correction status |
|---|---|---|---|---|
| RECIPIENT_FILTER_ENABLE_SMTP_PROBE | Startup-only (restart required) | Pre-send filtering | High | Finalized (effect-site proof integrated) |
| RECIPIENT_FILTER_SMTP_PROBE_LIMIT | Startup-only (restart required) | Pre-send filtering | High | Finalized (domain-scoped cap clarified) |
| SHIVA_DB_PATH | Startup-only (restart required) | Persistence | High | Finalized (read-to-connection chain explicit) |
| SHIVA_DB_WRITE_BATCH_SIZE | Startup-only (restart required) | Persistence | High | Finalized (transaction-batch semantics explicit) |
| DB_CLEAR_ON_START | Startup-only (restart required) | Persistence | High | Finalized (startup delete scope explicit) |
| SHIVA_BACKOFF_JITTER_PCT | Mixed — global value is reloadable, but active jobs may continue using a per-job runtime snapshot captured at job/thread start | Backoff / pacing | High | Finalized (placeholder removed; runtime nuance embedded) |
| SHIVA_BACKOFF_JITTER_EXPORT | Reloadable | Observability only | High | Finalized (telemetry-only effect bounded) |
| BRIDGE_BASE_URL | Mixed — explicit configured base URL is reloadable; runtime fallback derivation is dynamic at poll-time | Bridge ingestion, Runtime URL resolution | High | Finalized (dual-role lifecycle separated) |
| SHIVA_HOST | Mixed — bind role is startup-only; helper fallback role is dynamic read at call time | Server bind, Runtime URL resolution | High | Finalized (dual-role lifecycle separated) |

SECTION 5 — Final Residual Ambiguities
- No code-proven ambiguity remains for the finalized scope in this cleanup pass.
