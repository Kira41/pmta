# Final Master Report — `shiva.py` Direct `os.getenv(...)` Environment Variables

## 1) Scope and Count Verification

- **Scope:** This report covers only environment variables read by **direct literal** `os.getenv("NAME", ...)` calls inside `shiva.py`.
- **Out of scope:** variables read through helper wrappers (`get_env*`, `_env_*`, `cfg_get_*`) and non-literal/dynamic key lookups.
- **Verified count:** `shiva.py` contains **64 literal `os.getenv(...)` call sites** and **60 unique environment variable names**.
- **Literal duplicates (4 names, each read twice):**
  - `PMTA_DIAG_ON_ERROR`
  - `PMTA_DIAG_RATE_S`
  - `PMTA_QUEUE_TOP_N`
  - `SHIVA_HOST`

## 2) Global Lifecycle Model

1. **Module load / env parse:** most variables are parsed at import time into module globals (bool/int/float/string), with immediate coercion and default fallback.
2. **Normalization / clamping / fallback:** parse failures fall back to hardcoded defaults; several values are clamped or sanitized (e.g., jitter mode whitelist, thread bounds, scheme whitelist).
3. **Runtime decision points:** globals drive send admission checks, PMTA monitoring/backoff behavior, bridge poll behavior, blacklist checks, and diagnostics payload composition.
4. **Background loops / pollers / caches:** PMTA live/pressure/domain loops and bridge polling use these globals each cycle; cache TTL and poll interval knobs affect loop cadence and cache freshness.
5. **Startup-only vs reloadable vs dynamic-read:**
   - **Startup-only:** parsed once, effective only after restart.
   - **Reloadable:** can be reapplied at runtime through config reload paths that update the same globals.
   - **Dynamic-read:** read directly inside runtime helper functions per call.
   - **Mixed:** variable has more than one role with different lifecycle behavior.
6. **Operational scope nuance:** not every variable changes send pacing or acceptance; some only affect observability payloads, URL/path resolution, or persistence target/initialization semantics.

## 3) Dependency and Precedence Chains

- `SHIVA_DB_PATH -> SMTP_SENDER_DB_PATH -> APP_DIR/smtp_sender.db`
- `SHIVA_DISABLE_BLACKLIST -> DISABLE_BLACKLIST -> default false`
- `OUTCOMES_SYNC -> BRIDGE_POLL_FETCH_OUTCOMES -> default true`
- `BRIDGE_POLL_INTERVAL_S -> PMTA_BRIDGE_PULL_S -> 5.0`
- `PMTA_MONITOR_BASE_URL` **overrides** derived monitor URL from SMTP host + scheme logic.
- `SHIVA_HOST` bridge-helper fallback chain: campaign job SMTP host -> `SHIVA_HOST` (if not wildcard bind literal) -> `127.0.0.1`.
- `BRIDGE_BASE_URL`: explicit configured non-empty value wins; otherwise runtime derives `http://<resolved_host>:<PMTA_BRIDGE_PULL_PORT>`.
- DKIM selector chain: `DKIM_SELECTOR` + `DKIM_SELECTORS` + `DEFAULT_DKIM_SELECTOR`; if empty, fallback to internal common selector list.
- `BRIDGE_MODE`: env value parsed then normalized to `{counts, legacy}`, fallback `counts` on invalid values.

## 4) Variable-by-Variable Master Reference

### SPAMCHECK_BACKEND
- Lifecycle class: Reloadable
- Effect-type label(s): Spam-check backend selection
- Read / parse / normalize behavior: string; default `spamd`; lowercase.
- Precedence / fallback: direct env default only.
- Code-level effect: selects spam-check implementation branch.
- Runtime effect: changes which backend is used during checks.
- System-level operational effect: changes dependency path for spam verdict generation.
- What it does NOT change: does not change PMTA polling/backoff.
- Reload / restart / dynamic-read behavior: reloadable via runtime config reload.
- Misconfiguration consequence: invalid/unexpected value can route to unintended backend path.
- Proven status: PROVEN

### SPAMD_HOST
- Lifecycle class: Reloadable
- Effect-type label(s): Spam-check connectivity
- Read / parse / normalize behavior: string; default `127.0.0.1`; trimmed.
- Precedence / fallback: direct env default only.
- Code-level effect: target host for `spamd` socket calls.
- Runtime effect: changes destination of spamd queries.
- System-level operational effect: affects spam-check reachability.
- What it does NOT change: does not alter sender pacing or recipient caps.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: spam-check failures/timeouts.
- Proven status: PROVEN

### SPAMD_PORT
- Lifecycle class: Reloadable
- Effect-type label(s): Spam-check connectivity
- Read / parse / normalize behavior: int parse; default `783`; fallback on parse error.
- Precedence / fallback: direct env default only.
- Code-level effect: target port for spamd connection.
- Runtime effect: directs TCP endpoint.
- System-level operational effect: affects spam-check service reachability.
- What it does NOT change: no impact on PMTA monitor/bridge URL logic.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: connection refused or wrong service.
- Proven status: PROVEN

### SPAMD_TIMEOUT
- Lifecycle class: Reloadable
- Effect-type label(s): Spam-check timeout
- Read / parse / normalize behavior: float parse; default `5.0`; fallback on parse error.
- Precedence / fallback: direct env default only.
- Code-level effect: timeout for spamd operations.
- Runtime effect: bounds wait time for spam checks.
- System-level operational effect: shifts latency vs false-timeout risk.
- What it does NOT change: no effect on SMTP send backoff policy.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: too low -> excessive timeout errors; too high -> latency inflation.
- Proven status: PROVEN

### DNS_RESOLVER_NAMESERVERS
- Lifecycle class: Startup-only (restart required)
- Effect-type label(s): DNS resolution
- Read / parse / normalize behavior: comma-split list; trims entries; default public resolvers.
- Precedence / fallback: direct env default only.
- Code-level effect: initializes resolver nameserver set.
- Runtime effect: influences DNS query path for DNS-dependent checks.
- System-level operational effect: changes DNS resolution source and reliability profile.
- What it does NOT change: does not change PMTA bridge polling cadence.
- Reload / restart / dynamic-read behavior: startup-only.
- Misconfiguration consequence: lookup failures or degraded DNS quality.
- Proven status: PROVEN

### RECIPIENT_FILTER_ENABLE_SMTP_PROBE
- Lifecycle class: Startup-only (restart required)
- Effect-type label(s): Pre-send filtering gate
- Read / parse / normalize behavior: boolish parse; default true.
- Precedence / fallback: direct env default only.
- Code-level effect: gates SMTP probe branch in recipient pre-filtering.
- Runtime effect: toggles whether SMTP probe checks run.
- System-level operational effect: changes strictness of recipient admission hygiene.
- What it does NOT change: does not alter route syntax checks or pacing math.
- Reload / restart / dynamic-read behavior: startup-only.
- Misconfiguration consequence: disabled probe can admit more risky recipients.
- Proven status: PROVEN

### RECIPIENT_FILTER_ENABLE_ROUTE_CHECK
- Lifecycle class: Reloadable
- Effect-type label(s): Pre-send filtering gate
- Read / parse / normalize behavior: boolish parse; default true.
- Precedence / fallback: direct env default only.
- Code-level effect: gates route/domain validation branch.
- Runtime effect: toggles route-check pass before sending.
- System-level operational effect: changes pre-send validation strictness.
- What it does NOT change: does not cap chunk size/workers.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: disabled route checks may increase invalid-route attempts.
- Proven status: PROVEN

### RECIPIENT_FILTER_SMTP_PROBE_LIMIT
- Lifecycle class: Startup-only (restart required)
- Effect-type label(s): Pre-send filtering limit
- Read / parse / normalize behavior: int parse; default `25`; min clamp to `1`.
- Precedence / fallback: direct env default only.
- Code-level effect: caps domain-level SMTP probe set growth.
- Runtime effect: limits probe breadth.
- System-level operational effect: trades hygiene coverage vs filter latency.
- What it does NOT change: not a total recipient send cap.
- Reload / restart / dynamic-read behavior: startup-only.
- Misconfiguration consequence: too low under-samples domains; too high increases probe cost.
- Proven status: PROVEN

### RECIPIENT_FILTER_SMTP_TIMEOUT
- Lifecycle class: Startup-only (restart required)
- Effect-type label(s): Pre-send filtering timeout
- Read / parse / normalize behavior: float parse; default `5`; min clamp to `1.0`.
- Precedence / fallback: direct env default only.
- Code-level effect: timeout for probe SMTP checks.
- Runtime effect: bounds probe wait time.
- System-level operational effect: latency vs timeout sensitivity tradeoff.
- What it does NOT change: no impact on PMTA polling.
- Reload / restart / dynamic-read behavior: startup-only.
- Misconfiguration consequence: false negatives/positives due to timing skew.
- Proven status: PROVEN

### RECIPIENT_FILTER_ROUTE_THREADS
- Lifecycle class: Startup-only (restart required)
- Effect-type label(s): Pre-send filtering concurrency
- Read / parse / normalize behavior: int parse default `24`; clamped `1..64`.
- Precedence / fallback: direct env default only.
- Code-level effect: worker count for route checks.
- Runtime effect: parallelism of route validation.
- System-level operational effect: CPU/network load and filter throughput.
- What it does NOT change: no effect on send-loop worker caps.
- Reload / restart / dynamic-read behavior: startup-only.
- Misconfiguration consequence: too high can overuse resources.
- Proven status: PROVEN

### RECIPIENT_FILTER_SMTP_THREADS
- Lifecycle class: Startup-only (restart required)
- Effect-type label(s): Pre-send filtering concurrency
- Read / parse / normalize behavior: int parse default `8`; clamped `1..64`.
- Precedence / fallback: direct env default only.
- Code-level effect: worker count for SMTP probe threads.
- Runtime effect: parallel SMTP pre-probing.
- System-level operational effect: throughput/resource tradeoff.
- What it does NOT change: no direct impact on PMTA pressure policy.
- Reload / restart / dynamic-read behavior: startup-only.
- Misconfiguration consequence: excessive concurrency can stress upstream endpoints.
- Proven status: PROVEN

### SHIVA_DB_PATH
- Lifecycle class: Startup-only (restart required)
- Effect-type label(s): Persistence path
- Read / parse / normalize behavior: raw string; may be empty.
- Precedence / fallback: `SHIVA_DB_PATH -> SMTP_SENDER_DB_PATH -> APP_DIR/smtp_sender.db`.
- Code-level effect: sets `DB_PATH` used by DB connection helper.
- Runtime effect: selects SQLite file target for all DB I/O.
- System-level operational effect: controls persistence location and retention continuity.
- What it does NOT change: does not change write cadence logic.
- Reload / restart / dynamic-read behavior: startup-only.
- Misconfiguration consequence: writes to wrong path or inaccessible path errors.
- Proven status: PROVEN

### SMTP_SENDER_DB_PATH
- Lifecycle class: Startup-only (restart required)
- Effect-type label(s): Persistence path alias
- Read / parse / normalize behavior: raw string alias source.
- Precedence / fallback: only used when `SHIVA_DB_PATH` is empty.
- Code-level effect: legacy alias for DB path selection.
- Runtime effect: same persistence target role as `SHIVA_DB_PATH`.
- System-level operational effect: compatibility path control only.
- What it does NOT change: no effect on DB batching/queueing behavior.
- Reload / restart / dynamic-read behavior: startup-only.
- Misconfiguration consequence: unexpected DB file selected when primary key unset.
- Proven status: PROVEN

### SHIVA_DB_WRITE_BATCH_SIZE
- Lifecycle class: Startup-only (restart required)
- Effect-type label(s): Persistence write batching
- Read / parse / normalize behavior: int parse default `500`; clamped `50..1000`.
- Precedence / fallback: direct env default only.
- Code-level effect: max queued write items per transaction batch.
- Runtime effect: commit granularity in DB writer loop.
- System-level operational effect: throughput/latency/transaction-size tradeoff.
- What it does NOT change: not queue capacity.
- Reload / restart / dynamic-read behavior: startup-only.
- Misconfiguration consequence: too low overhead-heavy; too high larger commit bursts.
- Proven status: PROVEN

### SHIVA_DB_WRITE_QUEUE_MAX
- Lifecycle class: Startup-only (restart required)
- Effect-type label(s): Persistence queue capacity
- Read / parse / normalize behavior: int parse default `50000`; minimum clamp `1000`.
- Precedence / fallback: direct env default only.
- Code-level effect: queue size ceiling for buffered DB writes.
- Runtime effect: controls in-memory buffering before backpressure/drop behavior.
- System-level operational effect: memory footprint and write burst tolerance.
- What it does NOT change: does not alter per-commit batch size.
- Reload / restart / dynamic-read behavior: startup-only.
- Misconfiguration consequence: too low can increase queue saturation risk.
- Proven status: PROVEN

### DB_CLEAR_ON_START
- Lifecycle class: Startup-only (restart required)
- Effect-type label(s): Persistence initialization
- Read / parse / normalize behavior: boolish parse; default false.
- Precedence / fallback: direct env default only.
- Code-level effect: startup table-row clearing in DB init path.
- Runtime effect: one-time destructive cleanup at process start.
- System-level operational effect: resets persisted operational history/state.
- What it does NOT change: does not drop schema/file.
- Reload / restart / dynamic-read behavior: startup-only.
- Misconfiguration consequence: unintended data loss at startup.
- Proven status: PROVEN

### RBL_ZONES
- Lifecycle class: Reloadable
- Effect-type label(s): DNSBL policy data
- Read / parse / normalize behavior: comma list string; default fixed RBL list; parsed into normalized zone list.
- Precedence / fallback: direct env default only.
- Code-level effect: source zones for IP blacklist queries.
- Runtime effect: changes DNSBL lookup targets.
- System-level operational effect: modifies blacklist screening policy coverage.
- What it does NOT change: no pacing/backoff effect.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: false positives/negatives or lookup failures.
- Proven status: PROVEN

### DBL_ZONES
- Lifecycle class: Reloadable
- Effect-type label(s): DNSBL policy data
- Read / parse / normalize behavior: comma list string; default `dbl.spamhaus.org`; parsed list.
- Precedence / fallback: direct env default only.
- Code-level effect: source zones for domain blacklist queries.
- Runtime effect: changes DBL lookup targets.
- System-level operational effect: modifies domain blacklist coverage.
- What it does NOT change: does not alter SMTP probe threading.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: reduced/incorrect domain risk detection.
- Proven status: PROVEN

### SHIVA_DISABLE_BLACKLIST
- Lifecycle class: Reloadable
- Effect-type label(s): DNSBL gating
- Read / parse / normalize behavior: boolish parse with alias chain.
- Precedence / fallback: `SHIVA_DISABLE_BLACKLIST -> DISABLE_BLACKLIST -> false`.
- Code-level effect: disables blacklist query branches when true.
- Runtime effect: turns blacklist checks on/off.
- System-level operational effect: shifts deliverability risk posture.
- What it does NOT change: no PMTA monitor URL behavior.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: disabling can suppress critical blacklist signals.
- Proven status: PROVEN

### DISABLE_BLACKLIST
- Lifecycle class: Reloadable (alias)
- Effect-type label(s): DNSBL gating alias
- Read / parse / normalize behavior: only consulted when primary key absent.
- Precedence / fallback: lower-priority alias behind `SHIVA_DISABLE_BLACKLIST`.
- Code-level effect: legacy compatibility input for same gate.
- Runtime effect: same as primary when selected.
- System-level operational effect: same as primary.
- What it does NOT change: no independent behavior beyond alias role.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: unexpected gate state if alias conflicts with primary.
- Proven status: PROVEN

### DKIM_SELECTOR
- Lifecycle class: Dynamic-read
- Effect-type label(s): DKIM selector resolution
- Read / parse / normalize behavior: read per-call; comma/semicolon normalized list.
- Precedence / fallback: part of combined selector chain before defaults.
- Code-level effect: candidate selector source.
- Runtime effect: affects selector list returned for domain state computations.
- System-level operational effect: diagnostics/policy visibility for DKIM readiness.
- What it does NOT change: does not sign mail or alter PMTA behavior directly in this path.
- Reload / restart / dynamic-read behavior: dynamic-read each helper call.
- Misconfiguration consequence: empty/invalid selectors reduce DKIM readiness signal quality.
- Proven status: PROVEN

### DKIM_SELECTORS
- Lifecycle class: Dynamic-read
- Effect-type label(s): DKIM selector resolution
- Read / parse / normalize behavior: per-call list source; normalized with chain.
- Precedence / fallback: combined with singular/default keys.
- Code-level effect: additional selector candidates.
- Runtime effect: extends/overrides computed selector set.
- System-level operational effect: domain state visibility impact.
- What it does NOT change: no send pacing/backoff effect.
- Reload / restart / dynamic-read behavior: dynamic-read.
- Misconfiguration consequence: malformed list can reduce selector usefulness.
- Proven status: PROVEN

### DEFAULT_DKIM_SELECTOR
- Lifecycle class: Dynamic-read
- Effect-type label(s): DKIM selector resolution
- Read / parse / normalize behavior: per-call fallback selector source.
- Precedence / fallback: lower-priority member of selector chain before built-in defaults.
- Code-level effect: contributes fallback selector candidate.
- Runtime effect: affects returned selector list when other keys empty.
- System-level operational effect: DKIM readiness reporting stability.
- What it does NOT change: no direct SMTP send parameter enforcement.
- Reload / restart / dynamic-read behavior: dynamic-read.
- Misconfiguration consequence: missing useful fallback selector in diagnostics.
- Proven status: PROVEN

### PMTA_MONITOR_TIMEOUT_S
- Lifecycle class: Reloadable
- Effect-type label(s): PMTA monitor HTTP behavior
- Read / parse / normalize behavior: float parse default `3.0`.
- Precedence / fallback: direct env default only.
- Code-level effect: timeout for PMTA monitor HTTP calls.
- Runtime effect: bounds monitor request wait.
- System-level operational effect: health-check responsiveness vs transient-failure sensitivity.
- What it does NOT change: no bridge poll interval effect.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: false unreachable or slow feedback.
- Proven status: PROVEN

### PMTA_MONITOR_BASE_URL
- Lifecycle class: Reloadable
- Effect-type label(s): PMTA monitor endpoint override
- Read / parse / normalize behavior: trimmed string; empty allowed.
- Precedence / fallback: explicit value overrides host/scheme-derived URL.
- Code-level effect: direct base URL used by PMTA monitor probes.
- Runtime effect: monitor target can switch to configured endpoint.
- System-level operational effect: controls PMTA observability target routing.
- What it does NOT change: does not alter SMTP host used for sending.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: monitor probes target wrong/unreachable endpoint.
- Proven status: PROVEN

### PMTA_MONITOR_SCHEME
- Lifecycle class: Reloadable
- Effect-type label(s): PMTA monitor URL derivation
- Read / parse / normalize behavior: lowercase; valid set `{auto,http,https}` else `auto`.
- Precedence / fallback: ignored when base URL override is set.
- Code-level effect: selects scheme for derived PMTA base URL.
- Runtime effect: toggles protocol used in derived monitor calls.
- System-level operational effect: compatibility/security posture for monitor access.
- What it does NOT change: no effect when explicit base URL provided.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: repeated monitor connect/SSL issues.
- Proven status: PROVEN

### PMTA_MONITOR_API_KEY
- Lifecycle class: Reloadable
- Effect-type label(s): PMTA monitor authentication
- Read / parse / normalize behavior: trimmed string token.
- Precedence / fallback: direct env default empty.
- Code-level effect: sets `X-API-Key` request header when non-empty.
- Runtime effect: changes auth credentials for monitor requests.
- System-level operational effect: monitor access authorization.
- What it does NOT change: no influence on send strategy controls.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: 401/403 or monitor probe failure.
- Proven status: PROVEN

### PMTA_HEALTH_REQUIRED
- Lifecycle class: Reloadable
- Effect-type label(s): PMTA health gating policy
- Read / parse / normalize behavior: boolish parse; default true.
- Precedence / fallback: direct env default only.
- Code-level effect: controls strict blocking vs warn-only when PMTA data unavailable.
- Runtime effect: changes admission/gating behavior on monitor failure.
- System-level operational effect: operational risk posture during PMTA visibility loss.
- What it does NOT change: does not tune backoff coefficients directly.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: over-blocking or under-protection under monitor outage.
- Proven status: PROVEN

### PMTA_DIAG_ON_ERROR
- Lifecycle class: Reloadable
- Effect-type label(s): Observability only
- Read / parse / normalize behavior: boolish parse; duplicated literal read; default true.
- Precedence / fallback: direct env default only.
- Code-level effect: gates diagnostic snapshot emission paths.
- Runtime effect: toggles extra diagnostics when errors occur.
- System-level operational effect: logging/telemetry volume only.
- What it does NOT change: does not alter send/backoff decisions.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: missing troubleshooting data or noisy logs.
- Proven status: PROVEN

### PMTA_DIAG_RATE_S
- Lifecycle class: Reloadable
- Effect-type label(s): Observability only
- Read / parse / normalize behavior: float parse; duplicated literal read; default `1.0`.
- Precedence / fallback: direct env default only.
- Code-level effect: throttles diagnostic emission cadence.
- Runtime effect: rate-limits error diagnostics.
- System-level operational effect: controls telemetry/log burstiness.
- What it does NOT change: not a send pacing knob.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: too low noisy logs; too high sparse diagnostics.
- Proven status: PROVEN

### PMTA_QUEUE_TOP_N
- Lifecycle class: Reloadable
- Effect-type label(s): Observability only
- Read / parse / normalize behavior: int parse; duplicated literal read; default `6`.
- Precedence / fallback: direct env default only.
- Code-level effect: caps number of top queue entries included in diagnostics/live snapshots.
- Runtime effect: changes detail depth in monitor outputs.
- System-level operational effect: observability granularity and payload size.
- What it does NOT change: no effect on queue processing itself.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: insufficient or overly heavy diagnostics payload.
- Proven status: PROVEN

### PMTA_QUEUE_BACKOFF
- Lifecycle class: Reloadable
- Effect-type label(s): Backoff policy gate
- Read / parse / normalize behavior: boolish parse default true.
- Precedence / fallback: direct env default only.
- Code-level effect: enables queue-driven backoff policy branch.
- Runtime effect: toggles adaptive slowdown from PMTA queue state.
- System-level operational effect: affects traffic pressure response.
- What it does NOT change: does not disable all backoff sources by itself.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: disabled queue backoff can increase overload risk.
- Proven status: PROVEN

### PMTA_QUEUE_REQUIRED
- Lifecycle class: Reloadable
- Effect-type label(s): PMTA data strictness gate
- Read / parse / normalize behavior: boolish parse default false.
- Precedence / fallback: direct env default only.
- Code-level effect: if true, missing queue detail can produce blocked state.
- Runtime effect: strictness of queue-data dependency.
- System-level operational effect: availability vs safety tradeoff.
- What it does NOT change: does not set queue thresholds.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: unnecessary blocking when PMTA detail endpoint is unstable.
- Proven status: PROVEN

### SHIVA_DISABLE_BACKOFF
- Lifecycle class: Reloadable
- Effect-type label(s): Backoff policy gate
- Read / parse / normalize behavior: boolish parse default false.
- Precedence / fallback: direct env default only.
- Code-level effect: global disable switch for backoff logic paths.
- Runtime effect: bypasses backoff-driven pacing reductions.
- System-level operational effect: can increase throughput and overload risk.
- What it does NOT change: does not disable PMTA diagnostics collection.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: elevated deferrals/errors due to no throttling.
- Proven status: PROVEN

### SHIVA_BACKOFF_JITTER
- Lifecycle class: Reloadable
- Effect-type label(s): Backoff pacing shape
- Read / parse / normalize behavior: lowercase string; valid `{off,deterministic,random}` else `off`.
- Precedence / fallback: direct env default `off`.
- Code-level effect: selects jitter strategy for computed delays.
- Runtime effect: changes delay variability behavior.
- System-level operational effect: affects burst smoothing and timing spread.
- What it does NOT change: not a retry-count limiter.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: unintended deterministic/no-jitter behavior.
- Proven status: PROVEN

### SHIVA_BACKOFF_JITTER_PCT
- Lifecycle class: Mixed (reloadable global; active job snapshots may continue old value)
- Effect-type label(s): Backoff pacing amplitude
- Read / parse / normalize behavior: float parse default `0.15`; reload path clamps `>=0`.
- Precedence / fallback: direct env default only.
- Code-level effect: percentage amplitude for jitter offset.
- Runtime effect: changes size of delay perturbation.
- System-level operational effect: pacing smoothness vs variability.
- What it does NOT change: no direct impact on recipient filtering.
- Reload / restart / dynamic-read behavior: mixed runtime behavior.
- Misconfiguration consequence: too large jitter causes unstable pacing.
- Proven status: PROVEN

### SHIVA_BACKOFF_JITTER_MAX_S
- Lifecycle class: Reloadable
- Effect-type label(s): Backoff pacing clamp
- Read / parse / normalize behavior: float parse default `120`; reload clamp `>=0`.
- Precedence / fallback: direct env default only.
- Code-level effect: upper bound for jitter contribution.
- Runtime effect: caps positive jitter offset.
- System-level operational effect: prevents excessive random delay spikes.
- What it does NOT change: not base backoff duration.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: overly high cap can over-slow retries.
- Proven status: PROVEN

### SHIVA_BACKOFF_JITTER_MIN_S
- Lifecycle class: Reloadable
- Effect-type label(s): Backoff pacing clamp
- Read / parse / normalize behavior: float parse default `0`; reload clamp `>=0`.
- Precedence / fallback: direct env default only.
- Code-level effect: lower bound for jitter contribution.
- Runtime effect: prevents jitter floor below configured minimum.
- System-level operational effect: controls minimum delay perturbation.
- What it does NOT change: does not define retry schedule alone.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: too high floor removes responsive fast retries.
- Proven status: PROVEN

### SHIVA_BACKOFF_JITTER_EXPORT
- Lifecycle class: Reloadable
- Effect-type label(s): Observability only
- Read / parse / normalize behavior: boolish parse default false.
- Precedence / fallback: direct env default only.
- Code-level effect: toggles jitter metadata export in diagnostics/debug payload.
- Runtime effect: changes telemetry content only.
- System-level operational effect: observability detail level.
- What it does NOT change: no backoff math change.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: absent or excessive debug data.
- Proven status: PROVEN

### SHIVA_BACKOFF_JITTER_DEBUG
- Lifecycle class: Reloadable
- Effect-type label(s): Observability only
- Read / parse / normalize behavior: boolish parse default false.
- Precedence / fallback: direct env default only.
- Code-level effect: enables extra jitter debug logs/fields.
- Runtime effect: diagnostics verbosity toggle.
- System-level operational effect: troubleshooting visibility only.
- What it does NOT change: does not alter pacing logic outputs.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: noisy logging or insufficient debug detail.
- Proven status: PROVEN

### PMTA_LIVE_POLL_S
- Lifecycle class: Reloadable
- Effect-type label(s): PMTA poll cadence
- Read / parse / normalize behavior: float parse default `3`.
- Precedence / fallback: direct env default only.
- Code-level effect: sleep/cadence for PMTA live polling loop(s).
- Runtime effect: changes monitoring refresh frequency.
- System-level operational effect: monitor freshness vs API load.
- What it does NOT change: does not change bridge polling interval.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: stale data or excess polling overhead.
- Proven status: PROVEN

### PMTA_DOMAIN_CHECK_TOP_N
- Lifecycle class: Reloadable
- Effect-type label(s): PMTA domain detail scope
- Read / parse / normalize behavior: int parse default `2`.
- Precedence / fallback: direct env default only.
- Code-level effect: top-domain count used in PMTA detail checks.
- Runtime effect: changes breadth of per-domain pressure sampling.
- System-level operational effect: detail fidelity vs API/query cost.
- What it does NOT change: no direct queue threshold values.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: low coverage or unnecessary overhead.
- Proven status: PROVEN

### PMTA_DETAIL_CACHE_TTL_S
- Lifecycle class: Reloadable
- Effect-type label(s): PMTA detail cache behavior
- Read / parse / normalize behavior: float parse default `3`.
- Precedence / fallback: direct env default only.
- Code-level effect: TTL for PMTA detail cache entries.
- Runtime effect: controls cache reuse window.
- System-level operational effect: freshness vs request volume tradeoff.
- What it does NOT change: no effect on DB persistence path.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: stale detail views or high request rate.
- Proven status: PROVEN

### PMTA_PRESSURE_CONTROL
- Lifecycle class: Reloadable
- Effect-type label(s): Pressure policy gate
- Read / parse / normalize behavior: boolish parse default true.
- Precedence / fallback: direct env default only.
- Code-level effect: enables global PMTA-pressure adaptive policy.
- Runtime effect: toggles pressure-derived limits.
- System-level operational effect: controls protective throttling behavior.
- What it does NOT change: does not itself set pressure thresholds.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: disabled protection under high PMTA load.
- Proven status: PROVEN

### PMTA_PRESSURE_POLL_S
- Lifecycle class: Reloadable
- Effect-type label(s): Pressure polling cadence
- Read / parse / normalize behavior: float parse default `3`.
- Precedence / fallback: direct env default only.
- Code-level effect: interval for pressure sampling loop.
- Runtime effect: changes pressure-policy response latency.
- System-level operational effect: responsiveness vs monitoring overhead.
- What it does NOT change: no change to pressure level boundaries.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: slow reaction or excessive polling.
- Proven status: PROVEN

### PMTA_DOMAIN_STATS
- Lifecycle class: Reloadable
- Effect-type label(s): Domain statistics collection gate
- Read / parse / normalize behavior: boolish parse default true.
- Precedence / fallback: direct env default only.
- Code-level effect: enables/disables domain stats loop.
- Runtime effect: toggles per-domain stats tracking.
- System-level operational effect: domain-level observability availability.
- What it does NOT change: no direct send pacing changes when disabled.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: loss of domain granularity for diagnostics/policy.
- Proven status: PROVEN

### PMTA_DOMAINS_POLL_S
- Lifecycle class: Reloadable
- Effect-type label(s): Domain stats polling cadence
- Read / parse / normalize behavior: float parse default `4`.
- Precedence / fallback: direct env default only.
- Code-level effect: interval for domain stats polling.
- Runtime effect: adjusts refresh rate of domain stats.
- System-level operational effect: freshness vs polling load.
- What it does NOT change: no effect on bridge outcomes sync.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: stale domain signals or high overhead.
- Proven status: PROVEN

### PMTA_DOMAINS_TOP_N
- Lifecycle class: Reloadable
- Effect-type label(s): Domain stats scope
- Read / parse / normalize behavior: int parse default `6`.
- Precedence / fallback: direct env default only.
- Code-level effect: number of top domains included in stats snapshots.
- Runtime effect: controls per-cycle domain sample breadth.
- System-level operational effect: observability granularity vs payload size.
- What it does NOT change: no influence on SMTP probe count.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: under/over detailed stats output.
- Proven status: PROVEN

### PMTA_BRIDGE_PULL_ENABLED
- Lifecycle class: Reloadable
- Effect-type label(s): Bridge ingestion gate
- Read / parse / normalize behavior: boolish parse default true.
- Precedence / fallback: direct env default only.
- Code-level effect: enables background bridge pull behavior.
- Runtime effect: starts/stops effective bridge ingestion logic.
- System-level operational effect: controls whether accounting ingestion is active.
- What it does NOT change: no direct PMTA monitor endpoint selection.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: accounting data stale/unavailable when disabled.
- Proven status: PROVEN

### BRIDGE_MODE
- Lifecycle class: Reloadable
- Effect-type label(s): Bridge ingestion mode selection
- Read / parse / normalize behavior: lowercase; valid `{counts,legacy}` else `counts`.
- Precedence / fallback: direct env default `counts`.
- Code-level effect: selects bridge polling path semantics.
- Runtime effect: switches count-mode vs legacy-style behavior.
- System-level operational effect: changes bridge API usage pattern.
- What it does NOT change: no SMTP send worker limits.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: mode fallback to `counts` may differ from intended workflow.
- Proven status: PROVEN

### PMTA_BRIDGE_PULL_PORT
- Lifecycle class: Reloadable
- Effect-type label(s): Bridge URL resolution
- Read / parse / normalize behavior: int parse default `8090`; fallback on parse error.
- Precedence / fallback: direct env default only.
- Code-level effect: port in derived bridge base/pull URL builders.
- Runtime effect: changes bridge HTTP destination port.
- System-level operational effect: connectivity target selection.
- What it does NOT change: no effect on poll interval timing.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: connection failures to bridge API.
- Proven status: PROVEN

### BRIDGE_BASE_URL
- Lifecycle class: Mixed (reloadable explicit value; dynamic runtime derivation when empty)
- Effect-type label(s): Bridge ingestion, Runtime URL resolution
- Read / parse / normalize behavior: trimmed string; empty allowed.
- Precedence / fallback: explicit non-empty value wins; else derived from resolved host and pull port.
- Code-level effect: direct client calls require configured base; poller resolver may assign derived base.
- Runtime effect: target endpoint may be explicit or computed per poll cycle.
- System-level operational effect: determines bridge traffic destination and failover behavior.
- What it does NOT change: no SMTP send pacing logic.
- Reload / restart / dynamic-read behavior: mixed.
- Misconfiguration consequence: empty/invalid base can break direct bridge calls or misroute polling.
- Proven status: PROVEN

### BRIDGE_TIMEOUT_S
- Lifecycle class: Startup-only (restart required)
- Effect-type label(s): Bridge HTTP behavior
- Read / parse / normalize behavior: float parse default `20`; fallback on parse error.
- Precedence / fallback: direct env default only.
- Code-level effect: timeout for bridge HTTP requests.
- Runtime effect: controls max wait per bridge call.
- System-level operational effect: ingestion resilience vs latency.
- What it does NOT change: no PMTA monitor timeout.
- Reload / restart / dynamic-read behavior: startup-only in current reload path.
- Misconfiguration consequence: poll timeouts or long blocking waits.
- Proven status: PROVEN

### PMTA_BRIDGE_PULL_S
- Lifecycle class: Reloadable
- Effect-type label(s): Bridge polling cadence default
- Read / parse / normalize behavior: float parse default `5.0`.
- Precedence / fallback: used as fallback for `BRIDGE_POLL_INTERVAL_S`.
- Code-level effect: baseline bridge poll interval source.
- Runtime effect: changes poll sleep cadence when explicit poll interval absent.
- System-level operational effect: ingestion freshness vs load.
- What it does NOT change: no direct impact on outcomes fetch enablement.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: over/under polling bridge service.
- Proven status: PROVEN

### BRIDGE_POLL_INTERVAL_S
- Lifecycle class: Reloadable
- Effect-type label(s): Bridge polling cadence
- Read / parse / normalize behavior: float parse, defaulting to `PMTA_BRIDGE_PULL_S` then `5.0`.
- Precedence / fallback: `BRIDGE_POLL_INTERVAL_S -> PMTA_BRIDGE_PULL_S -> 5.0`.
- Code-level effect: primary sleep interval for bridge poll loop.
- Runtime effect: directly controls poll frequency.
- System-level operational effect: data freshness / API pressure tradeoff.
- What it does NOT change: no effect on bridge host derivation logic.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: stale accounting state or excessive bridge load.
- Proven status: PROVEN

### OUTCOMES_SYNC
- Lifecycle class: Reloadable
- Effect-type label(s): Bridge outcomes ingestion gate
- Read / parse / normalize behavior: raw env may be None; boolish parse after alias fallback.
- Precedence / fallback: `OUTCOMES_SYNC -> BRIDGE_POLL_FETCH_OUTCOMES -> true`.
- Code-level effect: controls whether outcomes endpoint is fetched.
- Runtime effect: toggles per-recipient outcomes synchronization.
- System-level operational effect: granularity of accounting reconciliation data.
- What it does NOT change: no bridge poll schedule change.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: missing outcomes detail when unintentionally disabled.
- Proven status: PROVEN

### BRIDGE_POLL_FETCH_OUTCOMES
- Lifecycle class: Reloadable (alias)
- Effect-type label(s): Bridge outcomes ingestion gate alias
- Read / parse / normalize behavior: read as fallback alias; then runtime boolean mirrors `OUTCOMES_SYNC` chain.
- Precedence / fallback: secondary to `OUTCOMES_SYNC` for initial parse.
- Code-level effect: legacy key for same outcomes-fetch switch.
- Runtime effect: same outcomes enable/disable behavior.
- System-level operational effect: same as primary key.
- What it does NOT change: no independent scheduling behavior.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: conflicting alias intent can be overridden by primary key.
- Proven status: PROVEN

### PMTA_BRIDGE_PULL_MAX_LINES
- Lifecycle class: Reloadable
- Effect-type label(s): Bridge batch size / URL resolution parameter
- Read / parse / normalize behavior: int parse default `2000`; fallback on parse error.
- Precedence / fallback: direct env default only.
- Code-level effect: max lines per bridge pull; also embedded in legacy pull URL query.
- Runtime effect: controls per-cycle fetch size.
- System-level operational effect: throughput vs payload size/latency.
- What it does NOT change: does not select bridge host.
- Reload / restart / dynamic-read behavior: reloadable.
- Misconfiguration consequence: too low slows catch-up; too high increases burst load.
- Proven status: PROVEN

### SHIVA_HOST
- Lifecycle class: Mixed (startup bind + dynamic helper fallback read)
- Effect-type label(s): Server bind, Runtime URL resolution
- Read / parse / normalize behavior: startup read default `0.0.0.0`; helper read default empty.
- Precedence / fallback: helper path uses campaign host first; then non-wildcard `SHIVA_HOST`; then `127.0.0.1`.
- Code-level effect: Flask bind host at startup; fallback host source for bridge runtime resolver.
- Runtime effect: controls listen interface and helper host fallback behavior.
- System-level operational effect: network exposure + fallback bridge reachability.
- What it does NOT change: does not force all SMTP job hosts.
- Reload / restart / dynamic-read behavior: mixed.
- Misconfiguration consequence: unintended bind surface or wrong fallback endpoint.
- Proven status: PROVEN

### SHIVA_PORT
- Lifecycle class: Startup-only (restart required)
- Effect-type label(s): Server bind
- Read / parse / normalize behavior: int parse default `5001`; fallback on parse error.
- Precedence / fallback: direct env default only.
- Code-level effect: Flask listen port.
- Runtime effect: determines serving port for HTTP API/UI.
- System-level operational effect: service reachability and port-level routing.
- What it does NOT change: no bridge polling semantics.
- Reload / restart / dynamic-read behavior: startup-only.
- Misconfiguration consequence: port conflict or unreachable service port.
- Proven status: PROVEN

## 5) Final Classification Matrix

| Variable | Lifecycle class | Effect-type label(s) | Confidence | Notes |
|---|---|---|---|---|
| SPAMCHECK_BACKEND | Reloadable | Spam-check backend selection | High | Backend branch selector |
| SPAMD_HOST | Reloadable | Spam-check connectivity | High | Host endpoint |
| SPAMD_PORT | Reloadable | Spam-check connectivity | High | Port endpoint |
| SPAMD_TIMEOUT | Reloadable | Spam-check timeout | High | Timeout control |
| DNS_RESOLVER_NAMESERVERS | Startup-only | DNS resolution | High | Resolver list at init |
| RECIPIENT_FILTER_ENABLE_SMTP_PROBE | Startup-only | Pre-send filtering gate | High | SMTP probe gate |
| RECIPIENT_FILTER_ENABLE_ROUTE_CHECK | Reloadable | Pre-send filtering gate | High | Route-check gate |
| RECIPIENT_FILTER_SMTP_PROBE_LIMIT | Startup-only | Pre-send filtering limit | High | Domain probe cap |
| RECIPIENT_FILTER_SMTP_TIMEOUT | Startup-only | Pre-send filtering timeout | High | Probe timeout |
| RECIPIENT_FILTER_ROUTE_THREADS | Startup-only | Pre-send filtering concurrency | High | Thread clamp |
| RECIPIENT_FILTER_SMTP_THREADS | Startup-only | Pre-send filtering concurrency | High | Thread clamp |
| SHIVA_DB_PATH | Startup-only | Persistence path | High | Primary DB path |
| SMTP_SENDER_DB_PATH | Startup-only | Persistence path alias | High | Legacy alias |
| SHIVA_DB_WRITE_BATCH_SIZE | Startup-only | Persistence write batching | High | Transaction batch cap |
| SHIVA_DB_WRITE_QUEUE_MAX | Startup-only | Persistence queue capacity | High | Queue size floor |
| DB_CLEAR_ON_START | Startup-only | Persistence initialization | High | Startup table clear |
| RBL_ZONES | Reloadable | DNSBL policy data | High | IP blacklist zones |
| DBL_ZONES | Reloadable | DNSBL policy data | High | Domain blacklist zones |
| SHIVA_DISABLE_BLACKLIST | Reloadable | DNSBL gating | High | Primary disable key |
| DISABLE_BLACKLIST | Reloadable | DNSBL gating alias | High | Legacy alias |
| DKIM_SELECTOR | Dynamic-read | DKIM selector resolution | High | Per-call read |
| DKIM_SELECTORS | Dynamic-read | DKIM selector resolution | High | Per-call read |
| DEFAULT_DKIM_SELECTOR | Dynamic-read | DKIM selector resolution | High | Per-call read |
| PMTA_MONITOR_TIMEOUT_S | Reloadable | PMTA monitor HTTP behavior | High | Request timeout |
| PMTA_MONITOR_BASE_URL | Reloadable | PMTA monitor endpoint override | High | Explicit override wins |
| PMTA_MONITOR_SCHEME | Reloadable | PMTA monitor URL derivation | High | Used when no base override |
| PMTA_MONITOR_API_KEY | Reloadable | PMTA monitor authentication | High | X-API-Key header |
| PMTA_HEALTH_REQUIRED | Reloadable | PMTA health gating policy | High | Block vs warn behavior |
| PMTA_DIAG_ON_ERROR | Reloadable | Observability only | High | Duplicate literal read |
| PMTA_DIAG_RATE_S | Reloadable | Observability only | High | Duplicate literal read |
| PMTA_QUEUE_TOP_N | Reloadable | Observability only | High | Duplicate literal read |
| PMTA_QUEUE_BACKOFF | Reloadable | Backoff policy gate | High | Queue-based slowdown gate |
| PMTA_QUEUE_REQUIRED | Reloadable | PMTA data strictness gate | High | Missing detail strictness |
| SHIVA_DISABLE_BACKOFF | Reloadable | Backoff policy gate | High | Global backoff disable |
| SHIVA_BACKOFF_JITTER | Reloadable | Backoff pacing shape | High | Mode whitelist |
| SHIVA_BACKOFF_JITTER_PCT | Mixed | Backoff pacing amplitude | High | Reload + snapshot nuance |
| SHIVA_BACKOFF_JITTER_MAX_S | Reloadable | Backoff pacing clamp | High | Upper jitter bound |
| SHIVA_BACKOFF_JITTER_MIN_S | Reloadable | Backoff pacing clamp | High | Lower jitter bound |
| SHIVA_BACKOFF_JITTER_EXPORT | Reloadable | Observability only | High | Telemetry payload toggle |
| SHIVA_BACKOFF_JITTER_DEBUG | Reloadable | Observability only | High | Debug verbosity toggle |
| PMTA_LIVE_POLL_S | Reloadable | PMTA poll cadence | High | Live poll interval |
| PMTA_DOMAIN_CHECK_TOP_N | Reloadable | PMTA domain detail scope | High | Domain detail breadth |
| PMTA_DETAIL_CACHE_TTL_S | Reloadable | PMTA detail cache behavior | High | Cache freshness window |
| PMTA_PRESSURE_CONTROL | Reloadable | Pressure policy gate | High | Enables pressure policy |
| PMTA_PRESSURE_POLL_S | Reloadable | Pressure polling cadence | High | Pressure interval |
| PMTA_DOMAIN_STATS | Reloadable | Domain statistics collection gate | High | Domain stats on/off |
| PMTA_DOMAINS_POLL_S | Reloadable | Domain stats polling cadence | High | Domain stats interval |
| PMTA_DOMAINS_TOP_N | Reloadable | Domain stats scope | High | Top-N domain coverage |
| PMTA_BRIDGE_PULL_ENABLED | Reloadable | Bridge ingestion gate | High | Poller behavior gate |
| BRIDGE_MODE | Reloadable | Bridge ingestion mode selection | High | counts/legacy normalized |
| PMTA_BRIDGE_PULL_PORT | Reloadable | Bridge URL resolution | High | Port for derived URL |
| BRIDGE_BASE_URL | Mixed | Bridge ingestion; Runtime URL resolution | High | Explicit vs derived base |
| BRIDGE_TIMEOUT_S | Startup-only | Bridge HTTP behavior | High | Not reloaded in runtime path |
| PMTA_BRIDGE_PULL_S | Reloadable | Bridge polling cadence default | High | Fallback interval source |
| BRIDGE_POLL_INTERVAL_S | Reloadable | Bridge polling cadence | High | Primary poll interval |
| OUTCOMES_SYNC | Reloadable | Bridge outcomes ingestion gate | High | Primary key |
| BRIDGE_POLL_FETCH_OUTCOMES | Reloadable | Bridge outcomes ingestion gate alias | High | Legacy alias |
| PMTA_BRIDGE_PULL_MAX_LINES | Reloadable | Bridge batch size / URL parameter | High | Pull batch bound |
| SHIVA_HOST | Mixed | Server bind; Runtime URL resolution | High | Startup bind + helper fallback |
| SHIVA_PORT | Startup-only | Server bind | High | Startup Flask port |

## 6) Final Corrections to Earlier Drafting

- Corrected **read-site vs effect-site** confusion by mapping each variable to its actual behavior branch (not only where it is parsed).
- Corrected **domain-cap vs recipient-cap** wording for `RECIPIENT_FILTER_SMTP_PROBE_LIMIT` (domain probe coverage cap, not total recipient cap).
- Corrected **persistence path vs write cadence** separation (`SHIVA_DB_PATH` family selects file; batch/queue keys control write mechanics).
- Corrected **diagnostics vs pacing** separation (`PMTA_DIAG_*`, `PMTA_QUEUE_TOP_N`, and jitter export/debug are observability-only).
- Corrected **dual-role variable treatment** for `SHIVA_HOST` and `BRIDGE_BASE_URL` by splitting lifecycle/effect by role.
- Corrected **alias/precedence chains** (`SHIVA_DISABLE_BLACKLIST` alias chain, outcomes alias chain, poll interval fallback chain, PMTA base URL override rule).

## 7) Final Residual Ambiguities

- **No remaining code-proven ambiguities** within this finalized scope.
