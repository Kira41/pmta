# SECTION 1 — Executive Clarification Summary

## Top unclear areas in the previous draft
- It mixed **read site** and **effect site** for several variables (for example DB path resolution and bridge URL resolution were treated as full behavior).
- It did not consistently separate **startup env parse** from **live runtime overrides** (`reload_runtime_config`) and therefore lifecycle was partially blurred.
- It did not explicitly prove where fallback chains end (notably `OUTCOMES_SYNC`, `SHIVA_DISABLE_BLACKLIST`, bridge poll interval fallback).
- It under-explained variables that are read via env but only influence **diagnostics/visibility** vs. actual send execution.
- It did not explicitly state that literal `os.getenv(...)` count is **60 unique names** (64 calls due to duplicates).

## Top variables needing deeper proof
- `SHIVA_DB_PATH`, `SMTP_SENDER_DB_PATH`, `DB_CLEAR_ON_START`, `SHIVA_DB_WRITE_BATCH_SIZE`, `SHIVA_DB_WRITE_QUEUE_MAX` (path/queue/flush timing distinction).
- `PMTA_MONITOR_BASE_URL` vs `PMTA_MONITOR_SCHEME` (override precedence + real URL builder usage).
- `PMTA_QUEUE_BACKOFF`, `PMTA_QUEUE_REQUIRED`, `SHIVA_DISABLE_BACKOFF` (blocking/slowdown disable interplay).
- `OUTCOMES_SYNC` vs `BRIDGE_POLL_FETCH_OUTCOMES` (legacy alias and final bool binding).
- `SHIVA_HOST` (bridge-host fallback helper vs Flask bind at `__main__`).

## Top likely mapping mistakes from the draft
- Mapping `DNS_RESOLVER_NAMESERVERS` as affecting all DNS activity: code proves it only applies when `dns.resolver` is available and only for code paths using `DNS_RESOLVER` object.
- Mapping `SHIVA_DB_PATH` directly to persistence behavior: code proves it selects file path; persistence timing is controlled by DB queue/writer logic.
- Mapping `BRIDGE_BASE_URL` to all bridge requests: `_resolve_bridge_base_url_runtime()` can compute base URL, but `bridge_get_json()` hard-requires configured `BRIDGE_BASE_URL`.
- Mapping `PMTA_DIAG_*` as throttling knobs: these knobs gate diagnostics emission rate/verbosity, not queue pacing policy itself.

## Top fallback/alias chains requiring explicit documentation
- `SHIVA_DB_PATH -> SMTP_SENDER_DB_PATH -> APP_DIR/smtp_sender.db`.
- `SHIVA_DISABLE_BLACKLIST -> DISABLE_BLACKLIST -> default false`.
- `OUTCOMES_SYNC -> BRIDGE_POLL_FETCH_OUTCOMES -> default true`.
- `BRIDGE_POLL_INTERVAL_S -> PMTA_BRIDGE_PULL_S -> 5.0`.
- `PMTA_MONITOR_BASE_URL` override winning over derived host+scheme logic (`PMTA_MONITOR_SCHEME`).

---

# SECTION 2 — Variables Requiring Clarification

| Variable | Status | What is unclear | What must be verified in code | Why this matters operationally |
|---|---|---|---|---|
| SHIVA_DB_PATH / SMTP_SENDER_DB_PATH | PARTIALLY PROVEN | Draft conflates file selection with write timing | `_resolve_db_path`, `_db_conn`, writer queue code | Wrong assumption can hide queue pressure / write lag root cause |
| SHIVA_DB_WRITE_BATCH_SIZE | PARTIALLY PROVEN | Draft often says “batching” without showing writer loop use | writer dequeue/flush loop | Throughput vs durability latency tuning |
| SHIVA_DB_WRITE_QUEUE_MAX | PROVEN | Usually documented, but need queue-full failure path proof | queue init + enqueue fallback counters | Data freshness and drop/backpressure risk |
| DB_CLEAR_ON_START | PARTIALLY PROVEN | Not always shown where cleanup executes | startup DB init/wipe call path | Startup destructive behavior risk |
| DNS_RESOLVER_NAMESERVERS | AMBIGUOUS | Scope limited to dnspython resolver path only | `dns is not None` gate + lookup functions actually using resolver | Misbelief can cause wrong DNS troubleshooting |
| SHIVA_DISABLE_BLACKLIST / DISABLE_BLACKLIST | PROVEN | Alias precedence must be explicit | two-step raw read and bool conversion | Can unintentionally disable reputation checks |
| DKIM_SELECTOR / DKIM_SELECTORS / DEFAULT_DKIM_SELECTOR | PROVEN | Merge precedence and fallback to common selectors | `_dkim_selectors_from_env`, `_dkim_selectors_for_domain` | Sender-domain diagnostics correctness |
| PMTA_MONITOR_BASE_URL / PMTA_MONITOR_SCHEME | PROVEN | Need explicit override precedence proof | `_pmta_base_from_smtp_host` | Wrong monitor URL => false health block |
| PMTA_HEALTH_REQUIRED | PROVEN | Gating vs warn-only must be shown in send-start path | monitor preflight branch | Can block all jobs if strict in unstable monitor |
| PMTA_QUEUE_BACKOFF / PMTA_QUEUE_REQUIRED / SHIVA_DISABLE_BACKOFF | PROVEN | Interplay not always documented together | queue policy + disable guard branches | Throughput safety vs aggressive sending |
| SHIVA_BACKOFF_JITTER* family | PARTIALLY PROVEN | Some docs omit export/debug-only nature | jitter compute + telemetry branches | Noise vs observability tradeoff |
| PMTA_PRESSURE_* subset | PROVEN | Distinguish adaptive pressure from diagnostics | `pmta_pressure_policy_from_live` and callers | Queue pressure avoidance |
| PMTA_BRIDGE_PULL_ENABLED / BRIDGE_MODE | PROVEN | Enablement and counts/legacy semantics need hard proof | `_bridge_mode_counts_enabled`, poller start conditions | Outcomes freshness and bridge load |
| OUTCOMES_SYNC / BRIDGE_POLL_FETCH_OUTCOMES | PROVEN | Alias and final assignment order | env read + bool bind + reload semantics | Missing outcomes or excess bridge calls |
| SHIVA_HOST / SHIVA_PORT | PARTIALLY PROVEN | Dual role (bind + fallback host) not always separated | `_resolve_bridge_pull_host_from_campaign`, `__main__` | Wrong bind security / wrong bridge target |

---

# SECTION 3 — Deep Variable-by-Variable Clarification

### SPAMCHECK_BACKEND
- Read site: module load (`SPAMCHECK_BACKEND = ...`).
- Parse / normalize / clamp: string; default `spamd`; `.strip().lower()`.
- Precedence / fallback: no alias.
- Direct consumers: `compute_spam_score` backend switch.
- Indirect consumers: send job thread path that calls spam scoring.
- Real effect in code: chooses first scoring backend and fallback order behavior.
- Runtime lifecycle: startup parse + runtime-reloadable via `reload_runtime_config`.
- Operational impact: controls spam-score source latency/availability.
- Misconfiguration risk: unsupported value falls through fallback chain; may degrade scoring quality.
- Reload / restart behavior: reloadable; affects new scoring calls immediately.
- Code quote(s): `SPAMCHECK_BACKEND = ...`; `if SPAMCHECK_BACKEND == "spamd": ... elif ...`.
- Scenario 1: set `spamd` in production with local daemon for stable scoring.
- Scenario 2: set `off` during incident to remove spam-check latency from hot path.
- Draft assessment: PROVEN.

### SPAMD_HOST
- Read site: module load.
- Parse / normalize / clamp: string default `127.0.0.1`, strip.
- Precedence / fallback: none.
- Direct consumers: `_score_via_spamd` socket connect.
- Indirect consumers: `compute_spam_score`.
- Real effect in code: target endpoint for spamd TCP.
- Runtime lifecycle: reloadable.
- Operational impact: shifts spam scoring to local/remote spamd.
- Misconfiguration risk: connection failures -> fallback backends / no score.
- Reload / restart behavior: reloadable.
- Code quote(s): assignment + `_score_via_spamd` connect call.
- Scenario 1: remote centralized spamd farm.
- Scenario 2: loopback for single-node deployment.
- Draft assessment: PROVEN.

### SPAMD_PORT
- Read site: module load.
- Parse / normalize / clamp: `int`, default 783; guarded by try/except fallback 783.
- Precedence / fallback: none.
- Direct consumers: `_score_via_spamd`.
- Indirect consumers: `compute_spam_score`.
- Real effect in code: spamd socket port.
- Runtime lifecycle: reloadable.
- Operational impact: connectivity to spam daemon.
- Misconfiguration risk: invalid value sanitized to 783; wrong but valid port causes runtime scoring failures.
- Reload / restart behavior: reloadable.
- Code quote(s): `try: SPAMD_PORT = int(...); except: SPAMD_PORT=783`.
- Scenario 1: non-standard spamd port on hardened host.
- Scenario 2: default 783 for packaged installs.
- Draft assessment: PROVEN.

### SPAMD_TIMEOUT
- Read site: module load.
- Parse / normalize / clamp: float default 5.0 with try/except.
- Precedence / fallback: none.
- Direct consumers: `_score_via_spamd`, CLI scoring helper timeouts.
- Indirect consumers: `compute_spam_score`.
- Real effect in code: max wait before scoring fails/next backend.
- Runtime lifecycle: reloadable.
- Operational impact: scoring latency vs timeout false-negative.
- Misconfiguration risk: too low => frequent fallback/no score; too high => slow job execution.
- Reload / restart behavior: reloadable.
- Code quote(s): timeout parse and helper calls using timeout.
- Scenario 1: increase when spamd under transient load.
- Scenario 2: lower when send throughput has strict latency SLO.
- Draft assessment: PROVEN.

### DNS_RESOLVER_NAMESERVERS
- Read site: module load inside `if dns is not None` block.
- Parse / normalize / clamp: CSV string split, trimmed, empty filtered.
- Precedence / fallback: default `1.1.1.1,8.8.8.8,9.9.9.9`.
- Direct consumers: `DNS_RESOLVER.nameservers` assignment.
- Indirect consumers: only functions using `DNS_RESOLVER`-based lookups.
- Real effect in code: bootstrap dnspython resolver upstreams.
- Runtime lifecycle: startup-only (no reload path).
- Operational impact: DNS query path if dnspython available; no effect otherwise.
- Misconfiguration risk: unreachable nameservers -> DNS checks fail/unknown states.
- Reload / restart behavior: restart required.
- Code quote(s): resolver init + nameserver list build.
- Scenario 1: set internal resolver IPs in private network.
- Scenario 2: keep public defaults in stateless public VM.
- Draft assessment: AMBIGUOUS (effect scope depends on dnspython availability and call-path usage).

### RECIPIENT_FILTER_ENABLE_SMTP_PROBE
- Read site: module load.
- Parse / normalize / clamp: bool via lower() membership; default true.
- Precedence / fallback: none.
- Direct consumers: `pre_send_recipient_filter`.
- Indirect consumers: job thread pre-send filtering path.
- Real effect in code: enables/disables SMTP RCPT probing step.
- Runtime lifecycle: startup-only in current reload function (not reloaded).
- Operational impact: hygiene quality vs pre-send latency.
- Misconfiguration risk: disabling increases bounce exposure.
- Reload / restart behavior: restart required (not in reload globals).
- Code quote(s): bool parse and branch in recipient filter.
- Scenario 1: enable for list-cleanliness before warmup.
- Scenario 2: disable for urgent bulk where speed > hygiene.
- Draft assessment: PARTIALLY PROVEN.

### RECIPIENT_FILTER_ENABLE_ROUTE_CHECK
- Read site: module load.
- Parse / normalize / clamp: bool default true.
- Precedence / fallback: none.
- Direct consumers: `pre_send_recipient_filter` route check branch.
- Indirect consumers: send path.
- Real effect in code: perform domain route validation before send.
- Runtime lifecycle: reloadable.
- Operational impact: early detection of unroutable domains.
- Misconfiguration risk: disabling may waste send attempts.
- Reload / restart behavior: live reload supported.
- Code quote(s): parse + reload assignment + branch usage.
- Scenario 1: enable for sender reputation protection.
- Scenario 2: disable under DNS outage to avoid hard prefilter drops.
- Draft assessment: PROVEN.

### RECIPIENT_FILTER_SMTP_PROBE_LIMIT
- Read site: module load.
- Parse / normalize / clamp: int default 25 with try/except.
- Precedence / fallback: none.
- Direct consumers: `pre_send_recipient_filter` count cap.
- Indirect consumers: SMTP probe worker selection.
- Real effect in code: limits number of recipients actively probed.
- Runtime lifecycle: startup-only.
- Operational impact: probe coverage vs latency/API pressure.
- Misconfiguration risk: too low weak hygiene; too high slow start.
- Reload / restart behavior: restart required.
- Code quote(s): parse + probe limit slice/threshold in filter function.
- Scenario 1: lower on huge lists to bound startup delay.
- Scenario 2: increase for small high-value campaigns.
- Draft assessment: PARTIALLY PROVEN.

### RECIPIENT_FILTER_SMTP_TIMEOUT
- Read site: module load.
- Parse / normalize / clamp: float default 5 with try/except.
- Precedence / fallback: none.
- Direct consumers: `_smtp_rcpt_probe` timeout.
- Indirect consumers: pre-send filter.
- Real effect in code: per-probe socket timeout.
- Runtime lifecycle: startup-only.
- Operational impact: false-negative vs speed.
- Misconfiguration risk: too low misclassifies slow domains; too high stalls probes.
- Reload / restart behavior: restart required.
- Code quote(s): parse + `_smtp_rcpt_probe` timeout argument.
- Scenario 1: raise for remote/slow MX geos.
- Scenario 2: lower for strict campaign launch latency.
- Draft assessment: PROVEN.

### RECIPIENT_FILTER_ROUTE_THREADS
- Read site: module load.
- Parse / normalize / clamp: int default 24; clamped `1..128`.
- Precedence / fallback: none.
- Direct consumers: threadpool size in route checks.
- Indirect consumers: pre-send filter runtime.
- Real effect in code: concurrency for route checks.
- Runtime lifecycle: startup-only.
- Operational impact: DNS load and precheck speed.
- Misconfiguration risk: too high -> DNS pressure; too low -> slow filtering.
- Reload / restart behavior: restart required.
- Code quote(s): parse + `max(1, min(128,...))`.
- Scenario 1: reduce under resolver rate limits.
- Scenario 2: increase for large batches with strong resolver capacity.
- Draft assessment: PROVEN.

### RECIPIENT_FILTER_SMTP_THREADS
- Read site: module load.
- Parse / normalize / clamp: int default 8; clamped `1..64`.
- Precedence / fallback: none.
- Direct consumers: SMTP probe threadpool size.
- Indirect consumers: recipient filter pipeline.
- Real effect in code: probe parallelism.
- Runtime lifecycle: startup-only.
- Operational impact: RCPT hygiene speed and remote load.
- Misconfiguration risk: too high triggers remote anti-abuse; too low slows completion.
- Reload / restart behavior: restart required.
- Code quote(s): parse + clamp line.
- Scenario 1: low during provider strict anti-connection policies.
- Scenario 2: high in controlled internal test lab.
- Draft assessment: PROVEN.

### SHIVA_DB_PATH
- Read site: inside `_resolve_db_path()`.
- Parse / normalize / clamp: raw string, strip, `Path.expanduser`, absolute resolve.
- Precedence / fallback: highest over `SMTP_SENDER_DB_PATH`, then default file.
- Direct consumers: global `DB_PATH` used by `_db_conn`.
- Indirect consumers: all DB read/write APIs.
- Real effect in code: selects sqlite file location only.
- Runtime lifecycle: startup-only.
- Operational impact: persistence location (durability, storage medium).
- Misconfiguration risk: bad path may fail sqlite open/write.
- Reload / restart behavior: restart required.
- Code quote(s): `_resolve_db_path` 3-way `or` chain.
- Scenario 1: set to persistent volume in containers.
- Scenario 2: set local fast disk for ephemeral test.
- Draft assessment: PARTIALLY PROVEN.

### SMTP_SENDER_DB_PATH
- Read site: fallback inside `_resolve_db_path`.
- Parse / normalize / clamp: same path normalize pipeline.
- Precedence / fallback: used only if `SHIVA_DB_PATH` missing.
- Direct consumers: same as above via `DB_PATH`.
- Indirect consumers: all DB functions.
- Real effect in code: legacy path alias fallback.
- Runtime lifecycle: startup-only.
- Operational impact: backward compatibility for deployments.
- Misconfiguration risk: ignored if `SHIVA_DB_PATH` is set.
- Reload / restart behavior: restart required.
- Code quote(s): `os.getenv("SHIVA_DB_PATH") or os.getenv("SMTP_SENDER_DB_PATH") ...`.
- Scenario 1: legacy env preserved during migration.
- Scenario 2: remove once new var standardized.
- Draft assessment: PROVEN.

### SHIVA_DB_WRITE_BATCH_SIZE
- Read site: module load.
- Parse / normalize / clamp: int with try/except; clamp `50..1000`.
- Precedence / fallback: default 500.
- Direct consumers: DB writer loop commit batch sizing.
- Indirect consumers: async queue flush latency.
- Real effect in code: how many queued ops per flush.
- Runtime lifecycle: startup-only.
- Operational impact: throughput vs commit frequency.
- Misconfiguration risk: too low high commit overhead; too high longer durability lag.
- Reload / restart behavior: restart required.
- Code quote(s): `max(50, min(1000, int(...)))`.
- Scenario 1: increase for high ingest throughput.
- Scenario 2: lower when minimizing in-memory unflushed window.
- Draft assessment: PARTIALLY PROVEN.

### SHIVA_DB_WRITE_QUEUE_MAX
- Read site: module load.
- Parse / normalize / clamp: int with try/except; lower bound 1000.
- Precedence / fallback: default 50000.
- Direct consumers: queue maxsize at `_DB_WRITE_QUEUE` init.
- Indirect consumers: enqueue failure path/queue_full metric.
- Real effect in code: bounds pending DB writes.
- Runtime lifecycle: startup-only.
- Operational impact: burst tolerance vs memory usage.
- Misconfiguration risk: too low -> queue full/backpressure/drops; too high memory growth.
- Reload / restart behavior: restart required.
- Code quote(s): `queue.Queue(maxsize=DB_WRITE_QUEUE_MAX)`.
- Scenario 1: raise for bursty campaigns.
- Scenario 2: lower for memory-constrained node.
- Draft assessment: PROVEN.

### DB_CLEAR_ON_START
- Read site: module load.
- Parse / normalize / clamp: bool default false.
- Precedence / fallback: none.
- Direct consumers: startup clear path for DB state.
- Indirect consumers: every runtime API sees cleared state.
- Real effect in code: destructive startup reset when true.
- Runtime lifecycle: startup-only.
- Operational impact: wipe persisted campaigns/jobs.
- Misconfiguration risk: accidental data loss on restart.
- Reload / restart behavior: restart required.
- Code quote(s): bool parse and startup clear call-site.
- Scenario 1: clean-room test deployments.
- Scenario 2: keep false in production to preserve history.
- Draft assessment: PARTIALLY PROVEN.

### RBL_ZONES
- Read site: module load.
- Parse / normalize / clamp: CSV string -> `_parse_zones` dedupe lowercase strip dot.
- Precedence / fallback: default list if unset.
- Direct consumers: `check_ip_dnsbl` loops `RBL_ZONES_LIST`.
- Indirect consumers: `compute_sender_domain_states` listing details.
- Real effect in code: which DNSBL zones queried for IPs.
- Runtime lifecycle: reloadable.
- Operational impact: blacklist signal breadth and lookup load.
- Misconfiguration risk: empty reduces detection; too many zones increases DNS overhead.
- Reload / restart behavior: live reload updates list.
- Code quote(s): `_RBL_ZONES_RAW`, `_parse_zones`, `for zone in RBL_ZONES_LIST`.
- Scenario 1: strict hygiene with multiple reputable RBLs.
- Scenario 2: narrow list under DNS budget constraints.
- Draft assessment: PROVEN.

### DBL_ZONES
- Read site: module load.
- Parse / normalize / clamp: CSV to normalized list.
- Precedence / fallback: default `dbl.spamhaus.org`.
- Direct consumers: `check_domain_dnsbl`.
- Indirect consumers: sender domain state computation.
- Real effect in code: domain-level blacklist query zones.
- Runtime lifecycle: reloadable.
- Operational impact: domain reputation diagnostics quality.
- Misconfiguration risk: empty disables domain listings silently.
- Reload / restart behavior: live reload.
- Code quote(s): `_DBL_ZONES_RAW` + `for zone in DBL_ZONES_LIST`.
- Scenario 1: include provider-approved DBL zones.
- Scenario 2: keep minimal when DNS latency is critical.
- Draft assessment: PROVEN.

### SHIVA_DISABLE_BLACKLIST
- Read site: module load.
- Parse / normalize / clamp: bool parse.
- Precedence / fallback: primary over `DISABLE_BLACKLIST` legacy.
- Direct consumers: guard inside `compute_sender_domain_states`.
- Indirect consumers: blacklist check helpers bypassed.
- Real effect in code: disables all DNSBL checks for sender/domain/IP.
- Runtime lifecycle: reloadable.
- Operational impact: faster checks but weaker reputation signals.
- Misconfiguration risk: silent degradation of risk detection.
- Reload / restart behavior: live reload.
- Code quote(s): `_SHIVA_DISABLE_BLACKLIST_RAW = os.getenv(...)` then fallback.
- Scenario 1: disable during DNS provider outage.
- Scenario 2: enable in normal production for risk visibility.
- Draft assessment: PROVEN.

### DISABLE_BLACKLIST
- Read site: fallback alias only when `SHIVA_DISABLE_BLACKLIST` is absent.
- Parse / normalize / clamp: same bool parser.
- Precedence / fallback: lower priority legacy alias.
- Direct consumers: none directly (feeds `SHIVA_DISABLE_BLACKLIST`).
- Indirect consumers: same blacklist bypass behavior.
- Real effect in code: only legacy compatibility.
- Runtime lifecycle: startup alias + reload uses only new key by default config key set.
- Operational impact: migration compatibility.
- Misconfiguration risk: ignored if new key also set.
- Reload / restart behavior: mostly startup path.
- Code quote(s): `if _SHIVA_DISABLE_BLACKLIST_RAW is None: _...=os.getenv("DISABLE_BLACKLIST")`.
- Scenario 1: old deployments without new env name.
- Scenario 2: avoid setting both to reduce ambiguity.
- Draft assessment: PROVEN.

### DKIM_SELECTOR
- Read site: `_dkim_selectors_from_env`.
- Parse / normalize / clamp: list contributor, comma/semicolon split, lower/strip/dedupe.
- Precedence / fallback: appended in order before other DKIM envs.
- Direct consumers: selector list builder.
- Indirect consumers: `compute_sender_domain_states` DKIM lookup loop.
- Real effect in code: candidate selector precedence for DKIM TXT checks.
- Runtime lifecycle: runtime-read per call (function reads env each invocation).
- Operational impact: DKIM diagnostics accuracy.
- Misconfiguration risk: wrong selector marks pass domains as missing.
- Reload / restart behavior: immediate (read at call time).
- Code quote(s): raw env list with three vars and merge logic.
- Scenario 1: set when sender uses non-default selector.
- Scenario 2: unset to rely on common selector fallback.
- Draft assessment: PROVEN.

### DKIM_SELECTORS
- Read site: same function.
- Parse / normalize / clamp: same CSV normalization.
- Precedence / fallback: second source after `DKIM_SELECTOR`.
- Direct consumers: same.
- Indirect consumers: same.
- Real effect in code: adds multiple selectors tested in order.
- Runtime lifecycle: call-time dynamic.
- Operational impact: broader selector discovery.
- Misconfiguration risk: huge list adds DNS overhead.
- Reload / restart behavior: no restart required.
- Code quote(s): second item in `raw` array.
- Scenario 1: multi-tenant domains with multiple active selectors.
- Scenario 2: keep empty for fast default checks.
- Draft assessment: PROVEN.

### DEFAULT_DKIM_SELECTOR
- Read site: same function.
- Parse / normalize / clamp: same.
- Precedence / fallback: third source; still before hardcoded commons.
- Direct consumers: same.
- Indirect consumers: same.
- Real effect in code: additional fallback selector before common list fallback.
- Runtime lifecycle: call-time dynamic.
- Operational impact: catches org-wide default selector conventions.
- Misconfiguration risk: wrong default masks true state as missing.
- Reload / restart behavior: immediate.
- Code quote(s): third item in env raw list.
- Scenario 1: set company-wide standard selector name.
- Scenario 2: leave unset if using per-domain selectors only.
- Draft assessment: PROVEN.

### PMTA_MONITOR_TIMEOUT_S
- Read site: module load.
- Parse / normalize / clamp: float default 3.0 try/except.
- Precedence / fallback: none.
- Direct consumers: PMTA monitor HTTP fetch functions.
- Indirect consumers: pre-start PMTA health checks for jobs.
- Real effect in code: timeout for monitor API requests.
- Runtime lifecycle: reloadable.
- Operational impact: false-health-failure sensitivity.
- Misconfiguration risk: too low blocks healthy-but-slow PMTA; too high slows failure detection.
- Reload / restart behavior: live reload.
- Code quote(s): parse + `_http_get_json(... timeout_s=PMTA_MONITOR_TIMEOUT_S)`.
- Scenario 1: increase behind slow reverse proxy.
- Scenario 2: decrease for rapid fail-fast during incidents.
- Draft assessment: PROVEN.

### PMTA_MONITOR_BASE_URL
- Read site: module load.
- Parse / normalize / clamp: stripped string default empty.
- Precedence / fallback: explicit override over derived URL.
- Direct consumers: `_pmta_base_from_smtp_host` returns this if set.
- Indirect consumers: all monitor endpoints built from base.
- Real effect in code: forces monitor endpoint.
- Runtime lifecycle: reloadable.
- Operational impact: can redirect monitor checks to separate host/proxy.
- Misconfiguration risk: wrong URL causes false unreachable and job blocks when health required.
- Reload / restart behavior: live reload.
- Code quote(s): `if (PMTA_MONITOR_BASE_URL or "").strip(): return _pmta_norm_base(PMTA_MONITOR_BASE_URL)`.
- Scenario 1: monitor sits behind central proxy URL.
- Scenario 2: leave empty to derive from SMTP host automatically.
- Draft assessment: PROVEN.

### PMTA_MONITOR_SCHEME
- Read site: module load.
- Parse / normalize / clamp: lower string; invalid -> `auto`.
- Precedence / fallback: ignored when base URL override exists.
- Direct consumers: `_pmta_base_from_smtp_host` scheme branch.
- Indirect consumers: monitor requests.
- Real effect in code: chooses http/https in derived monitor URL.
- Runtime lifecycle: reloadable.
- Operational impact: compatibility with PMTA monitor deployment.
- Misconfiguration risk: wrong scheme yields unreachable monitor.
- Reload / restart behavior: live reload.
- Code quote(s): validation block + scheme branch.
- Scenario 1: force `http` for plain internal monitor.
- Scenario 2: force `https` for TLS-only monitor.
- Draft assessment: PROVEN.

### PMTA_MONITOR_API_KEY
- Read site: module load.
- Parse / normalize / clamp: string strip default empty.
- Precedence / fallback: none.
- Direct consumers: `_pmta_headers` adds `X-API-Key`.
- Indirect consumers: all PMTA monitor API calls.
- Real effect in code: authentication header injection.
- Runtime lifecycle: reloadable.
- Operational impact: allows monitor access on secured PMTA API.
- Misconfiguration risk: missing/invalid key => health fetch failures.
- Reload / restart behavior: live reload.
- Code quote(s): `_pmta_headers` branch.
- Scenario 1: required when PMTA http-api-key enabled.
- Scenario 2: leave empty on non-authenticated lab monitor.
- Draft assessment: PROVEN.

### PMTA_HEALTH_REQUIRED
- Read site: module load.
- Parse / normalize / clamp: bool default true.
- Precedence / fallback: none.
- Direct consumers: pre-job PMTA check gating.
- Indirect consumers: job creation/start path.
- Real effect in code: block send start vs warn-only when monitor bad.
- Runtime lifecycle: reloadable.
- Operational impact: reliability safety gate.
- Misconfiguration risk: strict mode can halt jobs during monitor outages.
- Reload / restart behavior: live reload for future starts.
- Code quote(s): health required parse and check branch returning error/warn.
- Scenario 1: keep true in strict compliance send environments.
- Scenario 2: set false when monitor reliability is lower than PMTA itself.
- Draft assessment: PROVEN.

### PMTA_DIAG_ON_ERROR
- Read site: module load + duplicate parse later.
- Parse / normalize / clamp: bool default true.
- Precedence / fallback: last assignment at import wins.
- Direct consumers: diagnostic dump trigger on PMTA errors.
- Indirect consumers: logs/UI diagnostics.
- Real effect in code: enables error-time PMTA diagnostic collection.
- Runtime lifecycle: reloadable.
- Operational impact: visibility during failures.
- Misconfiguration risk: disabled loses RCA detail; enabled may add API load.
- Reload / restart behavior: live reload.
- Code quote(s): duplicated parse lines + usage in error branches.
- Scenario 1: enable during persistent deferral issues.
- Scenario 2: disable under strict monitor API rate limits.
- Draft assessment: PROVEN.

### PMTA_DIAG_RATE_S
- Read site: module load + duplicate parse.
- Parse / normalize / clamp: float default 1.0.
- Precedence / fallback: duplicate assignment pattern.
- Direct consumers: diagnostic rate limiter timing.
- Indirect consumers: error monitoring cadence.
- Real effect in code: min interval between diag pulls.
- Runtime lifecycle: reloadable.
- Operational impact: controls diagnostic request pressure.
- Misconfiguration risk: too low floods PMTA API; too high misses transient states.
- Reload / restart behavior: live reload.
- Code quote(s): parse + rate-limit check.
- Scenario 1: raise on busy PMTA with API saturation.
- Scenario 2: lower during active incident debugging.
- Draft assessment: PROVEN.

### PMTA_QUEUE_TOP_N
- Read site: module load + duplicate parse.
- Parse / normalize / clamp: int default 6.
- Precedence / fallback: duplicate parse; latest value used.
- Direct consumers: queue diagnostics/top queue extraction.
- Indirect consumers: backoff decision detail context.
- Real effect in code: number of queue rows inspected/reported.
- Runtime lifecycle: reloadable.
- Operational impact: diagnostic depth vs API payload.
- Misconfiguration risk: high values increase PMTA API response cost.
- Reload / restart behavior: live reload.
- Code quote(s): parse + queue fetch slicing.
- Scenario 1: increase for broad queue hotspot visibility.
- Scenario 2: reduce to minimize monitor overhead.
- Draft assessment: PROVEN.

### PMTA_QUEUE_BACKOFF
- Read site: module load.
- Parse / normalize / clamp: bool default true.
- Precedence / fallback: can be neutralized by `SHIVA_DISABLE_BACKOFF`.
- Direct consumers: queue backoff policy function.
- Indirect consumers: send loop pacing decisions.
- Real effect in code: whether queue metrics can throttle/block sending.
- Runtime lifecycle: reloadable.
- Operational impact: protects PMTA during queue stress.
- Misconfiguration risk: disabled can amplify queue pressure.
- Reload / restart behavior: live reload (new iterations/jobs).
- Code quote(s): parse + policy guard branch.
- Scenario 1: enable for automatic protection under backlog spikes.
- Scenario 2: temporary disable for controlled drain experiments.
- Draft assessment: PROVEN.

### PMTA_QUEUE_REQUIRED
- Read site: module load.
- Parse / normalize / clamp: bool default false.
- Precedence / fallback: independent; interacts with queue reachability.
- Direct consumers: branch where PMTA queue detail unreachable.
- Indirect consumers: start/send gating decisions.
- Real effect in code: unreachable queue endpoint blocks when true.
- Runtime lifecycle: reloadable.
- Operational impact: strict dependency on PMTA queue API health.
- Misconfiguration risk: true can cause false blocking on monitor outages.
- Reload / restart behavior: live reload.
- Code quote(s): `if not any_ok: if PMTA_QUEUE_REQUIRED: blocked=True`.
- Scenario 1: true in safety-critical deployment needing verified queue state.
- Scenario 2: false when PMTA monitor intermittently unavailable.
- Draft assessment: PROVEN.

### SHIVA_DISABLE_BACKOFF
- Read site: module load.
- Parse / normalize / clamp: bool default false.
- Precedence / fallback: hard override disabling backoff behavior.
- Direct consumers: send/backoff guard branches.
- Indirect consumers: pacing logic and worker limits.
- Real effect in code: bypasses queue/domain pressure throttling.
- Runtime lifecycle: reloadable.
- Operational impact: max throughput mode at risk of overload.
- Misconfiguration risk: can overrun PMTA under stress.
- Reload / restart behavior: live reload.
- Code quote(s): parse + `if SHIVA_DISABLE_BACKOFF` branches.
- Scenario 1: temporary emergency throughput push.
- Scenario 2: keep false for normal safe operation.
- Draft assessment: PROVEN.

### SHIVA_BACKOFF_JITTER
- Read site: module load.
- Parse / normalize / clamp: string lower default `off`, allowed `{off,deterministic,random}` else forced `off`.
- Precedence / fallback: none.
- Direct consumers: jitter calculation helper.
- Indirect consumers: computed delays in send loop.
- Real effect in code: adds deterministic/random spread to delays.
- Runtime lifecycle: reloadable.
- Operational impact: reduces synchronized burst patterns.
- Misconfiguration risk: unexpected pacing variance if random enabled blindly.
- Reload / restart behavior: live reload.
- Code quote(s): normalization/validation block.
- Scenario 1: random jitter to avoid thundering herd across workers.
- Scenario 2: deterministic/off for reproducible testing.
- Draft assessment: PROVEN.

### SHIVA_BACKOFF_JITTER_PCT
- Read site: module load.
- Parse / normalize / clamp: float default 0.15 with try/except.
- Precedence / fallback: bounded indirectly by min/max seconds logic.
- Direct consumers: jitter delta computation.
- Indirect consumers: delay calculations.
- Real effect in code: percent amplitude of jitter.
- Runtime lifecycle: reloadable.
- Operational impact: pacing spread width.
- Misconfiguration risk: high pct causes unstable throughput.
- Reload / restart behavior: live reload.
- Code quote(s): parse and jitter computation branch.
- Scenario 1: lower for predictable SLAs.
- Scenario 2: raise modestly to desynchronize high-parallel sends.
- Draft assessment: PARTIALLY PROVEN.

### SHIVA_BACKOFF_JITTER_MAX_S
- Read site: module load.
- Parse / normalize / clamp: float default 120 with try/except.
- Precedence / fallback: cap applied in jitter limiter.
- Direct consumers: jitter clamp.
- Indirect consumers: effective send delay.
- Real effect in code: maximum absolute jitter seconds.
- Runtime lifecycle: reloadable.
- Operational impact: upper bound on slowdown due to jitter.
- Misconfiguration risk: too high may overly delay sends.
- Reload / restart behavior: live reload.
- Code quote(s): parse + clamp with max bound.
- Scenario 1: lower for time-sensitive campaigns.
- Scenario 2: higher in overload-protection mode.
- Draft assessment: PROVEN.

### SHIVA_BACKOFF_JITTER_MIN_S
- Read site: module load.
- Parse / normalize / clamp: float default 0 with try/except.
- Precedence / fallback: lower clamp in jitter application.
- Direct consumers: jitter clamp floor.
- Indirect consumers: send delay.
- Real effect in code: minimum jitter allowance.
- Runtime lifecycle: reloadable.
- Operational impact: prevents too-small/noisy jitter.
- Misconfiguration risk: too high forces unavoidable extra delay.
- Reload / restart behavior: live reload.
- Code quote(s): parse + min clamp.
- Scenario 1: keep 0 when no guaranteed extra delay wanted.
- Scenario 2: set >0 to enforce baseline spreading.
- Draft assessment: PROVEN.

### SHIVA_BACKOFF_JITTER_EXPORT
- Read site: module load.
- Parse / normalize / clamp: bool default false.
- Precedence / fallback: none.
- Direct consumers: telemetry/export payload branches.
- Indirect consumers: UI/API diagnostics.
- Real effect in code: include jitter metadata in outputs.
- Runtime lifecycle: reloadable.
- Operational impact: observability only.
- Misconfiguration risk: extra payload/noise; no pacing change.
- Reload / restart behavior: live reload.
- Code quote(s): parse + conditional export fields.
- Scenario 1: enable while tuning jitter.
- Scenario 2: disable for lean telemetry.
- Draft assessment: PARTIALLY PROVEN.

### SHIVA_BACKOFF_JITTER_DEBUG
- Read site: module load.
- Parse / normalize / clamp: bool default false.
- Precedence / fallback: none.
- Direct consumers: debug logging branches in jitter logic.
- Indirect consumers: logs.
- Real effect in code: extra jitter debug lines.
- Runtime lifecycle: reloadable.
- Operational impact: observability only.
- Misconfiguration risk: verbose logs under high traffic.
- Reload / restart behavior: live reload.
- Code quote(s): parse + debug conditional checks.
- Scenario 1: enable during pacing investigation.
- Scenario 2: disable in normal high-volume production.
- Draft assessment: PROVEN.

### PMTA_LIVE_POLL_S
- Read site: module load.
- Parse / normalize / clamp: float default 3.0.
- Precedence / fallback: none.
- Direct consumers: PMTA live snapshot caching/poll cadence.
- Indirect consumers: pressure and queue policy freshness.
- Real effect in code: minimum interval for PMTA live refresh.
- Runtime lifecycle: reloadable.
- Operational impact: freshness vs monitor API load.
- Misconfiguration risk: too low increases API pressure; too high stale decisions.
- Reload / restart behavior: live reload.
- Code quote(s): parse and poll interval checks.
- Scenario 1: lower in rapidly changing queue conditions.
- Scenario 2: raise to reduce PMTA API traffic.
- Draft assessment: PROVEN.

### PMTA_DOMAIN_CHECK_TOP_N
- Read site: module load.
- Parse / normalize / clamp: int default 2.
- Precedence / fallback: none.
- Direct consumers: domain sampling for PMTA detail checks.
- Indirect consumers: domain-level backoff decisions.
- Real effect in code: how many top recipient domains inspected.
- Runtime lifecycle: reloadable.
- Operational impact: breadth of domain-aware throttling.
- Misconfiguration risk: low misses problematic domains; high increases API calls.
- Reload / restart behavior: live reload.
- Code quote(s): parse and top-domain slicing usage.
- Scenario 1: raise for diverse recipient distribution.
- Scenario 2: lower for small campaigns or API-constrained environments.
- Draft assessment: PROVEN.

### PMTA_DETAIL_CACHE_TTL_S
- Read site: module load.
- Parse / normalize / clamp: float default 3.0.
- Precedence / fallback: none.
- Direct consumers: PMTA detail cache expiry checks.
- Indirect consumers: backoff policy detail freshness.
- Real effect in code: cache staleness window for detail metrics.
- Runtime lifecycle: reloadable.
- Operational impact: freshness/load tradeoff.
- Misconfiguration risk: high TTL stale throttling signals; very low TTL API churn.
- Reload / restart behavior: live reload.
- Code quote(s): parse + cache TTL use.
- Scenario 1: lower for high-volatility queues.
- Scenario 2: raise when PMTA API is expensive.
- Draft assessment: PROVEN.

### PMTA_PRESSURE_CONTROL
- Read site: module load.
- Parse / normalize / clamp: bool default true.
- Precedence / fallback: none.
- Direct consumers: `pmta_pressure_policy_from_live` early return.
- Indirect consumers: send-speed recommendation applicators.
- Real effect in code: enables/disables adaptive global pressure policy.
- Runtime lifecycle: reloadable.
- Operational impact: automatic scaling down under PMTA pressure.
- Misconfiguration risk: disabled can overspeed into backlogs.
- Reload / restart behavior: live reload.
- Code quote(s): `if not PMTA_PRESSURE_CONTROL: return {enabled:False...}`.
- Scenario 1: keep enabled in shared PMTA clusters.
- Scenario 2: disable for controlled benchmark tests.
- Draft assessment: PROVEN.

### PMTA_PRESSURE_POLL_S
- Read site: module load.
- Parse / normalize / clamp: float default 3.0.
- Precedence / fallback: none.
- Direct consumers: background pressure poller sleep interval.
- Indirect consumers: pressure snapshot freshness.
- Real effect in code: cadence of pressure-control updates.
- Runtime lifecycle: reloadable.
- Operational impact: responsiveness vs API load.
- Misconfiguration risk: low poll hammers API; high poll reacts slowly.
- Reload / restart behavior: live reload.
- Code quote(s): parse + poll loop sleep.
- Scenario 1: decrease for fast-changing peak windows.
- Scenario 2: increase during stable low-volume periods.
- Draft assessment: PROVEN.

### PMTA_DOMAIN_STATS
- Read site: module load.
- Parse / normalize / clamp: bool default true.
- Precedence / fallback: none.
- Direct consumers: domain stats polling guard.
- Indirect consumers: domain-aware pacing diagnostics.
- Real effect in code: toggles domain snapshot collection.
- Runtime lifecycle: reloadable.
- Operational impact: domain-level visibility and controls.
- Misconfiguration risk: off removes domain granularity.
- Reload / restart behavior: live reload.
- Code quote(s): parse + `if PMTA_DOMAIN_STATS` branches.
- Scenario 1: enable for per-domain throttling quality.
- Scenario 2: disable to cut monitoring overhead.
- Draft assessment: PROVEN.

### PMTA_DOMAINS_POLL_S
- Read site: module load.
- Parse / normalize / clamp: float default 4.0.
- Precedence / fallback: none.
- Direct consumers: domain stats poller interval.
- Indirect consumers: freshness of domain pressure data.
- Real effect in code: cadence for domain metrics refresh.
- Runtime lifecycle: reloadable.
- Operational impact: stale/fresh domain controls.
- Misconfiguration risk: high interval stale domain signals; low interval load spike.
- Reload / restart behavior: live reload.
- Code quote(s): parse + domain poll loop sleep.
- Scenario 1: lower when deferral patterns shift quickly.
- Scenario 2: higher when PMTA API budget is tight.
- Draft assessment: PROVEN.

### PMTA_DOMAINS_TOP_N
- Read site: module load.
- Parse / normalize / clamp: int default 6.
- Precedence / fallback: none.
- Direct consumers: top-N domain list size.
- Indirect consumers: domain detail and pacing policy focus.
- Real effect in code: limits domain set analyzed.
- Runtime lifecycle: reloadable.
- Operational impact: breadth of domain-aware mitigation.
- Misconfiguration risk: low misses affected domains; high increases overhead.
- Reload / restart behavior: live reload.
- Code quote(s): parse + top-N selection.
- Scenario 1: increase for highly fragmented recipient mix.
- Scenario 2: lower for concentrated domain traffic.
- Draft assessment: PROVEN.

### PMTA_BRIDGE_PULL_ENABLED
- Read site: module load.
- Parse / normalize / clamp: bool default true.
- Precedence / fallback: none.
- Direct consumers: `start_accounting_bridge_poller_if_needed` and bridge policy.
- Indirect consumers: outcomes ingestion availability.
- Real effect in code: enables periodic bridge pull thread behavior.
- Runtime lifecycle: reloadable.
- Operational impact: whether delivery outcomes are ingested continuously.
- Misconfiguration risk: false leads to stale outcomes/UI.
- Reload / restart behavior: live reload can start poller.
- Code quote(s): bool parse + poller start condition.
- Scenario 1: enable for near-real-time outcomes.
- Scenario 2: disable when bridge API maintenance underway.
- Draft assessment: PROVEN.

### BRIDGE_MODE
- Read site: module load.
- Parse / normalize / clamp: lower string default `counts`; invalid -> `counts`.
- Precedence / fallback: none.
- Direct consumers: `_bridge_mode_counts_enabled`, URL resolver, policy branch.
- Indirect consumers: request style and endpoints used.
- Real effect in code: counts mode vs legacy pull URL behavior.
- Runtime lifecycle: reloadable.
- Operational impact: bridge protocol semantics.
- Misconfiguration risk: wrong mode can bypass expected pull logic.
- Reload / restart behavior: live reload.
- Code quote(s): validation + `_bridge_mode_counts_enabled` use.
- Scenario 1: `counts` for current API style.
- Scenario 2: `legacy` only for backward-compatible bridge endpoints.
- Draft assessment: PROVEN.

### PMTA_BRIDGE_PULL_PORT
- Read site: module load.
- Parse / normalize / clamp: int default 8090 with try/except.
- Precedence / fallback: none.
- Direct consumers: runtime bridge URL constructors.
- Indirect consumers: poller HTTP target.
- Real effect in code: bridge HTTP port.
- Runtime lifecycle: reloadable.
- Operational impact: connectivity to bridge service.
- Misconfiguration risk: wrong port => pull failures/outcome staleness.
- Reload / restart behavior: live reload.
- Code quote(s): parse + URL format with port.
- Scenario 1: custom port due to ingress mapping.
- Scenario 2: default 8090 in colocated deployment.
- Draft assessment: PROVEN.

### BRIDGE_BASE_URL
- Read site: module load.
- Parse / normalize / clamp: stripped string default empty.
- Precedence / fallback: when set, overrides runtime-derived base URL for compatible functions.
- Direct consumers: `_resolve_bridge_base_url_runtime`, `bridge_get_json`.
- Indirect consumers: bridge count/outcomes fetch functions.
- Real effect in code: explicit fixed bridge endpoint; `bridge_get_json` requires HTTP-only URL.
- Runtime lifecycle: reloadable.
- Operational impact: controls where ingestion API calls are sent.
- Misconfiguration risk: wrong or https URL raises errors; no base for direct `bridge_get_json` calls.
- Reload / restart behavior: live reload.
- Code quote(s): parse + `if configured: return configured` and HTTP-only validation.
- Scenario 1: set reverse-proxy URL fronting bridge.
- Scenario 2: leave empty to auto-resolve from campaign SMTP host.
- Draft assessment: PARTIALLY PROVEN.

### BRIDGE_TIMEOUT_S
- Read site: module load.
- Parse / normalize / clamp: float default 20 with try/except.
- Precedence / fallback: none.
- Direct consumers: `HTTPConnection(... timeout=BRIDGE_TIMEOUT_S)`.
- Indirect consumers: bridge poll loops.
- Real effect in code: request timeout for bridge pulls.
- Runtime lifecycle: startup-only (not in reload globals).
- Operational impact: delay before bridge failure handling.
- Misconfiguration risk: too low false failures; too high slow error recovery.
- Reload / restart behavior: restart required.
- Code quote(s): parse + connection timeout arg.
- Scenario 1: raise for high-latency cross-region bridge.
- Scenario 2: lower for faster failover behavior.
- Draft assessment: PROVEN.

### PMTA_BRIDGE_PULL_S
- Read site: module load.
- Parse / normalize / clamp: float default 5.
- Precedence / fallback: used as fallback for `BRIDGE_POLL_INTERVAL_S`.
- Direct consumers: bridge poll cycle sleep and config views.
- Indirect consumers: outcomes freshness.
- Real effect in code: baseline poll interval.
- Runtime lifecycle: reloadable.
- Operational impact: bridge call frequency.
- Misconfiguration risk: low increases bridge load; high makes stale outcomes.
- Reload / restart behavior: live reload.
- Code quote(s): parse and fallback in `BRIDGE_POLL_INTERVAL_S` parse.
- Scenario 1: lower for faster post-send visibility.
- Scenario 2: raise to protect overloaded bridge.
- Draft assessment: PROVEN.

### BRIDGE_POLL_INTERVAL_S
- Read site: module load.
- Parse / normalize / clamp: float; default fallback to `PMTA_BRIDGE_PULL_S`.
- Precedence / fallback: primary interval override variable.
- Direct consumers: `_accounting_bridge_poller_thread` sleep cycle.
- Indirect consumers: ingestion cadence.
- Real effect in code: actual periodic poll interval used.
- Runtime lifecycle: reloadable.
- Operational impact: data freshness vs API load.
- Misconfiguration risk: too high stale outcomes; too low load spikes.
- Reload / restart behavior: live reload affects subsequent cycles.
- Code quote(s): parse with `str(PMTA_BRIDGE_PULL_S)` fallback.
- Scenario 1: set small for real-time SLA dashboards.
- Scenario 2: set larger when bridge CPU constrained.
- Draft assessment: PROVEN.

### OUTCOMES_SYNC
- Read site: module load.
- Parse / normalize / clamp: bool from raw string default true.
- Precedence / fallback: primary; if unset then use `BRIDGE_POLL_FETCH_OUTCOMES`.
- Direct consumers: sets `BRIDGE_POLL_FETCH_OUTCOMES = bool(OUTCOMES_SYNC)`.
- Indirect consumers: poller deciding whether to request outcomes.
- Real effect in code: toggles outcomes fetch behavior.
- Runtime lifecycle: reloadable (but final bool is normalized to `BRIDGE_POLL_FETCH_OUTCOMES` in reload).
- Operational impact: enables/disables detailed outcome ingestion.
- Misconfiguration risk: off yields stale/not-yet statuses.
- Reload / restart behavior: live reload.
- Code quote(s): two-step raw read and alias assignment.
- Scenario 1: enable for forensic delivery lifecycle tracking.
- Scenario 2: disable temporarily to reduce bridge payload volume.
- Draft assessment: PROVEN.

### BRIDGE_POLL_FETCH_OUTCOMES
- Read site: fallback env read if `OUTCOMES_SYNC` absent.
- Parse / normalize / clamp: string->bool via same parser chain.
- Precedence / fallback: lower precedence alias.
- Direct consumers: poller fetch branch.
- Indirect consumers: DB outcome updates.
- Real effect in code: controls outcomes endpoint calls.
- Runtime lifecycle: reloadable and canonicalized in reload.
- Operational impact: data completeness in UI/job status.
- Misconfiguration risk: false decreases observability of actual delivery outcomes.
- Reload / restart behavior: live reload.
- Code quote(s): `if _OUTCOMES_SYNC_RAW is None: _OUTCOMES_SYNC_RAW = os.getenv("BRIDGE_POLL_FETCH_OUTCOMES", "1")`.
- Scenario 1: keep true when support team needs DSN details.
- Scenario 2: set false during bridge overload triage.
- Draft assessment: PROVEN.

### PMTA_BRIDGE_PULL_MAX_LINES
- Read site: module load.
- Parse / normalize / clamp: int default 2000 try/except.
- Precedence / fallback: none.
- Direct consumers: `_resolve_bridge_pull_url_runtime` limit query.
- Indirect consumers: per-poll ingestion volume.
- Real effect in code: caps number of pulled accounting lines per request.
- Runtime lifecycle: reloadable.
- Operational impact: backlog catch-up speed vs per-request load.
- Misconfiguration risk: too low slow catch-up; too high heavy payload/latency.
- Reload / restart behavior: live reload.
- Code quote(s): parse + `limit = max(1, int(PMTA_BRIDGE_PULL_MAX_LINES...))`.
- Scenario 1: increase when recovering from backlog.
- Scenario 2: decrease to smooth bridge load.
- Draft assessment: PROVEN.

### SHIVA_HOST
- Read site: `_resolve_bridge_pull_host_from_campaign` and `__main__`.
- Parse / normalize / clamp: stripped string; defaults differ (`""` fallback helper, `0.0.0.0` for bind).
- Precedence / fallback: bridge helper uses SHIVA_HOST only if no jobs and not wildcard.
- Direct consumers: Flask bind host; bridge host fallback.
- Indirect consumers: auto bridge URL host resolution.
- Real effect in code: server listen interface and possible bridge target fallback.
- Runtime lifecycle: startup-read in helper calls / bind.
- Operational impact: network exposure and bridge self-targeting behavior.
- Misconfiguration risk: exposing on wrong interface or wrong bridge host resolution.
- Reload / restart behavior: bind requires restart; helper reads env per call.
- Code quote(s): helper `host = os.getenv("SHIVA_HOST", "")` and `if __name__ == "__main__"` bind code.
- Scenario 1: `0.0.0.0` for containerized service access.
- Scenario 2: `127.0.0.1` for local-only dev safety.
- Draft assessment: PARTIALLY PROVEN.

### SHIVA_PORT
- Read site: `__main__` bind path.
- Parse / normalize / clamp: int default 5001 with try/except.
- Precedence / fallback: none.
- Direct consumers: `app.run(port=port)`.
- Indirect consumers: none for runtime logic.
- Real effect in code: HTTP server bind port only.
- Runtime lifecycle: startup-only.
- Operational impact: service reachability.
- Misconfiguration risk: collision/unreachable endpoint.
- Reload / restart behavior: restart required.
- Code quote(s): port parse and `app.run`.
- Scenario 1: custom port behind reverse proxy mapping.
- Scenario 2: default 5001 in standalone host.
- Draft assessment: PROVEN.

> Count verification note: literal `os.getenv("NAME"...)` calls in `shiva.py` = 64 calls, but unique variable names = 60. Duplicate literal reads: `PMTA_DIAG_ON_ERROR`, `PMTA_DIAG_RATE_S`, `PMTA_QUEUE_TOP_N`, `SHIVA_HOST`.

---

# SECTION 4 — Dependency and Precedence Chains

1) **DB path chain**
- If `SHIVA_DB_PATH` set and non-empty => use it.
- Else if `SMTP_SENDER_DB_PATH` set => use it.
- Else => use `APP_DIR/smtp_sender.db`.
- Then normalize (`expanduser`, absolute resolve) and ensure parent dir best-effort.

2) **Blacklist disable alias chain**
- Read `SHIVA_DISABLE_BLACKLIST`.
- If it is `None`, read `DISABLE_BLACKLIST`.
- Final bool = parsed raw or default `0`.
- If both set, `SHIVA_DISABLE_BLACKLIST` wins because fallback executes only on `None`.

3) **Outcomes fetch alias chain**
- Read `OUTCOMES_SYNC` first.
- If `OUTCOMES_SYNC is None`, read `BRIDGE_POLL_FETCH_OUTCOMES` with default `1`.
- Convert final raw to bool; assign both `OUTCOMES_SYNC` and `BRIDGE_POLL_FETCH_OUTCOMES` from that bool.
- In runtime reload, `BRIDGE_POLL_FETCH_OUTCOMES` becomes canonical and `OUTCOMES_SYNC` is reset to it.

4) **Bridge interval chain**
- Parse `PMTA_BRIDGE_PULL_S` default 5.
- Parse `BRIDGE_POLL_INTERVAL_S` default string of `PMTA_BRIDGE_PULL_S`.
- If parse fails, fallback to float(`PMTA_BRIDGE_PULL_S` or 5).
- Effective poll interval used by poll loop is `BRIDGE_POLL_INTERVAL_S`.

5) **PMTA monitor URL chain**
- If `PMTA_MONITOR_BASE_URL` non-empty => normalized base returned directly.
- Else derive from SMTP host and `PMTA_MONITOR_SCHEME`.
- `PMTA_MONITOR_SCHEME` invalid values forced to `auto`.
- In code, `auto` branch defaults to `https://<host>:8080`.

6) **Backoff control chain**
- Queue/domain/pressure policies can request block/slow actions.
- `SHIVA_DISABLE_BACKOFF` branch disables applying those slow/block controls.
- `PMTA_QUEUE_REQUIRED` additionally controls whether queue detail unreachability blocks.

7) **Bridge host fallback chain**
- Use latest non-deleted job `smtp_host` if present.
- Else check `SHIVA_HOST` if non-wildcard (`0.0.0.0`/`::` rejected).
- Else fallback to `127.0.0.1`.

---

# SECTION 5 — Draft Corrections Required

1. Replace any statement that says “60 reads” without precision:
- Correct wording: **60 unique env names, 64 literal `os.getenv` calls** (due to duplicates).

2. Strengthen DB variable rows:
- `SHIVA_DB_PATH`/`SMTP_SENDER_DB_PATH`: mark as path resolution only; do not claim they control flush/batching.
- `SHIVA_DB_WRITE_BATCH_SIZE`/`SHIVA_DB_WRITE_QUEUE_MAX`: add writer queue operational effects and failure mode differences.
- `DB_CLEAR_ON_START`: explicitly mark destructive startup behavior.

3. Correct lifecycle descriptions:
- Mark startup-only vars that are not applied in `reload_runtime_config` (e.g., `RECIPIENT_FILTER_ENABLE_SMTP_PROBE`, probe thread/timeouts, `BRIDGE_TIMEOUT_S`, bind vars).
- Mark live-reload vars explicitly from reload function globals.

4. Fix monitor precedence documentation:
- Explicitly document `PMTA_MONITOR_BASE_URL` override over scheme-derived URL.
- Clarify `PMTA_MONITOR_SCHEME=auto` currently means https-first via direct https return in derivation.

5. Fix bridge semantics rows:
- Distinguish `BRIDGE_BASE_URL` direct client requirement vs runtime-derived fallback helper behavior.
- Clarify `BRIDGE_MODE` affects counts/legacy path selection, not just logging.

6. Fix blacklist rows:
- Add legacy alias precedence (`SHIVA_DISABLE_BLACKLIST` wins over `DISABLE_BLACKLIST` when both set).
- Separate zone list tuning (`RBL_ZONES`, `DBL_ZONES`) from master disable gate.

7. Fix jitter rows:
- Separate knobs affecting pacing (`SHIVA_BACKOFF_JITTER`, pct/min/max) from observability-only knobs (`..._EXPORT`, `..._DEBUG`).

8. Fix SHIVA_HOST row:
- Split two proven effects: Flask bind (startup) and bridge host fallback helper (runtime path resolution).

9. Improve scenario quality:
- Remove generic “good for production” style text; replace with concrete load/freshness/failure scenarios (as done above).

10. Improve quote sufficiency:
- For each alias/fallback/clamp row include full chain snippet, not one-liner read-only quote.
