import os
import json
import math
import csv
import random
import re
import socket
import ssl
import subprocess
import time
import uuid
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy as email_policy
from email.message import EmailMessage
from email.utils import formataddr, format_datetime
from typing import Optional, Any, Tuple, Dict, List, Set
from concurrent.futures import ThreadPoolExecutor
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import quote_plus

import sqlite3
from pathlib import Path

import smtplib
from flask import Flask, request, redirect, url_for, jsonify, render_template_string, abort, make_response, g

# =========================
# Spam score
# =========================
# There is no single universal "real" spam score.
# The most common local score is SpamAssassin.
# This app supports these backends (in order):
# 1) spamd (SpamAssassin daemon) via TCP (recommended)
# 2) spamc CLI (client for spamd) (if installed)
# 3) spamassassin CLI (if installed)
# 4) python module named `spamcheck` (best-effort fallback)
#
# Configure backend:
#   SPAMCHECK_BACKEND=spamd|spamc|spamassassin|module|off
# Configure spamd location:
#   SPAMD_HOST=127.0.0.1
#   SPAMD_PORT=783
#   SPAMD_TIMEOUT=5
SPAMCHECK_BACKEND = (os.getenv("SPAMCHECK_BACKEND", "spamd") or "spamd").strip().lower()
SPAMD_HOST = (os.getenv("SPAMD_HOST", "127.0.0.1") or "127.0.0.1").strip()
try:
    SPAMD_PORT = int((os.getenv("SPAMD_PORT", "783") or "783").strip())
except Exception:
    SPAMD_PORT = 783
try:
    SPAMD_TIMEOUT = float((os.getenv("SPAMD_TIMEOUT", "5") or "5").strip())
except Exception:
    SPAMD_TIMEOUT = 5.0

# Optional fallback module
try:
    import spamcheck  # type: ignore
except Exception:
    spamcheck = None  # type: ignore

# Optional spamc python module (not required; CLI is preferred when available)
try:
    import spamc  # type: ignore
except Exception:
    spamc = None  # type: ignore

# Optional DNS MX resolver (dnspython) for better domain->mail IP resolution
# pip install dnspython
try:
    import dns.resolver  # type: ignore
except Exception:
    dns = None  # type: ignore

DNS_RESOLVER = None
if dns is not None:
    try:
        DNS_RESOLVER = dns.resolver.Resolver()  # type: ignore
        DNS_RESOLVER.lifetime = 3.0
        DNS_RESOLVER.timeout = 2.0
    except Exception:
        DNS_RESOLVER = None

# MX/A cache to avoid repeated DNS queries
_MX_CACHE: Dict[str, dict] = {}
_MX_CACHE_EXPIRES_AT: Dict[str, float] = {}
MX_CACHE_TTL_OK = 3600.0
MX_CACHE_TTL_SOFT_FAIL = 120.0

# =========================
# Safety / Validation
# =========================
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SMTP_CODE_RE = re.compile(r"\b([245])\d{2}\b")
SMTP_ENHANCED_CODE_RE = re.compile(r"\b([245])\.\d\.\d{1,3}\b")

RECIPIENT_FILTER_ENABLE_SMTP_PROBE = (os.getenv("RECIPIENT_FILTER_ENABLE_SMTP_PROBE", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}
try:
    RECIPIENT_FILTER_SMTP_PROBE_LIMIT = int((os.getenv("RECIPIENT_FILTER_SMTP_PROBE_LIMIT", "25") or "25").strip())
except Exception:
    RECIPIENT_FILTER_SMTP_PROBE_LIMIT = 25
try:
    RECIPIENT_FILTER_SMTP_TIMEOUT = float((os.getenv("RECIPIENT_FILTER_SMTP_TIMEOUT", "5") or "5").strip())
except Exception:
    RECIPIENT_FILTER_SMTP_TIMEOUT = 5.0

# Extract emails from messy text (handles weird separators / pasted content)
EMAIL_FIND_RE = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
)


def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def parse_multiline(text: str, *, dedupe_lower: bool = False) -> List[str]:
    """Split a textarea input by NEW LINE.

    - Removes empty lines.
    - If dedupe_lower=True, deduplicates using lowercase (useful for emails).
    """
    if not text:
        return []
    out: List[str] = []
    seen: Set[str] = set()
    for line in text.splitlines():
        s = (line or "").strip()
        if not s:
            continue
        if dedupe_lower:
            k = s.lower()
            if k in seen:
                continue
            seen.add(k)
        out.append(s)
    return out


def parse_recipients(text: str) -> List[str]:
    """Parse recipients from textarea/file.

    Robust against real-world pasted lists (spaces/tabs/weird unicode separators).

    Strategy:
    1) Normalize newlines.
    2) Extract emails using regex.
    3) Deduplicate while preserving order.
    """
    if not text:
        return []

    # Normalize newline variants (Windows/Mac + unicode line separators)
    t = (
        text.replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\u2028", "\n")
        .replace("\u2029", "\n")
    )

    found = [m.group(0) for m in EMAIL_FIND_RE.finditer(t)]

    # Fallback: split on common separators if nothing matched.
    if not found:
        raw = re.split(r"[\n,;\t ]+", t)
        found = [x.strip() for x in raw if x and x.strip()]

    out: List[str] = []
    seen: Set[str] = set()
    for e in found:
        e = (e or "").strip()
        if not e:
            continue
        k = e.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(e)

    return out


def filter_valid_emails(emails: List[str]) -> Tuple[List[str], List[str]]:
    valid, invalid = [], []
    for e in emails:
        if EMAIL_RE.match(e):
            valid.append(e)
        else:
            invalid.append(e)
    return valid, invalid


def count_recipient_domains(emails: List[str]) -> Dict[str, int]:
    """Count recipient domains for a list of emails."""
    counts: Dict[str, int] = {}
    for e in emails or []:
        d = _extract_domain_from_email(e)
        if not d:
            continue
        counts[d] = counts.get(d, 0) + 1
    return counts


def build_provider_buckets(recipients: List[str]) -> Tuple[Dict[str, List[str]], List[str]]:
    """Group recipients by recipient domain while preserving first-seen order.

    Each bucket is treated as one "provider queue" (gmail.com, yahoo.com, ...).
    """
    buckets: Dict[str, List[str]] = {}
    order: List[str] = []
    for rcpt in recipients or []:
        dom = _extract_domain_from_email(rcpt) or "unknown"
        if dom not in buckets:
            buckets[dom] = []
            order.append(dom)
        buckets[dom].append(rcpt)
    return buckets, order


def split_body_variants(body: str) -> List[str]:
    """Allow multiple body variants separated by a delimiter line:

        ---

    The delimiter is exactly a line containing three dashes, so the split token is "\n---\n".

    Example:
        Body 1
        ---
        Body 2
    """
    text = (body or "").strip()
    if not text:
        return [""]

    # IMPORTANT: keep this as a single-line python string (no raw newlines inside quotes)
    sep = "\n---\n"

    parts = [p.strip() for p in text.split(sep)]
    parts = [p for p in parts if p]
    return parts or [text]


# =========================
# Job Model (in-memory)
# =========================
@dataclass
class JobLog:
    ts: str
    level: str
    message: str


@dataclass
class SendJob:
    id: str
    created_at: str
    campaign_id: str = ""

    # SMTP host used for this job (also used to derive PMTA monitor base URL)
    smtp_host: str = ""

    # PMTA live panel snapshot (optional)
    pmta_live: dict = field(default_factory=dict)
    pmta_live_ts: str = ""

    # PMTA per-domain snapshot (optional): small map for big domains while sending
    pmta_domains: dict = field(default_factory=dict)
    pmta_domains_ts: str = ""

    # PMTA pressure/adaptive speed snapshot (optional)
    pmta_pressure: dict = field(default_factory=dict)
    pmta_pressure_ts: str = ""


    # PMTA diagnostics snapshot (optional; helps classify failures quickly)
    pmta_diag: dict = field(default_factory=dict)
    pmta_diag_ts: str = ""
    status: str = "queued"  # queued | running | backoff | paused | stopped | done | error
    started_at: str = ""  # first time job enters running
    updated_at: str = ""  # last activity timestamp

    # Deletion (soft flag; also deletes DB row)
    deleted: bool = False

    # Persistence throttle
    persist_ts: float = 0.0
    persist_counter: int = 0

    # Controls
    paused: bool = False
    stop_requested: bool = False
    stop_reason: str = ""

    # Live performance
    speed_window: List[float] = field(default_factory=list)  # recent event timestamps (seconds)

    # Chunk lifecycle / backoff
    chunks_total: int = 0
    chunks_done: int = 0
    chunks_backoff: int = 0
    chunks_abandoned: int = 0
    current_chunk: int = -1
    current_chunk_info: dict = field(default_factory=dict)
    current_chunk_domains: Dict[str, int] = field(default_factory=dict)
    chunk_states: List[dict] = field(default_factory=list)   # bounded
    backoff_items: List[dict] = field(default_factory=list)  # bounded

    # Domain state (recipient domains)
    domain_plan: Dict[str, int] = field(default_factory=dict)
    domain_sent: Dict[str, int] = field(default_factory=dict)
    domain_failed: Dict[str, int] = field(default_factory=dict)

    # Error histogram (simple categories)
    error_counts: Dict[str, int] = field(default_factory=dict)
    total: int = 0
    sent: int = 0
    failed: int = 0
    skipped: int = 0
    invalid: int = 0

    # Accounting outcomes (from PMTA accounting files/webhook)
    delivered: int = 0
    bounced: int = 0
    deferred: int = 0
    complained: int = 0
    # Per-minute series for simple trends (each item: {t_min, delivered, bounced, deferred, complained})
    outcome_series: List[dict] = field(default_factory=list)
    accounting_last_ts: str = ""
    # Accounting error rollups (response classes from accounting rows)
    accounting_error_counts: Dict[str, int] = field(default_factory=dict)
    accounting_last_errors: List[dict] = field(default_factory=list)  # {ts, email, type, kind, detail}

    # Spam score gate (computed before sending)
    spam_threshold: float = 4.0
    spam_score: Optional[float] = None
    spam_detail: str = ""

    # Safe list (optional whitelist)
    safe_list_total: int = 0
    safe_list_invalid: int = 0

    last_error: str = ""
    logs: List[JobLog] = field(default_factory=list)
    recent_results: List[dict] = field(default_factory=list)  # {ts, email, ok, detail}

    def log(self, level: str, msg: str):
        self.updated_at = now_iso()
        self.logs.append(JobLog(ts=now_iso(), level=level, message=msg))
        # keep logs bounded
        if len(self.logs) > 5000:
            self.logs = self.logs[-3000:]
        self.maybe_persist()
    def push_result(self, email: str, ok: bool, detail: str):
        self.updated_at = now_iso()
        # throughput window (for speed/ETA)
        try:
            now_t = time.time()
            self.speed_window.append(now_t)
            if len(self.speed_window) > 600:
                self.speed_window = self.speed_window[-400:]
            cut = now_t - 120.0
            while self.speed_window and self.speed_window[0] < cut:
                self.speed_window.pop(0)
        except Exception:
            pass

        self.recent_results.append({"ts": now_iso(), "email": email, "ok": ok, "detail": detail})

        self.maybe_persist()
    def push_chunk_state(self, item: dict):
        self.updated_at = now_iso()
        self.chunk_states.append(item)
        if len(self.chunk_states) > 600:
            self.chunk_states = self.chunk_states[-400:]
        self.maybe_persist()
    def push_backoff(self, item: dict):
        self.updated_at = now_iso()
        self.backoff_items.append(item)
        if len(self.backoff_items) > 600:
            self.backoff_items = self.backoff_items[-400:]
        self.maybe_persist()
    def record_error(self, err: str):
        """Increment a simple error histogram for Jobs UI."""
        self.updated_at = now_iso()
        msg = (err or "").lower()
        cat = "other"
        if "timed out" in msg or "timeout" in msg:
            cat = "timeout"
        elif "auth" in msg or "authentication" in msg or "login" in msg or "535" in msg:
            cat = "auth"
        elif "refused" in msg or "reject" in msg or "recipient" in msg or "550" in msg or "554" in msg:
            cat = "recipient"
        elif "dns" in msg or "getaddrinfo" in msg or "name or service not known" in msg:
            cat = "dns"
        elif "connect" in msg or "connection" in msg:
            cat = "connection"
        self.error_counts[cat] = int(self.error_counts.get(cat, 0)) + 1
        self.maybe_persist()
    def speed_epm(self) -> float:
        """Emails per minute based on last 60s of send events."""
        try:
            now_t = time.time()
            cut = now_t - 60.0
            n = 0
            for t in self.speed_window[-200:]:
                if t >= cut:
                    n += 1
            return float(n) * 60.0
        except Exception:
            return 0.0

    def eta_seconds(self) -> Optional[int]:
        """ETA (seconds) based on current speed. None if speed is too low."""
        spm = self.speed_epm()
        if spm < 1.0:
            return None
        remaining = max(0, int(self.total) - int(self.sent) - int(self.failed) - int(self.skipped))
        per_sec = spm / 60.0
        try:
            return int(remaining / per_sec) if per_sec > 0 else None
        except Exception:
            return None

    def maybe_persist(self, force: bool = False):
        """Persist to SQLite (throttled).

        This must NEVER crash the sender thread.
        """
        if self.deleted:
            return
        try:
            self.persist_counter += 1
            now_t = time.time()
            # save at least once per second, and also every ~15 events
            if (not force) and (self.persist_counter % 15 != 0) and ((now_t - float(self.persist_ts or 0.0)) < 1.0):
                return
            self.persist_ts = now_t
            db_upsert_job(self)
        except Exception:
            return


JOBS: Dict[str, SendJob] = {}
JOBS_LOCK = threading.Lock()

# =========================
# Start request guard (prevents duplicated jobs from double-submit / multi-tab)
# =========================
START_GUARD: Dict[str, float] = {}  # campaign_id -> timestamp
START_GUARD_LOCK = threading.Lock()
START_GUARD_TTL = 180.0  # seconds (safety: auto-release if server crashed)


def start_guard_acquire(campaign_id: str) -> bool:
    cid = (campaign_id or "").strip()
    if not cid:
        return True
    now_t = time.time()
    with START_GUARD_LOCK:
        # purge stale
        stale = [k for k, v in START_GUARD.items() if (now_t - float(v or 0.0)) > START_GUARD_TTL]
        for k in stale:
            START_GUARD.pop(k, None)
        ts = START_GUARD.get(cid)
        if ts and (now_t - float(ts)) <= START_GUARD_TTL:
            return False
        START_GUARD[cid] = now_t
        return True


def start_guard_release(campaign_id: str) -> None:
    cid = (campaign_id or "").strip()
    if not cid:
        return
    with START_GUARD_LOCK:
        START_GUARD.pop(cid, None)

# =========================
# Flask App
# =========================
app = Flask(__name__)
APP_VERSION = "ShivaMTA 2026-02-23"
# Accept both /path and /path/ (prevents annoying 404s from trailing slashes in links)
app.url_map.strict_slashes = False
app.config["SECRET_KEY"] = "change-me"


@app.teardown_request
def _release_start_guard(exc):
    """Always release campaign start-guard after request ends (even if it errors)."""
    cid = getattr(g, "_start_guard_campaign", None)
    if cid:
        try:
            start_guard_release(str(cid))
        except Exception:
            pass
        try:
            g._start_guard_campaign = None
        except Exception:
            pass

# =========================
# SQLite Form Storage (replaces browser localStorage)
# =========================
APP_DIR = Path(__file__).resolve().parent if "__file__" in globals() else Path(os.getcwd())


def _resolve_db_path() -> str:
    """Resolve SQLite path with writable fallback locations.

    Why: deployments sometimes run this app from a read-only code directory
    (for example under /opt or a bind-mounted volume). In that case SQLite
    writes fail and UI config save returns HTTP 500.
    """
    env_path = (os.getenv("SHIVA_DB_PATH") or os.getenv("SMTP_SENDER_DB_PATH") or "").strip()
    candidates: List[Path] = []
    if env_path:
        candidates.append(Path(env_path).expanduser())

    candidates.extend(
        [
            APP_DIR / "smtp_sender.db",
            Path.home() / ".local" / "state" / "shivamta" / "smtp_sender.db",
            Path("/tmp") / "shivamta" / "smtp_sender.db",
        ]
    )

    for p in candidates:
        try:
            parent = p.parent
            parent.mkdir(parents=True, exist_ok=True)
            probe = parent / f".db_write_probe_{uuid.uuid4().hex}"
            with open(probe, "w", encoding="utf-8") as f:
                f.write("ok")
            probe.unlink(missing_ok=True)
            return str(p)
        except Exception:
            continue

    # Last resort (keeps legacy behavior if all probes fail)
    return str(APP_DIR / "smtp_sender.db")


DB_PATH = _resolve_db_path()
DB_LOCK = threading.Lock()

BROWSER_COOKIE = "smtp_sender_bid"
_DB_CLEAR_ON_START = (os.getenv("DB_CLEAR_ON_START", "0") or "0").strip().lower() in {"1", "true", "yes", "on"}

_ALLOWED_FORM_FIELDS = {
    "smtp_host",
    "smtp_port",
    "smtp_security",
    "smtp_timeout",
    "smtp_user",
    "smtp_pass",
    "remember_pass",
    "permission_ok",
    "delay_s",
    "max_rcpt",
    "chunk_size",
    "thread_workers",
    "sleep_chunks",
    "enable_backoff",
    "ai_token",
    "use_ai",
    "remember_ai",
    "from_name",
    "from_email",
    "subject",
    "body_format",
    "reply_to",
    "score_range",
    "body",
    "urls_list",
    "src_list",
    "recipients",
    "maillist_safe",
}

# Accept custom form keys so newly-added campaign/job variables are persisted
# without requiring a code change to this static whitelist.
_FORM_FIELD_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,127}$")


def _db_conn() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def db_init() -> None:
    with DB_LOCK:
        conn = _db_conn()
        try:
            # Legacy (kept for backward compatibility)
            conn.execute(
                """CREATE TABLE IF NOT EXISTS form_state(
                       browser_id TEXT PRIMARY KEY,
                       data TEXT NOT NULL,
                       updated_at TEXT NOT NULL
                   )"""
            )

            # Campaigns
            conn.execute(
                """CREATE TABLE IF NOT EXISTS campaigns(
                       id TEXT PRIMARY KEY,
                       browser_id TEXT NOT NULL,
                       name TEXT NOT NULL,
                       created_at TEXT NOT NULL,
                       updated_at TEXT NOT NULL
                   )"""
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_browser ON campaigns(browser_id)")

            # Per-campaign saved form state
            conn.execute(
                """CREATE TABLE IF NOT EXISTS campaign_form(
                       campaign_id TEXT PRIMARY KEY,
                       data TEXT NOT NULL,
                       updated_at TEXT NOT NULL
                   )"""
            )

            # Jobs (persistent history)
            conn.execute(
                """CREATE TABLE IF NOT EXISTS jobs(
                       id TEXT PRIMARY KEY,
                       campaign_id TEXT NOT NULL,
                       created_at TEXT NOT NULL,
                       updated_at TEXT NOT NULL,
                       status TEXT NOT NULL,
                       snapshot TEXT NOT NULL
                   )"""
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_campaign ON jobs(campaign_id)")

            # Per-recipient outcomes (from PMTA accounting)
            conn.execute(
                """CREATE TABLE IF NOT EXISTS job_outcomes(
                       job_id TEXT NOT NULL,
                       rcpt TEXT NOT NULL,
                       status TEXT NOT NULL,
                       updated_at TEXT NOT NULL,
                       PRIMARY KEY(job_id, rcpt)
                   )"""
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_job_outcomes_job ON job_outcomes(job_id)")

            # Per-job recipient registry (helps map accounting rows with missing job/campaign ids)
            conn.execute(
                """CREATE TABLE IF NOT EXISTS job_recipients(
                       job_id TEXT NOT NULL,
                       campaign_id TEXT NOT NULL,
                       rcpt TEXT NOT NULL,
                       first_seen_at TEXT NOT NULL,
                       last_seen_at TEXT NOT NULL,
                       PRIMARY KEY(job_id, rcpt)
                   )"""
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_job_recipients_rcpt ON job_recipients(rcpt, last_seen_at)")

            # File offsets for PMTA accounting tailing
            conn.execute(
                """CREATE TABLE IF NOT EXISTS pmta_offsets(
                       path TEXT PRIMARY KEY,
                       offset INTEGER NOT NULL,
                       updated_at TEXT NOT NULL
                   )"""
            )

            # App-wide config overrides (UI-managed)
            conn.execute(
                """CREATE TABLE IF NOT EXISTS app_config(
                       key TEXT PRIMARY KEY,
                       value TEXT NOT NULL,
                       updated_at TEXT NOT NULL
                   )"""
            )

            conn.commit()

            # Optional: clear DB on startup (off by default)
            if _DB_CLEAR_ON_START:
                conn.execute("DELETE FROM campaign_form")
                conn.execute("DELETE FROM campaigns")
                conn.execute("DELETE FROM form_state")
                conn.execute("DELETE FROM jobs")
                conn.execute("DELETE FROM job_outcomes")
                conn.execute("DELETE FROM job_recipients")
                conn.commit()
        finally:
            conn.close()



def _sanitize_form_data(data: dict) -> dict:
    if not isinstance(data, dict):
        return {}
    out: Dict[str, Any] = {}
    for k, v in data.items():
        key = str(k or "").strip()
        if not key:
            continue
        if key not in _ALLOWED_FORM_FIELDS and _FORM_FIELD_KEY_RE.fullmatch(key) is None:
            continue
        if isinstance(v, bool):
            out[key] = v
        elif v is None:
            out[key] = ""
        else:
            s = str(v)
            if len(s) > 200000:
                s = s[:200000]
            out[key] = s
    return out


def db_get_form(browser_id: str) -> dict:
    if not browser_id:
        return {}
    with DB_LOCK:
        conn = _db_conn()
        try:
            row = conn.execute("SELECT data FROM form_state WHERE browser_id=?", (browser_id,)).fetchone()
            if not row:
                return {}
            try:
                return json.loads(row[0] or "{}")
            except Exception:
                return {}
        finally:
            conn.close()


def db_save_form(browser_id: str, data: dict) -> None:
    if not browser_id:
        return
    clean = _sanitize_form_data(data)
    payload = json.dumps(clean, ensure_ascii=False)
    if len(payload) > 800000:
        payload = payload[:800000]

    with DB_LOCK:
        conn = _db_conn()
        try:
            conn.execute(
                "INSERT INTO form_state(browser_id, data, updated_at) VALUES(?, ?, ?) "
                "ON CONFLICT(browser_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
                (browser_id, payload, now_iso()),
            )
            conn.commit()
        finally:
            conn.close()


def db_clear_form(browser_id: str) -> None:
    if not browser_id:
        return
    with DB_LOCK:
        conn = _db_conn()
        try:
            conn.execute("DELETE FROM form_state WHERE browser_id=?", (browser_id,))
            conn.commit()
        finally:
            conn.close()


def db_clear_all() -> None:
    with DB_LOCK:
        conn = _db_conn()
        try:
            conn.execute("DELETE FROM campaign_form")
            conn.execute("DELETE FROM campaigns")
            conn.execute("DELETE FROM form_state")
            conn.execute("DELETE FROM jobs")
            conn.execute("DELETE FROM job_outcomes")
            conn.execute("DELETE FROM job_recipients")
            conn.commit()
        finally:
            conn.close()


# =========================
# Jobs DB helpers (persistence)
# =========================

def _job_snapshot_dict(job: 'SendJob') -> dict:
    """Create a JSON-serializable snapshot of the job (bounded lists)."""
    return {
        "id": job.id,
        "campaign_id": job.campaign_id,
        "smtp_host": job.smtp_host or "",
        "pmta_live": job.pmta_live or {},
        "pmta_live_ts": job.pmta_live_ts or "",
        "pmta_domains": job.pmta_domains or {},
        "pmta_domains_ts": job.pmta_domains_ts or "",
        "pmta_pressure": job.pmta_pressure or {},
        "pmta_pressure_ts": job.pmta_pressure_ts or "",
        "pmta_diag": job.pmta_diag or {},
        "pmta_diag_ts": job.pmta_diag_ts or "",
        "created_at": job.created_at,
        "updated_at": job.updated_at or now_iso(),
        "status": job.status,
        "started_at": job.started_at,
        "paused": bool(job.paused),
        "stop_requested": bool(job.stop_requested),
        "stop_reason": job.stop_reason,
        "chunks_total": int(job.chunks_total or 0),
        "chunks_done": int(job.chunks_done or 0),
        "chunks_backoff": int(job.chunks_backoff or 0),
        "chunks_abandoned": int(job.chunks_abandoned or 0),
        "current_chunk": int(job.current_chunk or -1),
        "current_chunk_info": job.current_chunk_info or {},
        "current_chunk_domains": job.current_chunk_domains or {},
        "chunk_states": (job.chunk_states or [])[-200:],
        "backoff_items": (job.backoff_items or [])[-200:],
        "domain_plan": job.domain_plan or {},
        "domain_sent": job.domain_sent or {},
        "domain_failed": job.domain_failed or {},
        "error_counts": job.error_counts or {},
        "total": int(job.total or 0),
        "sent": int(job.sent or 0),
        "failed": int(job.failed or 0),
        "skipped": int(job.skipped or 0),
        "invalid": int(job.invalid or 0),
        # PMTA accounting outcomes
        "delivered": int(job.delivered or 0),
        "bounced": int(job.bounced or 0),
        "deferred": int(job.deferred or 0),
        "complained": int(job.complained or 0),
        "outcome_series": (job.outcome_series or [])[-180:],
        "accounting_last_ts": job.accounting_last_ts or "",
        "accounting_error_counts": job.accounting_error_counts or {},
        "accounting_last_errors": (job.accounting_last_errors or [])[-50:],
        "spam_threshold": float(job.spam_threshold or 4.0),
        "spam_score": job.spam_score,
        "spam_detail": (job.spam_detail or "")[:2000],
        "safe_list_total": int(job.safe_list_total or 0),
        "safe_list_invalid": int(job.safe_list_invalid or 0),
        "last_error": (job.last_error or "")[:600],
        "logs": [l.__dict__ for l in (job.logs or [])[-400:]],
        "recent_results": (job.recent_results or [])[-400:],
    }


def db_upsert_job(job: 'SendJob') -> None:
    """Upsert a job snapshot into SQLite."""
    if not job or not job.id:
        return
    if job.deleted:
        return
    snap = _job_snapshot_dict(job)
    payload = json.dumps(snap, ensure_ascii=False)
    if len(payload) > 900000:
        payload = payload[:900000]

    with DB_LOCK:
        conn = _db_conn()
        try:
            conn.execute(
                "INSERT INTO jobs(id, campaign_id, created_at, updated_at, status, snapshot) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET campaign_id=excluded.campaign_id, updated_at=excluded.updated_at, status=excluded.status, snapshot=excluded.snapshot",
                (job.id, job.campaign_id or "", job.created_at or now_iso(), job.updated_at or now_iso(), job.status or "", payload),
            )
            conn.commit()
        finally:
            conn.close()


def db_delete_job(job_id: str) -> None:
    jid = (job_id or "").strip()
    if not jid:
        return
    with DB_LOCK:
        conn = _db_conn()
        try:
            conn.execute("DELETE FROM jobs WHERE id=?", (jid,))
            conn.commit()
        finally:
            conn.close()


# =========================
# Outcomes DB helpers (PMTA accounting)
# =========================

def db_get_outcome(job_id: str, rcpt: str) -> Optional[str]:
    jid = (job_id or "").strip()
    r = (rcpt or "").strip().lower()
    if not jid or not r:
        return None
    with DB_LOCK:
        conn = _db_conn()
        try:
            row = conn.execute(
                "SELECT status FROM job_outcomes WHERE job_id=? AND rcpt=?",
                (jid, r),
            ).fetchone()
            return str(row[0]) if row and row[0] else None
        finally:
            conn.close()


def db_set_outcome(job_id: str, rcpt: str, status: str) -> None:
    jid = (job_id or "").strip()
    r = (rcpt or "").strip().lower()
    st = (status or "").strip().lower()
    if not jid or not r or not st:
        return
    with DB_LOCK:
        conn = _db_conn()
        try:
            conn.execute(
                "INSERT INTO job_outcomes(job_id, rcpt, status, updated_at) VALUES(?,?,?,?) "
                "ON CONFLICT(job_id, rcpt) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at",
                (jid, r, st, now_iso()),
            )
            conn.commit()
        finally:
            conn.close()


def db_list_outcome_rcpts(job_id: str, status: str) -> List[str]:
    jid = (job_id or "").strip()
    st = (status or "").strip().lower()
    if not jid or not st:
        return []
    with DB_LOCK:
        conn = _db_conn()
        try:
            rows = conn.execute(
                "SELECT rcpt FROM job_outcomes WHERE job_id=? AND status=? ORDER BY updated_at DESC",
                (jid, st),
            ).fetchall()
            out: List[str] = []
            seen: Set[str] = set()
            for r in rows or []:
                em = str(r[0] or "").strip().lower()
                if not em or em in seen:
                    continue
                seen.add(em)
                out.append(em)
            return out
        finally:
            conn.close()


def db_get_app_config(key: str) -> Optional[str]:
    k = (key or "").strip()
    if not k:
        return None
    try:
        with DB_LOCK:
            conn = _db_conn()
            try:
                row = conn.execute("SELECT value FROM app_config WHERE key=?", (k,)).fetchone()
                return str(row[0]) if row and row[0] is not None else None
            finally:
                conn.close()
    except Exception:
        return None


def db_list_app_config() -> dict:
    """Return all UI-stored config overrides as a dict."""
    out: Dict[str, str] = {}
    try:
        with DB_LOCK:
            conn = _db_conn()
            try:
                rows = conn.execute("SELECT key, value FROM app_config").fetchall()
            finally:
                conn.close()
        for r in rows or []:
            k = str(r[0] or "").strip()
            if not k:
                continue
            out[k] = "" if r[1] is None else str(r[1])
    except Exception:
        return {}
    return out


def db_set_app_config(key: str, value: str) -> Tuple[bool, str]:
    k = (key or "").strip()
    if not k:
        return False, "missing key"
    v = "" if value is None else str(value)
    if len(v) > 20000:
        v = v[:20000]
    try:
        with DB_LOCK:
            conn = _db_conn()
            try:
                ts = now_iso()
                # Prefer modern SQLite UPSERT syntax, but keep a legacy fallback for
                # older SQLite builds that raise: `near "ON": syntax error`.
                try:
                    conn.execute(
                        "INSERT INTO app_config(key, value, updated_at) VALUES(?,?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                        (k, v, ts),
                    )
                except Exception as upsert_err:
                    if "near \"ON\"" not in str(upsert_err):
                        raise
                    cur = conn.execute(
                        "UPDATE app_config SET value=?, updated_at=? WHERE key=?",
                        (v, ts, k),
                    )
                    if (cur.rowcount or 0) <= 0:
                        conn.execute(
                            "INSERT INTO app_config(key, value, updated_at) VALUES(?,?,?)",
                            (k, v, ts),
                        )
                conn.commit()
            finally:
                conn.close()
        return True, ""
    except Exception as e:
        return False, str(e)


def db_delete_app_config(key: str) -> bool:
    k = (key or "").strip()
    if not k:
        return False
    try:
        with DB_LOCK:
            conn = _db_conn()
            try:
                cur = conn.execute("DELETE FROM app_config WHERE key=?", (k,))
                conn.commit()
                return (cur.rowcount or 0) > 0
            finally:
                conn.close()
    except Exception:
        return False



def _sendjob_from_snapshot(s: dict) -> Optional['SendJob']:
    try:
        jid = str(s.get("id") or "").strip()
        if not jid:
            return None
        job = SendJob(id=jid, created_at=str(s.get("created_at") or now_iso()))
        job.campaign_id = str(s.get("campaign_id") or "")
        job.smtp_host = str(s.get("smtp_host") or "")
        job.pmta_live = (s.get("pmta_live") if isinstance(s.get("pmta_live"), dict) else {}) or {}
        job.pmta_live_ts = str(s.get("pmta_live_ts") or "")
        job.pmta_domains = (s.get("pmta_domains") if isinstance(s.get("pmta_domains"), dict) else {}) or {}
        job.pmta_domains_ts = str(s.get("pmta_domains_ts") or "")
        job.pmta_pressure = (s.get("pmta_pressure") if isinstance(s.get("pmta_pressure"), dict) else {}) or {}
        job.pmta_pressure_ts = str(s.get("pmta_pressure_ts") or "")
        job.pmta_diag = (s.get("pmta_diag") if isinstance(s.get("pmta_diag"), dict) else {}) or {}
        job.pmta_diag_ts = str(s.get("pmta_diag_ts") or "")
        job.updated_at = str(s.get("updated_at") or "")
        job.status = str(s.get("status") or "queued")
        job.started_at = str(s.get("started_at") or "")
        job.paused = bool(s.get("paused") or False)
        job.stop_requested = bool(s.get("stop_requested") or False)
        job.stop_reason = str(s.get("stop_reason") or "")

        job.chunks_total = int(s.get("chunks_total") or 0)
        job.chunks_done = int(s.get("chunks_done") or 0)
        job.chunks_backoff = int(s.get("chunks_backoff") or 0)
        job.chunks_abandoned = int(s.get("chunks_abandoned") or 0)
        job.current_chunk = int(s.get("current_chunk") or -1)
        job.current_chunk_info = s.get("current_chunk_info") or {}
        job.current_chunk_domains = s.get("current_chunk_domains") or {}
        job.chunk_states = list(s.get("chunk_states") or [])
        job.backoff_items = list(s.get("backoff_items") or [])

        job.domain_plan = s.get("domain_plan") or {}
        job.domain_sent = s.get("domain_sent") or {}
        job.domain_failed = s.get("domain_failed") or {}
        job.error_counts = s.get("error_counts") or {}

        job.total = int(s.get("total") or 0)
        job.sent = int(s.get("sent") or 0)
        job.failed = int(s.get("failed") or 0)
        job.skipped = int(s.get("skipped") or 0)
        job.invalid = int(s.get("invalid") or 0)

        # outcomes
        job.delivered = int(s.get("delivered") or 0)
        job.bounced = int(s.get("bounced") or 0)
        job.deferred = int(s.get("deferred") or 0)
        job.complained = int(s.get("complained") or 0)
        job.outcome_series = list(s.get("outcome_series") or [])
        job.accounting_last_ts = str(s.get("accounting_last_ts") or "")
        job.accounting_error_counts = dict(s.get("accounting_error_counts") or {})
        job.accounting_last_errors = list(s.get("accounting_last_errors") or [])

        job.spam_threshold = float(s.get("spam_threshold") or 4.0)
        job.spam_score = s.get("spam_score")
        job.spam_detail = str(s.get("spam_detail") or "")
        job.safe_list_total = int(s.get("safe_list_total") or 0)
        job.safe_list_invalid = int(s.get("safe_list_invalid") or 0)
        job.last_error = str(s.get("last_error") or "")

        # logs
        job.logs = []
        for l in (s.get("logs") or []):
            if isinstance(l, dict):
                job.logs.append(JobLog(ts=str(l.get("ts") or ""), level=str(l.get("level") or ""), message=str(l.get("message") or "")))
        job.recent_results = list(s.get("recent_results") or [])

        # Throttle state
        job.persist_ts = time.time()
        job.persist_counter = 0

        # If job was active when server died, mark as stopped (history only)
        if job.status in {"queued", "running", "backoff", "paused"}:
            job.status = "stopped"
            job.stop_requested = True
            job.paused = False
            job.stop_reason = job.stop_reason or "restored from DB (server restarted)"
            job.log("WARN", "Restored from DB; job was active but server restarted. Marked as stopped.")

        return job
    except Exception:
        return None


def db_load_jobs_into_memory() -> None:
    """Load historical jobs from SQLite into JOBS dict (in-memory)."""
    with DB_LOCK:
        conn = _db_conn()
        try:
            rows = conn.execute("SELECT snapshot FROM jobs ORDER BY created_at DESC").fetchall()
        finally:
            conn.close()

    loaded: Dict[str, SendJob] = {}
    for r in rows or []:
        try:
            s = json.loads(r[0] or "{}")
        except Exception:
            continue
        job = _sendjob_from_snapshot(s)
        if job and job.id and not job.deleted:
            loaded[job.id] = job

    with JOBS_LOCK:
        # Don't overwrite currently-running jobs; just backfill missing ones.
        for jid, j in loaded.items():
            if jid not in JOBS:
                JOBS[jid] = j


# =========================
# Campaign DB helpers
# =========================

def db_list_campaigns(browser_id: str) -> List[dict]:
    if not browser_id:
        return []
    with DB_LOCK:
        conn = _db_conn()
        try:
            rows = conn.execute(
                "SELECT id, name, created_at, updated_at FROM campaigns WHERE browser_id=? ORDER BY updated_at DESC",
                (browser_id,),
            ).fetchall()
            return [
                {"id": r[0], "name": r[1], "created_at": r[2], "updated_at": r[3]}
                for r in (rows or [])
            ]
        finally:
            conn.close()


def db_get_campaign(browser_id: str, campaign_id: str) -> Optional[dict]:
    if not browser_id or not campaign_id:
        return None
    with DB_LOCK:
        conn = _db_conn()
        try:
            r = conn.execute(
                "SELECT id, name, created_at, updated_at FROM campaigns WHERE browser_id=? AND id=?",
                (browser_id, campaign_id),
            ).fetchone()
            if not r:
                return None
            return {"id": r[0], "name": r[1], "created_at": r[2], "updated_at": r[3]}
        finally:
            conn.close()


def db_create_campaign(browser_id: str, name: str) -> dict:
    if not browser_id:
        raise ValueError("browser_id required")
    cid = uuid.uuid4().hex[:12]
    nm = (name or "").strip() or f"Campaign {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
    ts = now_iso()
    with DB_LOCK:
        conn = _db_conn()
        try:
            conn.execute(
                "INSERT INTO campaigns(id, browser_id, name, created_at, updated_at) VALUES(?,?,?,?,?)",
                (cid, browser_id, nm, ts, ts),
            )
            conn.execute(
                "INSERT OR REPLACE INTO campaign_form(campaign_id, data, updated_at) VALUES(?,?,?)",
                (cid, json.dumps({}, ensure_ascii=False), ts),
            )
            conn.commit()
        finally:
            conn.close()
    return {"id": cid, "name": nm, "created_at": ts, "updated_at": ts}


def db_rename_campaign(browser_id: str, campaign_id: str, name: str) -> bool:
    nm = (name or "").strip()
    if not browser_id or not campaign_id or not nm:
        return False
    with DB_LOCK:
        conn = _db_conn()
        try:
            cur = conn.execute(
                "UPDATE campaigns SET name=?, updated_at=? WHERE browser_id=? AND id=?",
                (nm, now_iso(), browser_id, campaign_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def db_delete_campaign(browser_id: str, campaign_id: str) -> bool:
    if not browser_id or not campaign_id:
        return False
    with DB_LOCK:
        conn = _db_conn()
        try:
            r = conn.execute(
                "SELECT 1 FROM campaigns WHERE browser_id=? AND id=?",
                (browser_id, campaign_id),
            ).fetchone()
            if not r:
                return False
            conn.execute("DELETE FROM campaign_form WHERE campaign_id=?", (campaign_id,))
            conn.execute("DELETE FROM campaigns WHERE id=?", (campaign_id,))
            # delete all jobs for this campaign
            conn.execute("DELETE FROM jobs WHERE campaign_id=?", (campaign_id,))
            conn.commit()

            # remove in-memory jobs too
            with JOBS_LOCK:
                for jid in [k for k,v in JOBS.items() if (v.campaign_id or "") == campaign_id]:
                    try:
                        del JOBS[jid]
                    except Exception:
                        pass

            return True
        finally:
            conn.close()


def db_get_campaign_form(browser_id: str, campaign_id: str) -> dict:
    if not browser_id or not campaign_id:
        return {}
    if not db_get_campaign(browser_id, campaign_id):
        return {}
    with DB_LOCK:
        conn = _db_conn()
        try:
            row = conn.execute("SELECT data FROM campaign_form WHERE campaign_id=?", (campaign_id,)).fetchone()
            if not row:
                return {}
            try:
                return json.loads(row[0] or "{}")
            except Exception:
                return {}
        finally:
            conn.close()


def db_get_campaign_form_raw(campaign_id: str) -> dict:
    """Read campaign form data by campaign_id (no browser_id).

    Used by the background sender thread to sync settings between chunks.
    """
    cid = (campaign_id or "").strip()
    if not cid:
        return {}
    with DB_LOCK:
        conn = _db_conn()
        try:
            row = conn.execute("SELECT data FROM campaign_form WHERE campaign_id=?", (cid,)).fetchone()
            if not row:
                return {}
            try:
                return json.loads(row[0] or "{}")
            except Exception:
                return {}
        finally:
            conn.close()



def db_save_campaign_form(browser_id: str, campaign_id: str, data: dict) -> bool:
    if not browser_id or not campaign_id:
        return False
    if not db_get_campaign(browser_id, campaign_id):
        return False

    clean = _sanitize_form_data(data)
    payload = json.dumps(clean, ensure_ascii=False)
    if len(payload) > 800000:
        payload = payload[:800000]

    ts = now_iso()
    with DB_LOCK:
        conn = _db_conn()
        try:
            cur = conn.execute(
                "UPDATE campaign_form SET data=?, updated_at=? WHERE campaign_id=?",
                (payload, ts, campaign_id),
            )
            if cur.rowcount == 0:
                conn.execute(
                    "INSERT INTO campaign_form(campaign_id, data, updated_at) VALUES(?,?,?)",
                    (campaign_id, payload, ts),
                )
            conn.execute(
                "UPDATE campaigns SET updated_at=? WHERE browser_id=? AND id=?",
                (ts, browser_id, campaign_id),
            )
            conn.commit()
            return True
        finally:
            conn.close()


def db_clear_campaign_form(browser_id: str, campaign_id: str) -> bool:
    if not browser_id or not campaign_id:
        return False
    if not db_get_campaign(browser_id, campaign_id):
        return False
    ts = now_iso()
    with DB_LOCK:
        conn = _db_conn()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO campaign_form(campaign_id, data, updated_at) VALUES(?,?,?)",
                (campaign_id, json.dumps({}, ensure_ascii=False), ts),
            )
            conn.execute(
                "UPDATE campaigns SET updated_at=? WHERE browser_id=? AND id=?",
                (ts, browser_id, campaign_id),
            )
            conn.commit()
            return True
        finally:
            conn.close()



def _valid_browser_id(bid: str) -> bool:
    return bool(bid) and (re.fullmatch(r"[a-f0-9]{16,64}", bid) is not None)


def get_or_create_browser_id() -> Tuple[str, bool]:
    bid = (request.cookies.get(BROWSER_COOKIE) or "").strip()
    if _valid_browser_id(bid):
        return bid, False
    return uuid.uuid4().hex, True


def attach_browser_cookie(resp, bid: str, is_new: bool):
    if is_new:
        resp.set_cookie(
            BROWSER_COOKIE,
            bid,
            max_age=60 * 60 * 24 * 365 * 2,
            httponly=True,
            samesite="Lax",
        )
    return resp


db_init()
# Load job history (so Jobs persist across page reloads / restarts)
db_load_jobs_into_memory()

# =========================
# OpenRouter AI (optional)
# =========================
OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = "arcee-ai/trinity-large-preview:free"
OPENROUTER_TIMEOUT_S = 40


def _extract_json_object(text: str) -> Optional[dict]:
    """Best-effort: extract a JSON object from model output."""
    if not text:
        return None
    t = text.strip()
    if t.startswith("{") and t.endswith("}"):
        try:
            return json.loads(t)
        except Exception:
            pass
    i = t.find("{")
    j = t.rfind("}")
    if i != -1 and j != -1 and j > i:
        frag = t[i : j + 1]
        try:
            return json.loads(frag)
        except Exception:
            return None
    return None


def ai_rewrite_subjects_and_body(
    *,
    token: str,
    subjects: List[str],
    body: str,
    body_format: str,
) -> Tuple[List[str], str, str]:
    """Rewrite subject lines + body using OpenRouter.

    Returns: (new_subjects, new_body, backend_info)

    Notes:
    - This is for readability/professional tone.
    - Preserves placeholders: [URL], [SRC], [EMAIL] exactly.
    - Keeps meaning, does not add new claims.
    """
    if not token:
        raise ValueError("AI token is required")

    subj_in = subjects[:30] if subjects else ["(no subject)"]
    body_in = body[:12000]

    sys = (
        "You rewrite email subject lines and body for clarity and professionalism, "
        "keeping the same meaning. Do NOT add new claims, promotions, or calls to action. "
        "Preserve these placeholders exactly (do not remove/rename them): [URL], [SRC], [EMAIL]. "
        "Keep the output language the same as input. "
        "Return ONLY valid JSON with keys: subjects (array of strings), body (string)."
    )

    user = {
        "subject_lines": subj_in,
        "body_format": body_format,
        "body": body_in,
        "constraints": {
            "preserve_placeholders": ["[URL]", "[SRC]", "[EMAIL]"],
            "no_new_claims": True,
            "json_only": True,
        },
    }

    payload = {
        "model": OPENROUTER_MODEL,
        "messages": [
            {"role": "system", "content": sys},
            {"role": "user", "content": json.dumps(user, ensure_ascii=False)},
        ],
        "temperature": 0.7,
        "max_tokens": 900,
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        # Optional attribution headers (recommended by OpenRouter)
        "HTTP-Referer": "http://localhost",
        "X-Title": "ShivaMTA SMTP Sender",
    }

    req = Request(
        OPENROUTER_ENDPOINT,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        with urlopen(req, timeout=OPENROUTER_TIMEOUT_S) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
    except HTTPError as e:
        err = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else str(e)
        raise RuntimeError(f"OpenRouter HTTPError: {e.code} {err[:500]}")
    except URLError as e:
        raise RuntimeError(f"OpenRouter URLError: {e}")

    data = json.loads(raw)
    content = (
        data.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )

    out = _extract_json_object(content)
    if not out:
        raise RuntimeError("AI output was not valid JSON")

    new_subjects = out.get("subjects")
    new_body = out.get("body")

    # Normalize subjects
    if isinstance(new_subjects, str):
        new_subjects = [new_subjects]
    if not isinstance(new_subjects, list):
        new_subjects = []

    cleaned: List[str] = []
    for x in new_subjects:
        if x is None:
            continue
        s = str(x).strip()
        if not s:
            continue
        # Avoid common bad placeholders from models
        if s.lower() in {"undefined", "null", "none"}:
            continue
        cleaned.append(s)

    new_subjects = cleaned

    # Normalize body
    new_body = "" if new_body is None else str(new_body)

    # Fallbacks
    if not new_subjects:
        new_subjects = subj_in
    if not new_body.strip():
        new_body = body_in

    backend_info = f"openrouter:{OPENROUTER_MODEL}"
    return new_subjects, new_body, backend_info

# =========================
# HTML UI (single-file)
# =========================
PAGE_FORM = r"""
<!doctype html>
<html lang="en" dir="ltr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>SMTP Mail Sender</title>
  <style>
    :root{
      --bg1:#0b1020; --bg2:#0a1a2b;
      --card: rgba(255,255,255,.08);
      --card2: rgba(255,255,255,.06);
      --border: rgba(255,255,255,.14);
      --text: rgba(255,255,255,.92);
      --muted: rgba(255,255,255,.65);
      --good: #35e49a;
      --bad: #ff5e73;
      --warn: #ffc14d;
      --accent:#7aa7ff;
      --shadow: 0 20px 60px rgba(0,0,0,.35);
      --radius: 18px;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family: system-ui, -apple-system, "Segoe UI", Tahoma, Arial;
      color: var(--text);
      background:
        radial-gradient(1000px 700px at 80% 20%, rgba(122,167,255,.22), transparent 60%),
        radial-gradient(900px 700px at 20% 30%, rgba(53,228,154,.16), transparent 60%),
        linear-gradient(180deg, var(--bg1), var(--bg2));
      min-height:100vh;
      padding: 28px 14px;
    }
    .wrap{max-width: 1100px; margin: 0 auto;}
    .top{
      display:flex; gap:14px; align-items:flex-start; justify-content:space-between;
      flex-wrap:wrap; margin-bottom: 18px;
    }
    h1{ margin:0; font-size: 22px; letter-spacing: .2px; }
    .sub{
      margin-top:6px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
      max-width: 740px;
    }
    .badge{
      display:inline-flex; align-items:center; gap:8px;
      padding: 10px 12px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 999px;
      box-shadow: var(--shadow);
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
      text-decoration:none;
    }

    .topActions{ display:flex; flex-direction:column; gap:10px; align-items:flex-end; }
    .topLinks{ display:flex; gap:10px; flex-wrap:wrap; justify-content:flex-end; }
    @media (max-width: 520px){
      .topActions{ align-items:stretch; width:100%; }
      .topLinks{ justify-content:flex-start; }
    }

    .grid{ display:grid; grid-template-columns: 1fr 1fr; gap: 14px; }
    .stack{ display:flex; flex-direction:column; gap:14px; }
    @media (max-width: 980px){ .grid{grid-template-columns: 1fr;} }
    .card{
      background: linear-gradient(180deg, var(--card), var(--card2));
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 16px;
      backdrop-filter: blur(10px);
    }
    .card h2{ margin:0 0 10px; font-size: 16px; color: rgba(255,255,255,.88); }
    label{ display:block; margin: 10px 0 6px; color: var(--muted); font-size: 12px; }
    input, select, textarea{
      width:100%;
      padding: 11px 12px;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,.16);
      background: rgba(0,0,0,.18);
      color: var(--text);
      outline: none;
    }
    input::placeholder, textarea::placeholder{color: rgba(255,255,255,.35)}
    textarea{min-height: 130px; resize: vertical}
    .row{ display:grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    @media (max-width: 520px){ .row{grid-template-columns: 1fr;} }
    .hint{
      margin-top: 10px;
      padding: 10px 12px;
      border-radius: 14px;
      border: 1px dashed rgba(255,255,255,.18);
      background: rgba(255,255,255,.06);
      color: var(--muted);
      font-size: 12px;
      line-height: 1.6;
    }
    .actions{
      display:flex;
      gap: 10px;
      align-items:center;
      justify-content:flex-start;
      flex-wrap: wrap;
      margin-top: 14px;
    }
    .btn{
      border: 1px solid rgba(255,255,255,.18);
      background: rgba(122,167,255,.18);
      color: var(--text);
      padding: 12px 14px;
      border-radius: 14px;
      cursor:pointer;
      font-weight: 600;
      letter-spacing:.2px;
    }
    .btn:hover{filter: brightness(1.06)}
    .btn.secondary{ background: rgba(255,255,255,.08); }
    .btn:disabled{ opacity:.55; cursor:not-allowed; }

    .check{
      display:flex; gap: 8px; align-items:flex-start;
      padding: 10px 12px;
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,.14);
      background: rgba(0,0,0,.12);
      color: var(--muted);
      font-size: 12px;
      line-height: 1.55;
      margin-top: 12px;
    }
    .check input{width:auto; margin-top: 2px;}
    .foot{ margin-top: 16px; color: rgba(255,255,255,.45); font-size: 12px; line-height: 1.7; }
    .mini{ font-size: 12px; color: var(--muted); margin-top: 8px; }
    .muted{ color: var(--muted); }
    code{background:rgba(255,255,255,.08); padding:2px 6px; border-radius:8px;}
    .muted{color:var(--muted)}

    .smallBar{height:8px; border-radius:999px; background:rgba(255,255,255,.10); border:1px solid rgba(255,255,255,.12); overflow:hidden}
    .smallBar > div{height:100%; width:0%; background: rgba(53,228,154,.55);}
    .extractBtn{
      border:1px solid rgba(122,167,255,.45);
      background: linear-gradient(135deg, rgba(122,167,255,.32), rgba(53,228,154,.18));
      color:#fff;
      font-weight:800;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.16), 0 8px 20px rgba(7,12,28,.35);
      transition: transform .12s ease, filter .12s ease, box-shadow .12s ease;
    }
    .extractBtn:hover{
      filter:brightness(1.08);
      transform: translateY(-1px);
      box-shadow: inset 0 1px 0 rgba(255,255,255,.2), 0 10px 24px rgba(7,12,28,.4);
    }
    .extractBtn:active{transform: translateY(0)}
    .extractBtn:disabled{opacity:.65; cursor:not-allowed; transform:none; filter:none; box-shadow:none;}

    /* Top navigation (Back to Campaign) */
    .nav{display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin:8px 0 14px;}
    .nav a, .nav button{
      display:inline-flex;
      align-items:center;
      gap:8px;
      padding:8px 10px;
      border:1px solid rgba(255,255,255,.14);
      background: rgba(255,255,255,.06);
      border-radius: 12px;
      text-decoration:none;
    }
    .nav a:hover{filter:brightness(1.06)}
    .nav a.primary{ background: rgba(122,167,255,.14); font-weight:800; }
    table{width:100%; border-collapse:collapse; font-size: 12px;}
    th,td{padding:8px; border-bottom:1px solid rgba(255,255,255,.10); text-align:left; vertical-align:top}

    /* Toast */
    .toast-wrap{ position: fixed; right: 16px; bottom: 16px; z-index: 9999; display:flex; flex-direction:column; gap:10px; }
    .toast{
      min-width: 280px;
      max-width: 420px;
      background: rgba(0,0,0,.55);
      border: 1px solid rgba(255,255,255,.18);
      box-shadow: 0 18px 55px rgba(0,0,0,.35);
      backdrop-filter: blur(10px);
      border-radius: 14px;
      padding: 12px 14px;
      color: rgba(255,255,255,.92);
      font-size: 13px;
      line-height: 1.5;
      animation: pop .18s ease-out;
    }
    @keyframes pop{ from{ transform: translateY(6px); opacity: .2; } to{ transform: translateY(0); opacity: 1; } }
    .toast .t{font-weight:800; margin-bottom:4px}
    .toast.good{ border-color: rgba(53,228,154,.35); }
    .toast.bad{ border-color: rgba(255,94,115,.35); }
    .toast.warn{ border-color: rgba(255,193,77,.35); }

    .inline-status{
      margin-top: 10px;
      padding: 10px 12px;
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,.14);
      background: rgba(0,0,0,.12);
      color: var(--muted);
      font-size: 12px;
      line-height: 1.6;
      display:none;
    }
    .inline-status.show{ display:block; }
    .inline-status b{ color: rgba(255,255,255,.88); }
  </style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div>
      <h1>SMTP Mail Sender · <span style="color: var(--muted)">{{campaign_name}}</span></h1>
      <div class="sub">
        A simple, clean UI to send email via SMTP with a progress bar and logs.
        <br>
        <b style="color: var(--warn)">⚠️ Legal use only:</b> send to opt-in/permission-based recipients.
      </div>
    </div>
    <div class="topActions">
      <a class="badge" href="/campaigns">📌 Campaigns</a>
    </div>
  </div>

  <form class="grid" method="post" action="/start" enctype="multipart/form-data" id="mainForm">
    <input type="hidden" name="campaign_id" value="{{campaign_id}}">
    <div class="stack">
      <div class="card">
      <h2>SMTP Settings</h2>

      <div class="row">
        <div>
          <label>SMTP Host</label>
          <input name="smtp_host" placeholder="Example: mail.example.com or an IP" required>
        </div>
        <div>
          <label>Port</label>
          <input name="smtp_port" type="number" placeholder="Example: 25 / 2525 / 587 / 465" required value="2525">
        </div>
      </div>

      <div class="row">
        <div>
          <label>Security</label>
          <select name="smtp_security">
            <option value="starttls">STARTTLS (587)</option>
            <option value="ssl">SSL/TLS (465)</option>
            <option value="none" selected>None (not recommended)</option>
          </select>
        </div>
        <div>
          <label>Timeout (seconds)</label>
          <input name="smtp_timeout" type="number" value="25" min="5" max="120">
        </div>
      </div>

      <div class="row">
        <div>
          <label>SMTP Username (optional)</label>
          <input name="smtp_user" placeholder="Example: user@example.com">
        </div>
        <div>
          <label>SMTP Password (optional)</label>
          <input name="smtp_pass" type="password" placeholder="••••••••">
        </div>
      </div>

      <div class="check" style="margin-top:10px">
        <input type="checkbox" id="remember_pass" name="remember_pass">
        <div>
          Remember SMTP password on this browser (saved in server database (SQLite)). <b style="color: var(--warn)">Not recommended</b> on shared PCs.
        </div>
      </div>

      <div class="hint">
        <b>Note:</b> If you use PowerMTA or a custom SMTP server, set the correct host and port.
        Usually: <code>587 + STARTTLS</code> or <code>465 + SSL/TLS</code>.
        <br>
        ✅ <b>Test SMTP</b> only connects (and authenticates if provided) — <b>it does not send any email</b>.
      </div>

      <div class="actions">
        <button class="btn secondary" type="button" id="btnTest">🔌 Test SMTP</button>
        <div class="mini" id="testMini">Test the connection before sending.</div>
      </div>
      <div class="inline-status" id="smtpTestInline"></div>
      </div>

      <div class="card">
        <h2>Preflight & Send Controls</h2>

        <div class="check">
        <input type="checkbox" name="permission_ok" required>
        <div>
          I confirm this recipient list is <b>permission-based (opt-in)</b> and this usage is lawful.
          (Sending is blocked without this confirmation.)
        </div>
      </div>

      <div class="hint" id="preflightBox" style="margin-top:12px">
        <b>Preflight stats (optional):</b> get the <b>Spam score</b> + check if the <b>sender domain / SMTP IP</b> is blacklisted.
        <div class="row" style="margin-top:10px">
          <div>
            <div class="mini"><b>Spam score:</b> <span id="pfSpam">—</span></div>
            <div class="mini" id="pfSpamMore" style="display:none"></div>
          </div>
          <div>
            <div class="mini"><b>Blacklist:</b> <span id="pfBl">—</span></div>
            <div class="mini" id="pfBlMore" style="display:none"></div>
          </div>
        </div>
        <div class="mini" style="margin-top:10px"><b>Sender domains status:</b> Domain → IP(s) → Listed/Not listed</div>
        <div style="overflow:auto; margin-top:8px">
          <table style="width:100%; border-collapse:collapse; font-size:12px">
            <thead>
              <tr>
                <th style="text-align:left; padding:6px; border-bottom:1px solid rgba(255,255,255,.10)">Domain</th>
                <th style="text-align:left; padding:6px; border-bottom:1px solid rgba(255,255,255,.10)">IP(s)</th>
                <th style="text-align:left; padding:6px; border-bottom:1px solid rgba(255,255,255,.10)">Status</th>
                <th style="text-align:left; padding:6px; border-bottom:1px solid rgba(255,255,255,.10)">Spam score (per domain)</th>
              </tr>
            </thead>
            <tbody id="pfDomains">
              <tr><td colspan="4" class="muted" style="padding:6px">Run Preflight to see sender domains.</td></tr>
            </tbody>
          </table>
        </div>

        <div class="actions" style="margin-top:10px">
          <button class="btn secondary" type="button" id="btnPreflight">📊 Preflight Check</button>
          <div class="mini">Uses SpamAssassin backend (if available) + DNSBL checks (server-side).</div>
        </div>

        <div class="hint" style="margin-top:10px">
          <b>Sending controls:</b> these settings affect the real sending job.
          <div class="mini">Rule: <b>one chunk uses one sender email</b> (rotated by chunk index). Each chunk can use many workers.</div>

          <div class="row" style="margin-top:10px">
            <div>
              <label>Delay between messages (seconds)</label>
              <input name="delay_s" type="number" value="0.0" step="0.1" min="0" max="10">
            </div>
            <div>
              <label>Max Recipients (safety)</label>
              <input name="max_rcpt" type="number" value="300" min="1" max="200000">
            </div>
          </div>

          <div class="row" style="margin-top:10px">
            <div>
              <label>Thread chunk size</label>
              <input name="chunk_size" type="number" value="50" min="1" max="50000">
              <div class="mini">Recipients are split into chunks of this size. Each chunk picks one sender email.</div>
            </div>
            <div>
              <label>Thread workers</label>
              <input name="thread_workers" type="number" value="5" min="1" max="200">
              <div class="mini">Workers send in parallel inside the same chunk (one SMTP connection per worker).</div>
            </div>
          </div>

          <div class="row" style="margin-top:10px">
            <div>
              <label>Sleep between chunks (seconds)</label>
              <input name="sleep_chunks" type="number" value="0.0" step="0.1" min="0" max="120">
            </div>
            <div>
              <div class="mini" style="margin-top:26px">Tip: start with <b>chunk size 20–100</b> and <b>workers 2–10</b>.</div>
            </div>
          </div>

          <div class="check" style="margin-top:10px">
            <input type="checkbox" name="enable_backoff" {% if default_enable_backoff %}checked{% endif %}>
            <div>
              Enable backoff protection (spam/PMTA policy). Turn this OFF to continue sending even when spam or PMTA policy signals would pause a chunk. DNSBL (domain/IP blacklist) is info-only.
            </div>
          </div>
        </div>

        <div class="hint" style="margin-top:10px">
            <b>AI rewrite (optional):</b> rewrite subject/body for clarity (requires OpenRouter token).
            <div class="row" style="margin-top:10px">
              <div>
                <label>AI Token (OpenRouter)</label>
                <input name="ai_token" type="password" placeholder="sk-or-..." autocomplete="off">
                <div class="mini">Token is not saved unless you enable the checkbox below.</div>
              </div>
              <div>
                <label>&nbsp;</label>
                <div class="check" style="margin-top:0">
                  <input type="checkbox" name="use_ai" id="use_ai">
                  <div>
                    Use AI rewrite before sending (applies once per job).
                  </div>
                </div>
                <div class="check" style="margin-top:10px">
                  <input type="checkbox" id="remember_ai" name="remember_ai">
                  <div>
                    Remember AI token on this browser (server database / SQLite). <b style="color: var(--warn)">Not recommended</b> on shared PCs.
                  </div>
                </div>
              </div>
            </div>
            <div class="actions" style="margin-top:10px">
              <button class="btn secondary" type="button" id="btnAiRewrite">🤖 Rewrite Now</button>
              <div class="mini" id="aiMini">Rewrites the current Subject lines + Body and fills the fields (review before sending).</div>
            </div>
          </div>

        
      </div>
      </div>
    </div>

    <div class="card">
      <h2>Message</h2>

      <div class="row">
        <div>
          <label>Sender Name</label>
          <textarea name="from_name" placeholder="Example: Ahmed (one per line)" required style="min-height:48px"></textarea>
        </div>
        <div>
          <label>Sender Email</label>
          <textarea name="from_email" placeholder="Example: sender@domain.com (one per line)" required style="min-height:48px"></textarea>
        </div>
      </div>

      <label>Subject</label>
      <textarea name="subject" placeholder="Email subject (one per line)" required style="min-height:48px"></textarea>

      <div class="row">
        <div>
          <label>Format</label>
          <select name="body_format">
            <option value="text" selected>Text</option>
            <option value="html">HTML</option>
          </select>
          <div class="mini">If you choose HTML, the email will be sent as HTML.</div>
        </div>
        <div>
          <label>Reply-To (optional)</label>
          <input name="reply_to" placeholder="reply@domain.com">
        </div>
      </div>

      <label>Spam score limit</label>
      <input type="range" class="form-range" min="1" max="10" value="4" step="0.5" style="width: 100%;" name="score_range" id="score_range">
      <div class="mini">Current limit: <b id="score_range_val">4.0</b> (sending is blocked if spam score is higher)</div>

      <label>Body</label>
      <textarea name="body" placeholder="Write your message here..." required></textarea>

      <div class="row" style="margin-top:10px">
        <div>
          <label>URL list (one per line)</label>
          <textarea name="urls_list" placeholder="https://example.com/a
https://example.com/b" style="min-height:90px"></textarea>
          <div class="mini">Use <code>[URL]</code> in the body. It will be replaced per email using a pseudo-random value from this list.</div>
        </div>
        <div>
          <label>SRC list (one per line)</label>
          <textarea name="src_list" placeholder="https://cdn.example.com/img1.png
https://cdn.example.com/img2.png" style="min-height:90px"></textarea>
          <div class="mini">Use <code>[SRC]</code> in the body. It will be replaced per email using a pseudo-random value from this list.</div>
        </div>
      </div>

      <h2 style="margin-top:14px">Recipients</h2>

      <label>Recipients (newline / comma / semicolon)</label>
      <textarea name="recipients" placeholder="a@x.com\nb@y.com\nc@z.com"></textarea>

      <label>Or upload a .txt or .csv file (single column or multiple columns)</label>
      <input type="file" name="recipients_file" accept=".txt,.csv">

      <label>Maillist Safe (optional whitelist)</label>
      <textarea name="maillist_safe" placeholder="If set, ONLY these emails will receive (newline / comma / semicolon)"></textarea>
      <div class="mini">If this field is filled, recipients not in this list will be skipped.</div>

      <div class="hint">
        ✅ This tool will:
        <ul style="margin:8px 0 0; padding:0 18px; color: rgba(255,255,255,.62)">
          <li>Clean & deduplicate recipients</li>
          <li>Filter invalid emails</li>
          <li>Show progress + logs</li>
        </ul>
      </div>

      <div class="actions">
        <button class="btn" type="submit" id="btnStart">🚀 Start Sending</button>
        <a class="btn secondary" href="/jobs?c={{campaign_id}}" style="text-decoration:none; display:inline-block;">📄 Jobs</a>
        <a class="btn secondary" href="/campaign/{{campaign_id}}/config" style="text-decoration:none; display:inline-block;">⚙️ Config</a>
      </div>

      <div class="foot">
        Tip: test first with 2–5 emails to confirm SMTP settings before sending large batches.
      </div>
    </div>
  </form>

  <div class="card" id="domainsCard" style="margin-top:14px">
    <h2>Domains stats</h2>
    <div class="muted">
      Shows how many emails will be sent to each <b>recipient domain</b> (based on current Recipients + Safe list for this campaign).
    </div>

    <div class="actions" style="margin-top:12px">
      <input id="domQ" placeholder="Search domain..." style="max-width:320px" />
      <button class="btn secondary" type="button" id="btnDomains">🌐 Refresh</button>
      <div class="mini" id="domStatus">—</div>
      <div class="mini" id="domLive">Live: —</div>
    </div>

    <div class="hint" style="margin-top:12px">
      <div class="mini"><b>Recipients:</b> <span id="domRecTotals">—</span></div>
      <div class="mini"><b>Safe list:</b> <span id="domSafeTotals">—</span></div>
      <div class="mini"><b>Live sending:</b> <span id="domJobTotals">—</span></div>
      <div class="mini"><b>Recipient filter:</b> <span id="domFilterTotals">—</span></div>
      <div class="mini">Live numbers come from the latest active Job for this campaign (running/backoff).</div>
    </div>

    <div style="overflow:auto; margin-top:12px">
      <table>
        <thead>
          <tr>
            <th>Recipient domain</th>
            <th>Planned</th>
            <th>Sent</th>
            <th>Failed</th>
            <th style="min-width:180px">Progress</th>
            <th>PMTA queued</th>
            <th>PMTA deferred</th>
            <th>PMTA active</th>
            <th>MX</th>
            <th>MX hosts</th>
            <th>Mail IP(s)</th>
            <th>Listed</th>
          </tr>
        </thead>
        <tbody id="domTblRec">
          <tr><td colspan="12" class="muted">Click “Refresh” to load domains stats.</td></tr>
        </tbody>
      </table>
    </div>

    <h2 style="margin-top:14px">Safe list domains</h2>
    <div style="overflow:auto; margin-top:12px">
      <table>
        <thead>
          <tr>
            <th>Safe domain</th>
            <th>Emails</th>
            <th>MX</th>
            <th>MX hosts</th>
            <th>Mail IP(s)</th>
            <th>Listed</th>
          </tr>
        </thead>
        <tbody id="domTblSafe">
          <tr><td colspan="6" class="muted">—</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<div class="toast-wrap" id="toastWrap"></div>

<script>
  function q(name){ return document.querySelector(`[name="${name}"]`); }

  // -------------------------
  // Persist form values (SQLite via server API)
  // -------------------------

  const CAMPAIGN_ID = "{{campaign_id}}";
  let __sendSubmitting = false;  // prevent double-submit while a job is being created

  async function apiGetForm(){
    try{
      const r = await fetch(`/api/campaign/${CAMPAIGN_ID}/form`);
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && j.ok && j.data && typeof j.data === 'object'){
        return j.data;
      }
    }catch(e){ /* ignore */ }
    return {};
  }

  async function apiSaveForm(data){
    try{
      await fetch(`/api/campaign/${CAMPAIGN_ID}/form`, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({data: data || {}})
      });
    }catch(e){ /* ignore */ }
  }

  async function apiClearForm(scope){
    try{
      await fetch(`/api/campaign/${CAMPAIGN_ID}/clear`, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({scope: scope || 'mine'})
      });
    }catch(e){ /* ignore */ }
  }

  function formFields(){
    return document.querySelectorAll('#mainForm input, #mainForm textarea, #mainForm select');
  }

  async function loadSavedForm(){
    const data = await apiGetForm();
    for(const [k,v] of Object.entries(data || {})){
      const el = q(k);
      if(!el) continue;
      if(el.type === 'file') continue;
      if(el.type === 'checkbox'){
        el.checked = !!v;
      }else{
        el.value = (v ?? '').toString();
      }
    }
  }

  async function saveFormNow(){
    const data = {};
    const rememberPass = document.getElementById('remember_pass')?.checked;

    formFields().forEach(el => {
      const name = el.name;
      if(!name) return;
      if(el.type === 'file') return;

      if(el.type === 'password'){
        // Only store secrets if user explicitly opts in.
        if(name === 'smtp_pass'){
          data[name] = rememberPass ? (el.value || '') : '';
          return;
        }
        if(name === 'ai_token'){
          const rememberAi = document.getElementById('remember_ai')?.checked;
          data[name] = rememberAi ? (el.value || '') : '';
          return;
        }
        data[name] = '';
        return;
      }

      if(el.type === 'checkbox'){
        data[name] = !!el.checked;
        return;
      }

      data[name] = (el.value ?? '').toString();
    });

    data.__ts = Date.now();
    await apiSaveForm(data);
  }

  let _saveTimer = null;
  function scheduleSave(){
    if(_saveTimer) clearTimeout(_saveTimer);
    _saveTimer = setTimeout(() => { saveFormNow(); }, 250);
  }

  function escHtml(s){
    return (s ?? '').toString()
      .replaceAll('&','&amp;')
      .replaceAll('<','&lt;')
      .replaceAll('>','&gt;')
      .replaceAll('"','&quot;')
      .replaceAll("'",'&#39;');
  }

  function toast(title, msg, kind){
    const wrap = document.getElementById('toastWrap');
    const div = document.createElement('div');
    div.className = `toast ${kind || 'warn'}`;
    const safeTitle = escHtml(title);
    const safeMsg = escHtml(msg).split(/\r?\n/).join("<br>");
    div.innerHTML = `<div class="t">${safeTitle}</div><div>${safeMsg}</div>`;
    wrap.appendChild(div);
    setTimeout(() => {
      div.style.opacity = '0';
      div.style.transform = 'translateY(6px)';
      div.style.transition = 'all .22s ease';
      setTimeout(()=>div.remove(), 260);
    }, 3600);
  }

  function setInline(html, kind){
    const box = document.getElementById('smtpTestInline');
    box.classList.add('show');
    box.style.borderColor = kind === 'good' ? 'rgba(53,228,154,.35)' : (kind === 'bad' ? 'rgba(255,94,115,.35)' : 'rgba(255,193,77,.35)');
    box.innerHTML = html;
  }

  async function doSmtpTest(){
    const btn = document.getElementById('btnTest');
    btn.disabled = true;

    const payload = {
      smtp_host: (q('smtp_host')?.value || '').trim(),
      smtp_port: (q('smtp_port')?.value || '').trim(),
      smtp_security: (q('smtp_security')?.value || 'none').trim(),
      smtp_timeout: (q('smtp_timeout')?.value || '25').trim(),
      smtp_user: (q('smtp_user')?.value || '').trim(),
      smtp_pass: (q('smtp_pass')?.value || '').trim(),
    };

    if(!payload.smtp_host || !payload.smtp_port){
      toast('SMTP Test', 'Please enter Host and Port first.', 'warn');
      setInline('<b>SMTP Test:</b> Please enter Host and Port first.', 'warn');
      btn.disabled = false;
      return;
    }

    toast('SMTP Test', 'Testing connection...', 'warn');
    setInline('<b>SMTP Test:</b> Testing connection...', 'warn');

    try{
      const r = await fetch('/api/smtp_test', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(payload)
      });
      const j = await r.json().catch(()=>({}));

      if(r.ok && j.ok){
        toast('✅ SMTP OK', j.detail || 'Connection successful', 'good');
        setInline(`<b>SMTP OK</b><br>• ${j.detail || ''}<br>• Time: <b>${j.time_ms || 0}ms</b>`, 'good');
      } else {
        const msg = (j && (j.detail || j.error)) ? (j.detail || j.error) : `HTTP ${r.status}`;
        toast('❌ SMTP Failed', msg, 'bad');
        setInline(`<b>SMTP Failed</b><br>• ${msg}`, 'bad');
      }

    }catch(e){
      toast('❌ SMTP Failed', e?.toString?.() || 'Unknown error', 'bad');
      setInline(`<b>SMTP Failed</b><br>• ${(e?.toString?.() || 'Unknown error')}`, 'bad');
    }finally{
      btn.disabled = false;
    }
  }

  document.getElementById('btnTest').addEventListener('click', doSmtpTest);

  async function doAiRewrite(){
    const btn = document.getElementById('btnAiRewrite');
    if(btn) btn.disabled = true;

    const token = (q('ai_token')?.value || '').trim();

    if(!token){
      toast('AI rewrite', 'Please paste your OpenRouter token first.', 'warn');
      if(btn) btn.disabled = false;
      return;
    }

    const subjText = (q('subject')?.value || '');
    const body = (q('body')?.value || '');
    const body_format = (q('body_format')?.value || 'text');

    toast('AI rewrite', 'Rewriting subject/body...', 'warn');

    try{
      const r = await fetch('/api/ai_rewrite', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({
          token,
          subjects: subjText.split('\n').map(x=>x.trim()).filter(Boolean),
          body,
          body_format
        })
      });
      const j = await r.json().catch(()=>({}));
      if(r.ok && j.ok){
        const subjEl = q('subject');
        const bodyEl = q('body');

        // Subjects: accept array or string, sanitize, fallback to current text
        const subjArr = Array.isArray(j.subjects)
          ? j.subjects
          : (typeof j.subjects === 'string' ? [j.subjects] : []);

        const cleaned = subjArr
          .map(x => (x ?? '').toString().trim())
          .filter(x => x && !['undefined','null','none'].includes(x.toLowerCase()));

        if(subjEl){
          if(cleaned.length){
            subjEl.value = cleaned.join('\n');
          } else {
            // keep existing subject if AI didn't return subjects
            subjEl.value = subjText;
          }
        }

        if(bodyEl && typeof j.body === 'string'){
          bodyEl.value = j.body;
        }

        scheduleSave();
        toast('✅ AI rewrite', 'Updated Subject + Body. Review, then send.', 'good');
      } else {
        const msg = (j && (j.error || j.detail)) ? (j.error || j.detail) : ('HTTP ' + r.status);
        toast('❌ AI rewrite failed', msg, 'bad');
      }
    }catch(e){
      toast('❌ AI rewrite failed', (e?.toString?.() || 'Unknown error'), 'bad');
    }finally{
      if(btn) btn.disabled = false;
    }
  }

  const _aiBtn = document.getElementById('btnAiRewrite');
  if(_aiBtn){ _aiBtn.addEventListener('click', doAiRewrite); }

  async function doPreflight(){
    const btn = document.getElementById('btnPreflight');
    if(btn) btn.disabled = true;

    const payload = {
      smtp_host: (q('smtp_host')?.value || '').trim(),
      from_email: (q('from_email')?.value || ''),
      subject: (q('subject')?.value || ''),
      body_format: (q('body_format')?.value || 'text'),
      body: (q('body')?.value || ''),
      spam_limit: (q('score_range')?.value || '4')
    };

    toast('Preflight', 'Checking spam score + blacklist...', 'warn');

    try{
      const r = await fetch('/api/preflight', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(payload)
      });
      const j = await r.json().catch(()=>({}));

      const spamEl = document.getElementById('pfSpam');
      const spamMore = document.getElementById('pfSpamMore');
      const blEl = document.getElementById('pfBl');
      const blMore = document.getElementById('pfBlMore');

      if(!spamEl || !blEl){
        toast('Preflight UI error', 'Missing elements: pfSpam/pfBl. Please refresh the page.', 'bad');
        return;
      }

      if(r.ok && j.ok){
        // spam
        if(j.spam_score !== null && j.spam_score !== undefined){
          const s = Number(j.spam_score);
          const lim = Number(j.spam_threshold);
          spamEl.textContent = s.toFixed(2) + ' (limit ' + lim.toFixed(1) + ')';
          spamEl.style.color = (s <= lim) ? 'var(--good)' : 'var(--bad)';
        }else{
          spamEl.textContent = 'unavailable';
          spamEl.style.color = 'var(--warn)';
        }

        if(j.spam_backend){
          spamMore.style.display = 'block';
          spamMore.textContent = 'Backend: ' + j.spam_backend;
        }else{
          spamMore.style.display = 'none';
        }

        // blacklist summary
        const ipListings = j.ip_listings || {};
        const domListings = j.domain_listings || [];

        // IPs from SMTP host
        const listedIpLines = [];
        for(const [ip, arr] of Object.entries(ipListings)){
          if(arr && arr.length){
            listedIpLines.push(ip + ': ' + arr.map(x=>x.zone).join(', '));
          }
        }

        // Domain DBL (domain-level)
        const domZones = (domListings || []).map(x=>x.zone).filter(Boolean);

        // NEW: Sender domains -> resolve IPs -> check IP DNSBL
        const senderDomainIps = j.sender_domain_ips || {};
        const senderDomainIpListings = j.sender_domain_ip_listings || {};
        const senderDomainDblListings = j.sender_domain_dbl_listings || {};
        const senderDomainSpamScores = j.sender_domain_spam_scores || {};
        const senderDomainSpamBackends = j.sender_domain_spam_backends || {};

        // DBL listings for ALL sender domains
        const senderDblListedLines = [];
        for(const [dom, arr] of Object.entries(senderDomainDblListings)){
          if(arr && arr.length){
            const zones = arr.map(x => (x && x.zone) ? x.zone : '').filter(Boolean);
            if(zones.length){
              senderDblListedLines.push(dom + ': ' + zones.join(', '));
            } else {
              senderDblListedLines.push(dom + ': listed');
            }
          }
        }

        const senderListedLines = [];
        const senderAllLines = [];

        for(const [dom, ips] of Object.entries(senderDomainIps)){
          const ipArr = Array.isArray(ips) ? ips : [];
          if(ipArr.length){
            senderAllLines.push(dom + ' => ' + ipArr.join(', '));
          }
        }

        for(const [dom, ipmap] of Object.entries(senderDomainIpListings)){
          const m = ipmap || {};
          for(const [ip, arr] of Object.entries(m)){
            if(arr && arr.length){
              senderListedLines.push(dom + ' / ' + ip + ': ' + arr.map(x=>x.zone).join(', '));
            }
          }
        }

        // Render table: all sender domains -> resolved IPs -> blacklist status + spam score
        const tb = document.getElementById('pfDomains');
        let anyDomainSpamHigh = false;

        if(tb){
          const domains = Array.isArray(j.sender_domains) ? j.sender_domains : [];
          if(!domains.length){
            tb.innerHTML = `<tr><td colspan="4" class="muted" style="padding:6px">No sender domains found.</td></tr>`;
          } else {
            const rows = [];
            for(const dom of domains){
              const ips = Array.isArray(senderDomainIps[dom]) ? senderDomainIps[dom] : [];
              const ipMap = senderDomainIpListings[dom] || {};
              const dblArr = Array.isArray(senderDomainDblListings[dom]) ? senderDomainDblListings[dom] : [];

              // Blacklist status (Listed/Not listed/Unknown)
              let listed = false;
              if(dblArr && dblArr.length){
                listed = true;
              }
              for(const [ip, arr] of Object.entries(ipMap)){
                if(arr && arr.length){
                  listed = true;
                }
              }

              const status = listed ? 'Listed' : (ips.length ? 'Not listed' : 'Unknown');
              const color = listed ? 'var(--bad)' : (ips.length ? 'var(--good)' : 'var(--warn)');
              const ipText = ips.length ? ips.join(', ') : '—';

              // Spam score per domain
              const scRaw = senderDomainSpamScores[dom];
              let spamText = '—';
              let spamColor = 'var(--warn)';
              if(scRaw !== null && scRaw !== undefined && scRaw !== ''){
                const sc = Number(scRaw);
                const lim = Number(j.spam_threshold);
                if(!Number.isNaN(sc)){
                  spamText = sc.toFixed(2);
                  spamColor = (sc <= lim) ? 'var(--good)' : 'var(--bad)';
                  if(sc > lim) anyDomainSpamHigh = true;
                }
              }

              rows.push(
                `<tr>`+
                  `<td style="padding:6px; border-bottom:1px solid rgba(255,255,255,.10)">${escHtml(dom)}</td>`+
                  `<td style="padding:6px; border-bottom:1px solid rgba(255,255,255,.10)">${escHtml(ipText)}</td>`+
                  `<td style="padding:6px; border-bottom:1px solid rgba(255,255,255,.10); color:${color}; font-weight:800">${escHtml(status)}</td>`+
                  `<td style="padding:6px; border-bottom:1px solid rgba(255,255,255,.10); color:${spamColor}; font-weight:800">${escHtml(spamText)}</td>`+
                `</tr>`
              );
            }
            tb.innerHTML = rows.join('');
          }
        }

        const anyListed = (listedIpLines.length > 0) || (domZones.length > 0) || (senderListedLines.length > 0) || (senderDblListedLines.length > 0);

        if(!anyListed){
          blEl.textContent = 'Not listed';
          blEl.style.color = 'var(--good)';
          // Still show resolved domain IPs if available
          if(senderAllLines.length){
            blMore.style.display = 'block';
            blMore.textContent = 'Resolved sender domain IPs: ' + senderAllLines.join(' | ');
          } else {
            blMore.style.display = 'none';
          }
        } else {
          blEl.textContent = 'Listed';
          blEl.style.color = 'var(--bad)';
          const parts = [];
          if(listedIpLines.length){ parts.push('SMTP Host IP: ' + listedIpLines.join(' | ')); }
          if(domZones.length){ parts.push('Sender Domain (DBL): ' + domZones.join(', ')); }
          if(senderDblListedLines.length){ parts.push('All sender domains (DBL): ' + senderDblListedLines.join(' | ')); }
          if(senderListedLines.length){ parts.push('Sender Domain IP (DNSBL): ' + senderListedLines.join(' | ')); }
          if(!senderListedLines.length && senderAllLines.length){ parts.push('Resolved sender domain IPs: ' + senderAllLines.join(' | ')); }
          blMore.style.display = 'block';
          blMore.textContent = parts.join(' · ');
        }

        // toast
        const warn = (j.spam_score !== null && j.spam_score !== undefined && Number(j.spam_score) > Number(j.spam_threshold))
          || anyDomainSpamHigh
          || (listedIpLines.length > 0) || (domZones.length > 0) || (senderListedLines.length > 0) || (senderDblListedLines.length > 0);
        toast('Preflight done', warn ? 'Issues detected. See stats below.' : 'Looks good.', warn ? 'warn' : 'good');

      } else {
        const msg = (j && (j.error || j.detail)) ? (j.error || j.detail) : ('HTTP ' + r.status);
        toast('Preflight failed', msg, 'bad');
      }

    }catch(e){
      toast('Preflight failed', (e?.toString?.() || 'Unknown error'), 'bad');
    }finally{
      if(btn) btn.disabled = false;
    }
  }

  const _pf = document.getElementById('btnPreflight');
  if(_pf){ _pf.addEventListener('click', doPreflight); }

  // Load saved values on page open
  loadSavedForm().then(() => {
    // One quick save after initial load (helps keep DB in sync with defaults)
    setTimeout(()=>{ saveFormNow(); }, 200);
  });

  // Auto-save on change/input + AJAX submit (stay on page, show toast on errors)
  const form = document.getElementById('mainForm');
  if(form){
    form.addEventListener('input', scheduleSave);
    form.addEventListener('change', scheduleSave);

    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();

      // Hard guard: if we are already submitting, do NOTHING.
      if(__sendSubmitting){
        toast('Please wait', 'A send request is already in progress. Wait until the job is created.', 'warn');
        return;
      }

      const btn = document.getElementById('btnStart');
      __sendSubmitting = true;
      if(btn) btn.disabled = true;

      try{
        await saveFormNow();
        // Keep Domains stats in sync with freshly pasted/edited recipients before starting a new send.
        refreshDomainsStats();

        // If campaign already has jobs (stopped/running/etc), confirm with the user.
        let latest = null;
        try{
          const r0 = await fetch(`/api/campaign/${CAMPAIGN_ID}/latest_job`);
          const j0 = await r0.json().catch(()=>({}));
          if(r0.ok && j0 && j0.ok && j0.job){ latest = j0.job; }
        }catch(e){ /* ignore */ }

        let forceNew = false;
        if(latest){
          const st = (latest.status || '').toString().toLowerCase();
          const active = (st === 'queued' || st === 'running' || st === 'backoff' || st === 'paused');
          const msg = active
            ? (`This campaign already has a job in progress:
`+
               `- ID: ${latest.id}
`+
               `- Status: ${latest.status}

`+
               `Do you want another job?`)
            : (`This campaign already has job history (latest):
`+
               `- ID: ${latest.id}
`+
               `- Status: ${latest.status}

`+
               `Do you want to start a new job?`);

          const yes = confirm(msg);
          if(!yes){
            toast('Cancelled', 'Start sending cancelled.', 'warn');
            return;
          }
          if(active){ forceNew = true; }
        }

        // Start recipient pre-send filter before submitting.
        toast('Maillist filter', 'The filter started verifying addresses before sending....', 'warn');

        // Only NOW show submitting toast (and lock start button) — job creation in progress.
        toast('Sending', 'Submitting... please wait', 'warn');

        const fd = new FormData(form);
        // Mark as ajax so server-side can differentiate if needed.
        fd.append('_ajax', '1');
        if(forceNew){ fd.append('force_new_job', '1'); }

        const r = await fetch('/start', {
          method: 'POST',
          body: fd,
          headers: { 'X-Requested-With': 'fetch' }
        });

        const txt = await r.text();

        if(r.ok){
          // Success: /start redirects to /job/<id>. fetch follows redirects, so r.url becomes the job URL.
          if(r.url && r.url.includes('/job/')){
            window.location.href = r.url;
            return;
          }
          toast('✅ Started', 'Job started successfully.', 'good');
          return;
        }

        // If server blocked due to active job, show a clearer message.
        if(r.status === 409){
          toast('Blocked', txt || 'Active job already running. Please confirm to create another job.', 'warn');
        } else {
          // Error: show toast, stay on the form
          toast('❌ Blocked', txt || ('HTTP ' + r.status), 'bad');
        }

      }catch(e){
        toast('❌ Error', (e?.toString?.() || 'Unknown error'), 'bad');
      }finally{
        __sendSubmitting = false;
        if(btn) btn.disabled = false;
      }
    });
  }

  // Clear-saved button removed (campaign data is auto-saved in SQLite).

  // -------------------------
  // Domains stats (in-page) + LIVE progress overlay
  // -------------------------
  let _domCache = null;
  let _domLiveJob = null;
  let _domLiveTimer = null;

  function domStatusBadge(mx){
    if(mx === 'mx') return '<span style="color:var(--good); font-weight:800">MX</span>';
    if(mx === 'a_fallback') return '<span style="color:var(--warn); font-weight:800">A</span>';
    if(mx === 'none') return '<span style="color:var(--bad); font-weight:800">NONE</span>';
    return '<span style="color:var(--warn); font-weight:800">UNKNOWN</span>';
  }

  function domListedBadge(v){
    return v ? '<span style="color:var(--bad); font-weight:800">Listed</span>' : '<span style="color:var(--good); font-weight:800">Not listed</span>';
  }

  function domProgressBar(pct){
    const w = Math.max(0, Math.min(100, Number(pct||0)));
    return `<div class="smallBar"><div style="width:${w}%"></div></div>`;
  }

  function renderDomainsTables(){
    const qv = (document.getElementById('domQ')?.value || '').trim().toLowerCase();
    const recBody = document.getElementById('domTblRec');
    const safeBody = document.getElementById('domTblSafe');
    const recTotals = document.getElementById('domRecTotals');
    const safeTotals = document.getElementById('domSafeTotals');

    const jobTotals = document.getElementById('domJobTotals');
    const filterTotals = document.getElementById('domFilterTotals');

    if(!_domCache || !_domCache.ok){
      if(recBody) recBody.innerHTML = `<tr><td colspan="9" class="muted">No data yet. Click “Refresh”.</td></tr>`;
      if(safeBody) safeBody.innerHTML = `<tr><td colspan="6" class="muted">—</td></tr>`;
      if(recTotals) recTotals.textContent = '—';
      if(safeTotals) safeTotals.textContent = '—';
      if(jobTotals) jobTotals.textContent = '—';
      if(filterTotals) filterTotals.textContent = '—';
      return;
    }

    const rec = _domCache.recipients || {};
    const safe = _domCache.safe || {};

    if(recTotals){
      recTotals.textContent = `${rec.total_emails || 0} emails · ${rec.unique_domains || 0} domains · invalid=${rec.invalid_emails || 0}`;
    }
    if(safeTotals){
      safeTotals.textContent = `${safe.total_emails || 0} emails · ${safe.unique_domains || 0} domains · invalid=${safe.invalid_emails || 0}`;
    }

    const filter = rec.filter || {};
    if(filterTotals){
      const checks = Array.isArray(filter.checks) ? filter.checks.join('+') : 'syntax+mx';
      filterTotals.textContent = `kept=${filter.kept || 0} · dropped=${filter.dropped || 0} · smtp_probe=${filter.smtp_probe_used || 0}/${filter.smtp_probe_limit || 0} · checks=${checks}`;
    }

    const live = (_domLiveJob && _domLiveJob.ok && _domLiveJob.job) ? _domLiveJob.job : null;
    const planMap = live ? (live.domain_plan || {}) : {};
    const sentMap = live ? (live.domain_sent || {}) : {};
    const failMap = live ? (live.domain_failed || {}) : {};

    const pmtaDom = live ? (live.pmta_domains || {}) : {};
    const pmtaOk = !!pmtaDom.ok;
    const pmtaMap = pmtaDom.domains || {};

    if(jobTotals){
      if(live){
        jobTotals.textContent = `Job ${live.id} · status=${live.status} · sent=${live.sent}/${live.total} · failed=${live.failed} · skipped=${live.skipped}`;
      } else {
        jobTotals.textContent = '—';
      }
    }

    function rows(items){
      const arr = Array.isArray(items) ? items : [];
      const out = [];
      for(const it of arr){
        const dom = (it.domain || '').toString();
        if(qv && !dom.toLowerCase().includes(qv)) continue;

        const mxHosts = (it.mx_hosts || []).slice(0,4).join(', ');
        const ips = (it.mail_ips || []).join(', ');

        const planned = (live && (dom in planMap)) ? Number(planMap[dom]||0) : Number(it.count || 0);
        const sent = live ? Number(sentMap[dom]||0) : 0;
        const failed = live ? Number(failMap[dom]||0) : 0;
        const done = sent + failed;
        const pct = planned ? Math.min(100, Math.round((done/planned)*100)) : 0;

        out.push(
          `<tr>`+
            `<td><code>${escHtml(dom)}</code></td>`+
            `<td style="font-weight:800">${planned}</td>`+
            `<td style="font-weight:800; color:var(--good)">${sent}</td>`+
            `<td style="font-weight:800; color:var(--bad)">${failed}</td>`+
            `<td>${domProgressBar(pct)}<div class="muted" style="font-size:12px; margin-top:4px">${done}/${planned} (${pct}%)</div></td>`+
            `<td style="font-weight:800">${(pmtaOk && pmtaMap[dom]) ? (pmtaMap[dom].queued ?? '—') : '—'}</td>`+
            `<td style="font-weight:800">${(pmtaOk && pmtaMap[dom]) ? (pmtaMap[dom].deferred ?? '—') : '—'}</td>`+
            `<td style="font-weight:800">${(pmtaOk && pmtaMap[dom]) ? (pmtaMap[dom].active ?? '—') : '—'}</td>`+
            `<td>${domStatusBadge(it.mx_status)}</td>`+
            `<td class="muted">${escHtml(mxHosts || '—')}</td>`+
            `<td class="muted">${escHtml(ips || '—')}</td>`+
            `<td>${domListedBadge(!!it.any_listed)}</td>`+
          `</tr>`
        );
      }
      return out.join('') || `<tr><td colspan="12" class="muted">No results.</td></tr>`;
    }

    if(recBody) recBody.innerHTML = rows(rec.domains);

    // Safe table stays the same (planned only)
    function safeRows(items){
      const arr = Array.isArray(items) ? items : [];
      const out = [];
      for(const it of arr){
        const dom = (it.domain || '').toString();
        if(qv && !dom.toLowerCase().includes(qv)) continue;
        const mxHosts = (it.mx_hosts || []).slice(0,4).join(', ');
        const ips = (it.mail_ips || []).join(', ');
        out.push(
          `<tr>`+
            `<td><code>${escHtml(dom)}</code></td>`+
            `<td style="font-weight:800">${Number(it.count || 0)}</td>`+
            `<td>${domStatusBadge(it.mx_status)}</td>`+
            `<td class="muted">${escHtml(mxHosts || '—')}</td>`+
            `<td class="muted">${escHtml(ips || '—')}</td>`+
            `<td>${domListedBadge(!!it.any_listed)}</td>`+
          `</tr>`
        );
      }
      return out.join('') || `<tr><td colspan="6" class="muted">No results.</td></tr>`;
    }

    if(safeBody) safeBody.innerHTML = safeRows(safe.domains);
  }

  async function refreshDomainsStats(){
    const btn = document.getElementById('btnDomains');
    const status = document.getElementById('domStatus');

    if(btn) btn.disabled = true;
    if(status) status.textContent = 'Loading...';

    try{
      const r = await fetch(`/api/campaign/${CAMPAIGN_ID}/domains_stats`);
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && j.ok){
        _domCache = j;
        if(status) status.textContent = `OK · ${new Date().toLocaleTimeString()}`;
        renderDomainsTables();
        toast('Domains stats', 'Updated domains distribution (planned). Live progress updates automatically.', 'good');
      } else {
        const msg = (j && (j.error || j.detail)) ? (j.error || j.detail) : ('HTTP ' + r.status);
        if(status) status.textContent = 'Failed';
        toast('Domains stats failed', msg, 'bad');
      }
    }catch(e){
      if(status) status.textContent = 'Failed';
      toast('Domains stats failed', (e?.toString?.() || 'Unknown error'), 'bad');
    }finally{
      if(btn) btn.disabled = false;
    }
  }

  let _domAutoRefreshTimer = null;
  function scheduleDomainsAutoRefresh(delayMs = 550){
    if(_domAutoRefreshTimer) clearTimeout(_domAutoRefreshTimer);
    _domAutoRefreshTimer = setTimeout(() => {
      refreshDomainsStats();
    }, Math.max(150, Number(delayMs || 0)));
  }

  async function refreshDomainsLive(){
    const liveEl = document.getElementById('domLive');
    try{
      const r = await fetch(`/api/campaign/${CAMPAIGN_ID}/active_job`);
      const j = await r.json().catch(()=>({}));

      if(r.ok && j && j.ok && j.job){
        _domLiveJob = j;
        const job = j.job;
        if(liveEl) liveEl.textContent = `Live: ${job.status} · sent=${job.sent}/${job.total} · failed=${job.failed} · skipped=${job.skipped}`;
        renderDomainsTables();
      } else {
        _domLiveJob = null;
        if(liveEl) liveEl.textContent = 'Live: no active job';
        renderDomainsTables();
      }
    }catch(e){
      _domLiveJob = null;
      if(liveEl) liveEl.textContent = 'Live: unavailable';
    }
  }

  function startDomainsLivePolling(){
    if(_domLiveTimer) clearInterval(_domLiveTimer);
    _domLiveTimer = setInterval(refreshDomainsLive, 1200);
    refreshDomainsLive();
  }

  const domBtn = document.getElementById('btnDomains');
  if(domBtn){ domBtn.addEventListener('click', refreshDomainsStats); }
  const domQ = document.getElementById('domQ');
  if(domQ){ domQ.addEventListener('input', renderDomainsTables); }

  const recipientsEl = q('recipients');
  const safeListEl = q('maillist_safe');
  const recipientsFileEl = q('recipients_file');
  [recipientsEl, safeListEl].forEach((el) => {
    if(!el) return;
    el.addEventListener('input', () => scheduleDomainsAutoRefresh(650));
    el.addEventListener('paste', () => scheduleDomainsAutoRefresh(450));
    el.addEventListener('change', () => scheduleDomainsAutoRefresh(350));
  });
  if(recipientsFileEl){
    recipientsFileEl.addEventListener('change', () => scheduleDomainsAutoRefresh(350));
  }

  // auto-load planned stats once, then live poll will keep progress updated
  refreshDomainsStats();
  startDomainsLivePolling();

  // Range value UI
  const scoreEl = document.getElementById('score_range');
  const scoreVal = document.getElementById('score_range_val');
  if(scoreEl && scoreVal){
    const sync = () => { scoreVal.textContent = Number(scoreEl.value).toFixed(1); };
    sync();
    scoreEl.addEventListener('input', sync);
  }
</script>
</body>
</html>
"""

PAGE_JOBS = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Jobs</title>
  <style>
    :root{
      --bg:#0b1020;
      --card: rgba(255,255,255,.06);
      --card2: rgba(255,255,255,.04);
      --border: rgba(255,255,255,.14);
      --text:#fff;
      --muted: rgba(255,255,255,.65);
      --accent:#7aa7ff;
      --good:#35e49a;
      --bad:#ff5e73;
      --warn:#ffc14d;
      --shadow: 0 18px 55px rgba(0,0,0,.35);
      --radius: 16px;
    }
    *{box-sizing:border-box}
    body{font-family:system-ui; margin:0; background:var(--bg); color: var(--text); padding:18px 14px;}
    a{color:var(--accent); text-decoration:none}

    .wrap{max-width: 1200px; margin: 0 auto;}

    .top{display:flex; gap:12px; flex-wrap:wrap; align-items:flex-start; justify-content:space-between; margin-bottom:12px;}
    h2{margin:0; font-size: 20px;}
    .sub{margin-top:6px; color:var(--muted); font-size:12px; line-height:1.6; max-width: 760px;}

    .nav{display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-top:8px}
    .nav form{display:inline; margin:0;}

    .btn{
      border:1px solid rgba(255,255,255,.14);
      background: rgba(122,167,255,.14);
      color: rgba(255,255,255,.92);
      padding:10px 12px;
      border-radius: 14px;
      cursor:pointer;
      font: inherit;
      font-weight: 800;
      display:inline-flex;
      align-items:center;
      gap:8px;
      text-decoration:none;
    }
    .btn:hover{filter:brightness(1.06)}
    .btn.secondary{background: rgba(255,255,255,.06); font-weight:700;}
    .btn.danger{background: rgba(255,94,115,.14);}
    .btn:disabled{opacity:.55; cursor:not-allowed;}

    .job{
      background: linear-gradient(180deg, var(--card), var(--card2));
      border:1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 14px;
      margin-bottom: 12px;
      backdrop-filter: blur(10px);
    }

    .jobTop{display:flex; gap:12px; flex-wrap:wrap; align-items:flex-start; justify-content:space-between;}
    .titleRow{display:flex; gap:10px; flex-wrap:wrap; align-items:center}
    .mini{color:var(--muted); font-size:12px; line-height:1.55}
    code{background:rgba(255,255,255,.08); padding:2px 6px; border-radius:8px;}

    .pill{padding:6px 10px; border-radius:999px; border:1px solid rgba(255,255,255,.14); background:rgba(255,255,255,.06); font-size:12px;}
    .pill.good{border-color: rgba(53,228,154,.35); color: var(--good); font-weight:900}
    .pill.bad{border-color: rgba(255,94,115,.35); color: var(--bad); font-weight:900}
    .pill.warn{border-color: rgba(255,193,77,.35); color: var(--warn); font-weight:900}

    .grid{display:grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap:10px; margin-top:12px;}
    @media (max-width: 1050px){ .grid{grid-template-columns: 1fr 1fr;} }
    @media (max-width: 560px){ .grid{grid-template-columns: 1fr;} }

    .metric{border:1px solid rgba(255,255,255,.10); background: rgba(0,0,0,.10); border-radius: 14px; padding: 10px 12px;}
    .metric b{color: rgba(255,255,255,.92)}

    .bars{display:grid; grid-template-columns: 1fr; gap:10px; margin-top: 12px;}
    .barWrap{display:flex; gap:10px; flex-wrap:wrap; align-items:center; justify-content:space-between;}
    .bar{height: 10px; background: rgba(255,255,255,.10); border:1px solid rgba(255,255,255,.14); border-radius:999px; overflow:hidden; width:100%;}
    .bar > div{height:100%; width:0%; background: rgba(122,167,255,.65);} 

    .twoCol{display:grid; grid-template-columns: 1fr 1fr; gap:10px; margin-top:12px;}
    @media (max-width: 980px){ .twoCol{grid-template-columns: 1fr;} }
    .panel{border:1px solid rgba(255,255,255,.10); background: rgba(0,0,0,.10); border-radius: 14px; padding: 10px 12px;}
    .panel h4{margin:0 0 8px; font-size: 13px; color: rgba(255,255,255,.86)}
    .headingRow{display:inline-flex; align-items:center; gap:8px; flex-wrap:wrap;}
    .liveStatus{display:inline-flex; align-items:center; gap:6px; font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:.45px;}
    .liveDot{width:9px; height:9px; border-radius:999px; display:inline-block; background:rgba(255,255,255,.45); box-shadow:0 0 0 1px rgba(255,255,255,.20) inset;}
    .liveStatus.good{color: var(--good);}
    .liveStatus.good .liveDot{background: var(--good); box-shadow:0 0 10px rgba(53,228,154,.45);}
    .liveStatus.bad{color: var(--bad);}
    .liveStatus.bad .liveDot{background: var(--bad); box-shadow:0 0 10px rgba(255,94,115,.45);}

    /* PMTA Live Panel (Jobs) — clearer layout */
    .pmtaLive{ margin-top:10px; }
    .pmtaGrid{ display:grid; grid-template-columns: repeat(7, minmax(0,1fr)); gap:10px; }
    @media (max-width: 1150px){ .pmtaGrid{ grid-template-columns: repeat(4, minmax(0,1fr)); } }
    @media (max-width: 820px){ .pmtaGrid{ grid-template-columns: repeat(2, minmax(0,1fr)); } }

    .pmtaBox{
      border:1px solid rgba(255,255,255,.12);
      background: rgba(0,0,0,.14);
      border-radius: 14px;
      padding: 10px 12px;
      min-height: 74px;
    }
    .pmtaTitle{
      font-size: 11px;
      letter-spacing: .6px;
      text-transform: uppercase;
      color: rgba(255,255,255,.60);
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      margin-bottom: 8px;
      user-select:none;
    }
    .pmtaTitle .tag{font-size:11px; padding:2px 8px; border-radius:999px; border:1px solid rgba(255,255,255,.14); background: rgba(255,255,255,.06);}
    .pmtaTitle .tag.good{ border-color: rgba(53,228,154,.35); color: var(--good); font-weight:900; }
    .pmtaTitle .tag.warn{ border-color: rgba(255,193,77,.35); color: var(--warn); font-weight:900; }
    .pmtaTitle .tag.bad{ border-color: rgba(255,94,115,.35); color: var(--bad); font-weight:900; }

    .pmtaRow{ display:flex; align-items:center; justify-content:space-between; gap:10px; margin-top:6px; }
    .pmtaKey{ font-size: 11px; color: rgba(255,255,255,.60); letter-spacing:.4px; text-transform:uppercase; }
    .pmtaVal{
      font-size: 16px;
      font-weight: 950;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      color: rgba(255,255,255,.92);
    }
    .pmtaVal.good{ color: var(--good); }
    .pmtaVal.warn{ color: var(--warn); }
    .pmtaVal.bad{ color: var(--bad); }
    .pmtaBig{ font-size: 22px; font-weight: 1000; letter-spacing: .2px; }
    .pmtaSub{ margin-top:8px; font-size: 11px; color: rgba(255,255,255,.60); line-height: 1.35; word-break: break-word; overflow-wrap:anywhere; }

    .pmtaBanner{
      border:1px solid rgba(255,255,255,.14);
      border-radius: 14px;
      padding: 10px 12px;
      background: rgba(0,0,0,.16);
      color: rgba(255,255,255,.90);
      font-weight: 800;
      line-height: 1.5;
    }
    .pmtaBanner.good{ border-color: rgba(53,228,154,.35); }
    .pmtaBanner.warn{ border-color: rgba(255,193,77,.35); }
    .pmtaBanner.bad{ border-color: rgba(255,94,115,.35); }

    details.more{margin-top:10px;}
    details.more summary{cursor:pointer; color: rgba(255,255,255,.86); font-weight:900;}

    .moreGrid{display:grid; grid-template-columns: 1.1fr .9fr; gap:10px; margin-top:10px;}
    @media (max-width: 980px){ .moreGrid{grid-template-columns: 1fr;} }

    .smallBar{height:8px; border-radius:999px; background:rgba(255,255,255,.10); border:1px solid rgba(255,255,255,.12); overflow:hidden}
    .smallBar > div{height:100%; width:0%; background: rgba(53,228,154,.55);} 

    .outcomesWrap{
      margin-top:8px;
      padding:10px;
      border:1px solid rgba(255,255,255,.10);
      border-radius:12px;
      background: rgba(255,255,255,.03);
    }
    .outcomesGrid{
      display:grid;
      grid-template-columns: repeat(2, minmax(0,1fr));
      gap:8px;
    }
    .outChip{
      border:1px solid rgba(255,255,255,.10);
      border-radius:10px;
      padding:8px 10px;
      background: rgba(0,0,0,.16);
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:8px;
    }
    .outChip .k{font-size:11px; letter-spacing:.5px; text-transform:uppercase; color:rgba(255,255,255,.62);}
    .outChip .v{font-weight:900; font-size:15px;}
    .outChip.del .v{color: var(--good);}
    .outChip.bnc .v{color: var(--bad);}
    .outChip.def .v{color: var(--warn);}
    .outChip.cmp .v{color: #ff8bd6;}
    .outTrend{
      margin-top:10px;
      padding:10px;
      border:1px dashed rgba(255,255,255,.14);
      border-radius:10px;
      background: linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.01));
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size:12px;
      line-height:1.5;
      color: rgba(255,255,255,.84);
      overflow-wrap:anywhere;
      word-break:break-word;
    }
    .trendHead{ color: rgba(255,255,255,.66); margin-right:8px; font-weight:800; }
    .trendSeg{ display:inline-flex; align-items:center; gap:6px; margin:2px 8px 2px 0; }
    .trendSeg .lbl{ font-weight:900; letter-spacing:.5px; }
    .trendSeg .spark{ font-size:13px; }
    .trendSeg.del .lbl, .trendSeg.del .spark{ color: var(--good); }
    .trendSeg.bnc .lbl, .trendSeg.bnc .spark{ color: var(--bad); }
    .trendSeg.def .lbl, .trendSeg.def .spark{ color: var(--warn); }
    .trendSeg.cmp .lbl, .trendSeg.cmp .spark{ color: #ff8bd6; }
    .outMeta{ margin-top:8px; font-size:11px; color:rgba(255,255,255,.62); }
    @media (max-width: 560px){ .outcomesGrid{ grid-template-columns: 1fr; } }

    table{width:100%; border-collapse:collapse; font-size: 12px;}
    th,td{padding:8px; border-bottom:1px solid rgba(255,255,255,.10); text-align:left; vertical-align:top}

    .ok{color:var(--good); font-weight:900}
    .no{color:var(--bad); font-weight:900}

    /* Tooltip (same behavior as Config page) */
    .tip{display:inline-flex; align-items:center; justify-content:center; width:18px; height:18px; border-radius:999px;
      border:1px solid rgba(255,255,255,.18); background: rgba(0,0,0,.18); color: rgba(255,255,255,.86);
      font-size: 12px; cursor: help; position: relative; user-select:none}
    .tip:hover::after{
      content: attr(data-tip);
      position: absolute;
      left: 0;
      top: 24px;
      min-width: 240px;
      max-width: 460px;
      background: rgba(0,0,0,.72);
      border: 1px solid rgba(255,255,255,.18);
      box-shadow: 0 18px 55px rgba(0,0,0,.35);
      backdrop-filter: blur(10px);
      color: rgba(255,255,255,.92);
      padding: 10px 12px;
      border-radius: 14px;
      z-index: 999;
      white-space: normal;
      line-height: 1.45;
    }

    /* Toast */
    .toast-wrap{ position: fixed; right: 16px; bottom: 16px; z-index: 9999; display:flex; flex-direction:column; gap:10px; }
    .toast{
      min-width: 280px;
      max-width: 460px;
      background: rgba(0,0,0,.55);
      border: 1px solid rgba(255,255,255,.18);
      box-shadow: 0 18px 55px rgba(0,0,0,.35);
      backdrop-filter: blur(10px);
      border-radius: 14px;
      padding: 12px 14px;
      color: rgba(255,255,255,.92);
      font-size: 13px;
      line-height: 1.5;
      animation: pop .18s ease-out;
    }
    @keyframes pop{ from{ transform: translateY(6px); opacity: .2; } to{ transform: translateY(0); opacity: 1; } }
    .toast .t{font-weight:900; margin-bottom:4px}
    .toast.good{ border-color: rgba(53,228,154,.35); }
    .toast.bad{ border-color: rgba(255,94,115,.35); }
    .toast.warn{ border-color: rgba(255,193,77,.35); }
  </style>
</head>
<body>
  <div class="wrap">

    <div class="top">
      <div>
        <h2>Jobs</h2>
        <div class="sub">
          Live monitoring: summary, current chunk, backoff, progress bars, top domains, counters, error histogram, and chunk preflight history.
        </div>
        <div class="nav">
          {% if campaign_id %}
            <form method="get" action="/campaign/{{campaign_id}}">
              <button class="btn secondary" type="submit">← Back to Campaign</button>
            </form>
            <a class="btn secondary" href="/campaigns">📌 Campaigns</a>
          {% else %}
            <a class="btn secondary" href="/campaigns">← Campaigns</a>
          {% endif %}
        </div>
      </div>
      <div class="nav">
        <button class="btn secondary" type="button" id="btnRefreshAll">🔄 Refresh</button>
      </div>
    </div>

    {% for j in jobs %}
      <div class="job" data-jobid="{{j.id}}" data-created="{{j.created_at}}">
        <div class="jobTop">
          <div>
            <div class="titleRow">
              <div style="font-weight:900">Job <code>{{j.id}}</code></div>
              <div class="pill" data-k="status">{{j.status}}</div>
              <div class="pill" data-k="speed">0 epm <span class="tip" data-tip="Estimated send speed in emails per minute, based on recent throughput.">ⓘ</span></div>
              <div class="pill" data-k="eta">ETA — <span class="tip" data-tip="Estimated time remaining for this job using the current send rate.">ⓘ</span></div>
            </div>
            <div class="mini">Created: <span class="muted">{{j.created_at}}</span></div>
            <div class="mini" data-k="alerts">Alerts: — <span class="tip" data-tip="Live warning summary for backoff, abandoned chunks, high fail ratio, or near-threshold spam.">ⓘ</span></div>
          </div>

          <div class="nav" style="margin-top:0">
            <a class="btn secondary" href="/job/{{j.id}}">Open</a>
            <button class="btn secondary" type="button" data-action="pause">⏸ Pause</button>
            <button class="btn secondary" type="button" data-action="resume">▶ Resume</button>
            <button class="btn danger" type="button" data-action="stop">⛔ Stop</button>
            <button class="btn danger" type="button" data-action="delete">🗑 Delete</button>
          </div>
        </div>

        <!-- 1) Summary header metrics -->
        <div class="grid">
          <div class="metric"><b>Sent</b> <span class="tip" data-tip="Total messages accepted by the sender workflow out of the job target list.">ⓘ</span><div class="mini"><span data-k="sent">0</span> / <span data-k="total">0</span></div></div>
          <div class="metric"><b>Failed</b> <span class="tip" data-tip="Messages that failed with a hard or terminal send error.">ⓘ</span><div class="mini"><span data-k="failed">0</span></div></div>
          <div class="metric"><b>Skipped</b> <span class="tip" data-tip="Recipients skipped by safety checks, policies, or runtime routing decisions.">ⓘ</span><div class="mini"><span data-k="skipped">0</span></div></div>
          <div class="metric"><b>Invalid</b> <span class="tip" data-tip="Invalid recipients detected during sanitization/validation.">ⓘ</span><div class="mini"><span data-k="invalid">0</span></div></div>

          <div class="metric"><b>Delivered</b> <span class="tip" data-tip="PMTA accounting outcome: delivered to recipient MX.">ⓘ</span><div class="mini"><span data-k="delivered">0</span></div></div>
          <div class="metric"><b>Bounced</b> <span class="tip" data-tip="PMTA accounting outcome: hard bounce or blocked outcome.">ⓘ</span><div class="mini"><span data-k="bounced">0</span></div></div>
          <div class="metric"><b>Deferred</b> <span class="tip" data-tip="PMTA accounting outcome: temporary/4xx delay.">ⓘ</span><div class="mini"><span data-k="deferred">0</span></div></div>
          <div class="metric"><b>Complained</b> <span class="tip" data-tip="PMTA accounting outcome: complaint/FBL events.">ⓘ</span><div class="mini"><span data-k="complained">0</span></div></div>
        </div>

        <!-- 4) Progress bars -->
        <div class="bars">
          <div class="panel">
            <h4><span class="headingRow">Progress <span class="tip" data-tip="Live completion for recipients, chunks, and domains in this job.">ⓘ</span></span></h4>
            <div class="mini" data-k="progressText">—</div>
            <div class="bar"><div data-k="barSend"></div></div>
            <div class="mini" style="margin-top:8px" data-k="chunksText">—</div>
            <div class="bar"><div data-k="barChunks"></div></div>
            <div class="mini" style="margin-top:8px" data-k="domainsText">—</div>
            <div class="bar"><div data-k="barDomains"></div></div>
          </div>
        </div>

        <!-- 2) Current chunk + 3) backoff info -->
        <div class="twoCol">
          <div class="panel">
            <h4><span class="headingRow">Current chunk <span class="tip" data-tip="Current chunk id, size, and the active target domains being processed now.">ⓘ</span></span></h4>
            <div class="mini" data-k="chunkLine">—</div>
            <div class="mini" data-k="chunkDomains">—</div>
          </div>
          <div class="panel">
            <h4><span class="headingRow">Backoff <span class="tip" data-tip="Latest backoff state and throttle reason for the running job.">ⓘ</span></span></h4>
            <div class="mini" data-k="backoffLine">—</div>
          </div>
        </div>

        <div class="panel" style="margin-top:10px">
          <h4><span class="headingRow">PMTA Live Panel <span class="tip" data-tip="Real-time PMTA monitor snapshot for queue, traffic, and pressure signals.">ⓘ</span></span></h4>
          <div class="pmtaLive" data-k="pmtaLine">—</div>
          <div class="mini" style="margin-top:6px" data-k="pmtaNote">Note: <b>sent</b> = accepted by PMTA (client-side). Delivery may still be queued/deferred.</div>
          <div class="mini" style="margin-top:6px" data-k="pmtaDiag">Diag: —</div>
        </div>

        <details class="more">
          <summary>More details <span class="tip" data-tip="Expanded diagnostics, outcomes, and preflight history for the selected job.">ⓘ</span></summary>
          <div class="moreGrid">

            <!-- 5) Top domains -->
            <div class="panel">
              <h4><span class="headingRow">Top domains (Top 10) <span class="tip" data-tip="Most active domains in the plan with send/fail progress and PMTA domain overlays.">ⓘ</span></span></h4>
              <div class="mini" data-k="topDomains">—</div>
              <div class="mini" style="margin-top:10px"><b>Domain progress (bars)</b> <span class="tip" data-tip="Visual completion bars by top domain in the active plan.">ⓘ</span></div>
              <div data-k="topDomainsBars"></div>
            </div>

            <div class="panel">
              <h4>
                <span class="headingRow">
                  Quality + Errors
                  <span class="tip" data-tip="Quality counters and accounting error analytics for this job.">ⓘ</span>
                  <span class="liveStatus" data-k="monitorStatus"><span class="liveDot"></span>Disconnected</span>
                </span>
              </h4>

              <!-- 6) counters -->
              <div class="mini" data-k="counters">—</div>

              <div style="height:10px"></div>
              <div class="mini"><b>Outcomes (PMTA accounting)</b> <span class="tip" data-tip="Delivered / bounced / deferred / complained outcomes from PMTA accounting stream.">ⓘ</span></div>
              <div class="outcomesWrap" data-k="outcomes">—</div>
              <div class="outTrend" data-k="outcomeTrend">—</div>

              <div style="height:10px"></div>

              <!-- 7) error types -->
              <div class="mini"><b>Error types</b> <span class="tip" data-tip="Error categories and dominant SMTP signature extracted from recent failures.">ⓘ</span></div>
              <div class="mini" data-k="errorTypes">—</div>

              <div style="height:10px"></div>

              <div class="mini"><b>Last errors (last 10)</b> <span class="tip" data-tip="Most recent 10 accounting error lines (4XX/5XX only).">ⓘ</span></div>
              <div class="mini" data-k="lastErrors">—</div>
            </div>

          </div>

          <!-- 8) Preflight history per chunk -->
          <div class="panel" style="margin-top:10px">
            <h4><span class="headingRow">Chunk preflight history (last 12) <span class="tip" data-tip="Recent preflight checks, attempts, and retry decisions before sending each chunk.">ⓘ</span></span></h4>
            <div style="overflow:auto; margin-top:8px">
              <table>
                <thead>
                  <tr>
                    <th>Chunk</th>
                    <th>Status</th>
                    <th>Size</th>
                    <th>Spam</th>
                    <th>Blacklist</th>
                    <th>Attempt</th>
                    <th>Next retry</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody data-k="chunkHist"></tbody>
              </table>
            </div>
          </div>
        </details>

      </div>
    {% endfor %}

    {% if jobs|length == 0 %}
      <div class="job">
        <div class="mini">No jobs yet.</div>
      </div>
    {% endif %}

  </div>

  <div class="toast-wrap" id="toastWrap"></div>

<script>
  const esc = (s) => (s ?? '').toString().replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');

  function toast(title, msg, kind){
    const wrap = document.getElementById('toastWrap');
    const div = document.createElement('div');
    div.className = `toast ${kind || 'warn'}`;
    const safeMsg = esc(msg).split(/\r?\n/).join("<br>");
    div.innerHTML = `<div class="t">${esc(title)}</div><div>${safeMsg}</div>`;
    wrap.appendChild(div);
    setTimeout(() => {
      div.style.opacity = '0';
      div.style.transform = 'translateY(6px)';
      div.style.transition = 'all .22s ease';
      setTimeout(()=>div.remove(), 260);
    }, 3600);
  }

  function qk(root, key){
    return root.querySelector(`[data-k="${key}"]`);
  }

  function pct(n,d){
    const nn = Number(n||0), dd = Number(d||0);
    return dd ? Math.min(100, Math.round((nn/dd)*100)) : 0;
  }

  function fmtEta(sec){
    if(sec === null || sec === undefined) return 'ETA —';
    const s = Math.max(0, Number(sec||0));
    if(!isFinite(s)) return 'ETA —';
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const ss = Math.floor(s % 60);
    if(h > 0) return `ETA ${h}h ${m}m`;
    if(m > 0) return `ETA ${m}m ${ss}s`;
    return `ETA ${ss}s`;
  }

  function statusPillClass(st){
    const s = (st||'').toString().toLowerCase();
    if(s === 'done') return 'pill good';
    if(s === 'running') return 'pill good';
    if(s === 'paused') return 'pill warn';
    if(s === 'backoff') return 'pill warn';
    if(s === 'stopped') return 'pill warn';
    if(s === 'error') return 'pill bad';
    return 'pill';
  }

  const state = {
    lastStatus: {},
    lastBackoff: {},
    lastAbandoned: {},
    lastFailed: {},
    lastAdaptive: {},
    lastRoute: {},
    lastPmtaMonitor: {},
  };

  async function controlJob(jobId, action){
    const reason = action === 'stop' ? prompt('Stop reason (optional):') : '';
    try{
      const r = await fetch(`/api/job/${jobId}/control`, {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({action, reason: reason || ''})
      });
      const j = await r.json().catch(()=>({}));
      if(r.ok && j.ok){
        toast('Job control', `Job ${jobId}: ${action} OK`, 'good');
      }else{
        toast('Job control failed', (j && (j.error||j.detail)) ? (j.error||j.detail) : ('HTTP '+r.status), 'bad');
      }
    }catch(e){
      toast('Job control failed', e?.toString?.() || 'Unknown error', 'bad');
    }
  }

  async function deleteJob(jobId, card){
    const ok = confirm(`Delete job ${jobId}?
This will remove it from Jobs history.`);
    if(!ok) return;
    try{
      const r = await fetch(`/api/job/${jobId}/delete`, { method:'POST' });
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && j.ok){
        toast('Job deleted', `Job ${jobId} deleted.`, 'good');
        if(card) card.remove();
      }else{
        toast('Delete failed', (j && (j.error||j.detail)) ? (j.error||j.detail) : ('HTTP '+r.status), 'bad');
      }
    }catch(e){
      toast('Delete failed', e?.toString?.() || 'Unknown error', 'bad');
    }
  }

  function renderTopDomains(card, j){
    const plan = j.domain_plan || {};
    const sent = j.domain_sent || {};
    const failed = j.domain_failed || {};
    const currDom = j.current_chunk_domains || {};

    const pmtaDom = j.pmta_domains || {};
    const pmtaOk = !!pmtaDom.ok;
    const pmtaMap = pmtaDom.domains || {};
    const chunkStates = Array.isArray(j.chunk_states) ? j.chunk_states : [];
    const domainStateMap = new Map();
    for(const x of chunkStates){
      const rd = (x && x.receiver_domain ? x.receiver_domain : '').toString().trim().toLowerCase();
      if(!rd) continue;
      const st = (x && x.status ? x.status : '').toString().trim().toLowerCase();
      domainStateMap.set(rd, st);
    }

    const entries = Object.entries(plan).map(([dom, p]) => {
      const pp = Number(p||0);
      const ss = Number(sent[dom]||0);
      const ff = Number(failed[dom]||0);
      const done = ss + ff;
      return {dom, pp, ss, ff, done, pct: pct(done, pp), active: (dom in currDom)};
    }).sort((a,b)=>b.pp - a.pp).slice(0,10);

    const elLine = qk(card,'topDomains');
    const elBars = qk(card,'topDomainsBars');

    if(!entries.length){
      if(elLine) elLine.textContent = '—';
      if(elBars) elBars.innerHTML = '';
      return;
    }

    if(elLine){
      elLine.innerHTML = entries.map(x => {
        const flag = x.active ? ' 🔥' : '';
        const domKey = (x.dom || '').toString().trim().toLowerCase();
        const isBackoffActive = domainStateMap.get(domKey) === 'backoff' && x.done < x.pp;
        const backoffFlag = isBackoffActive ? ' <span class="no">(backoff)</span>' : '';
        const pm = pmtaMap[x.dom] || {};
        const q = (pm && pm.queued !== undefined && pm.queued !== null) ? pm.queued : '—';
        const d = (pm && pm.deferred !== undefined && pm.deferred !== null) ? pm.deferred : '—';
        const a = (pm && pm.active !== undefined && pm.active !== null) ? pm.active : '—';
        const pmInfo = (pmtaOk && (x.dom in pmtaMap)) ? ` · pmta(q=${q} def=${d} act=${a})` : '';
        return `${esc(x.dom)}${backoffFlag}: <span class="ok">${x.ss}</span>/<b>${x.pp}</b> (fail <span class="no">${x.ff}</span>)${flag}${pmInfo}`;
      }).join('<br>');
    }

    if(elBars){
      elBars.innerHTML = entries.map(x => {
        const domKey = (x.dom || '').toString().trim().toLowerCase();
        const isBackoffActive = domainStateMap.get(domKey) === 'backoff' && x.done < x.pp;
        const backoffFlag = isBackoffActive ? ' <span class="no">(backoff)</span>' : '';
        const bar = `<div class="smallBar"><div style="width:${x.pct}%"></div></div>`;
        return `<div style="margin-top:10px">`+
          `<div class="mini"><b>${esc(x.dom)}</b>${backoffFlag} · ${x.done}/${x.pp} (${x.pct}%)${x.active ? ' · active' : ''}</div>`+
          `${bar}`+
        `</div>`;
      }).join('');
    }
  }

  function renderErrorTypes(card, j){
    const ec = j.accounting_error_counts || {};
    const entries = Object.entries(ec).sort((a,b)=>Number(b[1]||0)-Number(a[1]||0));
    const el = qk(card,'errorTypes');
    if(!el){ return; }

    const labels = {
      accepted: '2XX accepted',
      temporary_error: '4XX temporary',
      blocked: '5XX blocked'
    };

    const rawErrors = Array.isArray(j.accounting_last_errors) ? j.accounting_last_errors : [];
    const onlyErrors = rawErrors.filter(x => (x && x.kind !== 'accepted'));

    function errorSignature(detail){
      const txt = (detail || '').toString();
      const m = txt.match(/\b([245]\.\d\.\d{1,3})\b(?:\s*\(([^)]+)\))?/i);
      if(m){
        const code = (m[1] || '').trim();
        const reason = (m[2] || '').trim();
        return reason ? `${code} (${reason})` : code;
      }
      const smtp = txt.match(/\b([245]\d\d)\b/);
      if(smtp) return smtp[1];
      return txt ? txt.slice(0, 120) : 'unknown';
    }

    const sigMap = new Map();
    for(const x of onlyErrors){
      const sig = errorSignature(x.detail);
      if(!sigMap.has(sig)) sigMap.set(sig, {count: 0, sample: x});
      const row = sigMap.get(sig);
      row.count += 1;
    }
    const topSig = Array.from(sigMap.entries()).sort((a,b)=>b[1].count-a[1].count)[0] || null;

    if(!entries.length && !topSig){
      el.textContent = '—';
    }else{
      const parts = [];
      if(topSig){
        const [sig, info] = topSig;
        parts.push(`Most common error: <b>${esc(sig)}</b> · <b>${Number(info.count||0)}</b>`);
        const sample = (info.sample && info.sample.detail) ? info.sample.detail : '';
        if(sample){
          parts.push(`Example: ${esc(sample)}`);
        }
      }
      if(entries.length){
        parts.push(entries.map(([k,v]) => `${esc(labels[k] || k)}: <b>${Number(v||0)}</b>`).join(' · '));
      }
      el.innerHTML = parts.join('<br>');
    }

    // last accounting errors (last 10) - errors only
    const re = onlyErrors.slice().reverse().slice(0,10);
    const el2 = qk(card,'lastErrors');
    if(el2){
      if(!re.length){ el2.textContent = '—'; }
      else{
        el2.innerHTML = re.map(x => {
          const kk = (x.kind === 'temporary_error') ? '4XX' : '5XX';
          return `• [${esc(kk)}] ${esc(x.email || '—')} — ${esc(x.detail || '')}`;
        }).join('<br>');
      }
    }
  }


  function renderChunkHist(card, j){
    const tb = qk(card,'chunkHist');
    if(!tb) return;
    const cs = (j.chunk_states || []).slice().reverse().slice(0,12);
    if(!cs.length){
      tb.innerHTML = `<tr><td colspan="8" class="mini">No chunk states yet.</td></tr>`;
      return;
    }
    tb.innerHTML = cs.map(x => {
      const next = x.next_retry_ts ? new Date(Number(x.next_retry_ts)*1000).toLocaleTimeString() : '';
      const bl = (x.blacklist || '').toString();
      const blShort = bl.length > 30 ? (bl.slice(0,30) + '…') : bl;
      const spam = (x.spam_score === null || x.spam_score === undefined) ? '' : Number(x.spam_score).toFixed(2);
      const reason = (x.reason || '').toString();
      const reasonShort = reason.length > 40 ? (reason.slice(0,40) + '…') : reason;

      return `<tr>`+
        `<td>${Number(x.chunk)+1}</td>`+
        `<td>${esc(x.status || '')}</td>`+
        `<td>${Number(x.size||0)}</td>`+
        `<td>${esc(spam)}</td>`+
        `<td title="${esc(bl)}">${esc(blShort)}</td>`+
        `<td>${esc(String(x.attempt ?? ''))}</td>`+
        `<td>${esc(next)}</td>`+
        `<td title="${esc(reason)}">${esc(reasonShort)}</td>`+
      `</tr>`;
    }).join('');
  }

  function updateCard(card, j){
    const jobId = card.dataset.jobid;
    const st = (j.status || '').toString();

    const chunkStates = Array.isArray(j.chunk_states) ? j.chunk_states : [];
    const latestChunkStatus = new Map();
    for(const x of chunkStates){
      const cidx = Number(x && x.chunk);
      if(Number.isFinite(cidx)) latestChunkStatus.set(cidx, (x.status || '').toString().toLowerCase());
    }
    const allChunksBackoff = latestChunkStatus.size > 0 && Array.from(latestChunkStatus.values()).every(s => s === 'backoff');
    const stShown = (st === 'running' && allChunksBackoff) ? 'backoff' : st;

    // Header pills
    const stEl = qk(card,'status');
    if(stEl){
      stEl.className = statusPillClass(stShown);
      stEl.textContent = `Status: ${stShown}`;
    }

    const speedEl = qk(card,'speed');
    const spm = Number(j.speed_epm || 0);
    if(speedEl){
      speedEl.className = 'pill';
      speedEl.textContent = `${Math.round(spm)} epm`;
    }

    const etaEl = qk(card,'eta');
    if(etaEl){
      etaEl.className = 'pill';
      etaEl.textContent = fmtEta(j.eta_s);
    }

    // Core counters
    qk(card,'total').textContent = j.total || 0;
    qk(card,'sent').textContent = j.sent || 0;
    qk(card,'failed').textContent = j.failed || 0;
    qk(card,'skipped').textContent = j.skipped || 0;
    qk(card,'invalid').textContent = j.invalid || 0;

    // Outcomes (PMTA accounting)
    const elDel = qk(card,'delivered'); if(elDel) elDel.textContent = j.delivered || 0;
    const elBnc = qk(card,'bounced'); if(elBnc) elBnc.textContent = j.bounced || 0;
    const elDef = qk(card,'deferred'); if(elDef) elDef.textContent = j.deferred || 0;
    const elCmp = qk(card,'complained'); if(elCmp) elCmp.textContent = j.complained || 0;

    // Progress bars
    const total = Number(j.total||0);
    const sent = Number(j.sent||0);
    const failed = Number(j.failed||0);
    const skipped = Number(j.skipped||0);
    const done = sent + failed + skipped;

    const pSend = pct(done, total);
    qk(card,'barSend').style.width = pSend + '%';
    qk(card,'progressText').textContent = `Send progress: ${pSend}% (${done}/${total})`; 

    const cd = Number(j.chunks_done||0);
    const ct = Number(j.chunks_total||0);
    const pChunks = pct(cd, ct);
    qk(card,'barChunks').style.width = pChunks + '%';
    qk(card,'chunksText').textContent = `Chunks: ${cd}/${ct} · backoff_events=${Number(j.chunks_backoff||0)} · abandoned=${Number(j.chunks_abandoned||0)}`;

    const plan = j.domain_plan || {};
    const planTotal = Object.values(plan).reduce((a,v)=>a+Number(v||0),0);
    const dSent = j.domain_sent || {};
    const dFail = j.domain_failed || {};
    const domDone = Object.keys(plan).reduce((a,dom)=>a+Number(dSent[dom]||0)+Number(dFail[dom]||0),0);
    const pDom = pct(domDone, planTotal);
    qk(card,'barDomains').style.width = pDom + '%';
    qk(card,'domainsText').textContent = `Domains: ${pDom}% (${domDone}/${planTotal})`; 

    // Current chunk info
    const ci = j.current_chunk_info || {};
    const cDom = j.current_chunk_domains || {};

    let chunkLine = '—';
    if(ci && (ci.chunk !== undefined) && (ci.chunk !== null) && Number(ci.size||0) > 0){
      const cnum = Number(ci.chunk||0) + 1;
      const at = Number(ci.attempt||0);
      const sender = (ci.sender||'').toString();
      const subj = (ci.subject||'').toString();
      const subjShort = subj.length > 70 ? (subj.slice(0,70) + '…') : subj;
      const spam = (ci.spam_score === null || ci.spam_score === undefined) ? '—' : Number(ci.spam_score).toFixed(2);
      const bl = (ci.blacklist || '').toString();
      const blShort = bl.length > 60 ? (bl.slice(0,60) + '…') : bl;
      const pmtaReason = (ci.pmta_reason || '').toString();
      const pmtaReasonShort = pmtaReason.length > 80 ? (pmtaReason.slice(0,80) + '…') : pmtaReason;
      let pmtaSlowShort = '';
      let adaptiveShort = '';
      try{
        const ps = ci.pmta_slow || {};
        const dmin = (ps.delay_min !== undefined && ps.delay_min !== null) ? Number(ps.delay_min) : null;
        const wmax = (ps.workers_max !== undefined && ps.workers_max !== null) ? Number(ps.workers_max) : null;
        if((dmin !== null && !Number.isNaN(dmin)) || (wmax !== null && !Number.isNaN(wmax))){
          const parts = [];
          if(dmin !== null && !Number.isNaN(dmin)) parts.push('delay≥' + dmin);
          if(wmax !== null && !Number.isNaN(wmax)) parts.push('workers≤' + wmax);
          pmtaSlowShort = parts.join(', ');
        }
      }catch(e){ /* ignore */ }

      try{
        const ah = ci.adaptive_health || {};
        if(ah && ah.ok){
          const lvl = Number(ah.level || 0);
          const reduced = !!ah.reduced;
          const action = (ah.action || '').toString();
          const ap = ah.applied || {};
          const bits = [];
          if(ap.workers !== undefined) bits.push(`w=${Number(ap.workers)}`);
          if(ap.chunk_size !== undefined) bits.push(`chunk=${Number(ap.chunk_size)}`);
          if(ap.delay_s !== undefined) bits.push(`delay=${Number(ap.delay_s)}s`);
          adaptiveShort = `health[L${lvl}${reduced ? '↓' : ''}${action ? (':' + action) : ''}${bits.length ? (' ' + bits.join(',')) : ''}]`;
        }
      }catch(e){ /* ignore */ }

      chunkLine = `#${cnum} size=${Number(ci.size||0)} · workers=${Number(ci.workers||0)} · delay=${Number(ci.delay_s||0)}s · attempt=${at} · sender=${sender} · spam=${spam} · bl=${blShort} · subject=${subjShort}`+
        (pmtaReasonShort ? (` · pmta=${pmtaReasonShort}`) : '')+
        (pmtaSlowShort ? (` · pmta_slow(${pmtaSlowShort})`) : '')+
        (adaptiveShort ? (` · ${adaptiveShort}`) : '');
    }
    qk(card,'chunkLine').textContent = chunkLine;

    // active domains for current chunk
    const cdEntries = Object.entries(cDom).sort((a,b)=>Number(b[1]||0)-Number(a[1]||0)).slice(0,6);
    qk(card,'chunkDomains').innerHTML = cdEntries.length
      ? ('Active domains: ' + cdEntries.map(([d,c]) => `${esc(d)}(${Number(c||0)})`).join(' · '))
      : 'Active domains: —';

    // Backoff info (latest)
    const cs = chunkStates.slice().reverse();
    const lastBack = cs.find(x => (x.status || '') === 'backoff');
    let backLine = '—';
    if(lastBack){
      const next = lastBack.next_retry_ts ? new Date(Number(lastBack.next_retry_ts)*1000).toLocaleTimeString() : '';
      const rs = (lastBack.reason || '').toString();
      const rshort = rs.length > 120 ? (rs.slice(0,120) + '…') : rs;
      backLine = `Chunk #${Number(lastBack.chunk||0)+1} retry=${Number(lastBack.attempt||0)} · next=${next || '—'} · ${rshort}`;
    } else if((st||'').toLowerCase() === 'backoff'){
      backLine = 'Backoff active (waiting for retry)…';
    }
    qk(card,'backoffLine').textContent = backLine;
    // PMTA Live Panel (optional) — richer UI
    const pmEl = qk(card,'pmtaLine');
    const pmDiagEl = qk(card,'pmtaDiag');
    const pmNoteEl = qk(card,'pmtaNote');
    if(pmNoteEl){
      pmNoteEl.innerHTML = 'Note: <b>sent</b> = accepted by PMTA (client-side). Delivery may still be queued/deferred.';
    }

    function _pmFmt(v){ return (v === null || v === undefined) ? '—' : v; }
    function _pmNum(v){
      const n = Number(v);
      return (Number.isFinite(n) ? n : null);
    }

    function _pmTone(kind, n){
      // kind: 'backlog'|'deferred'|'conns'|'pressure'
      if(n === null) return '';
      const x = Number(n);
      if(kind === 'deferred'){
        if(x >= 100) return 'bad';
        if(x > 0) return 'warn';
        return 'good';
      }
      if(kind === 'backlog'){
        // backlog usually means spool/queue accumulating
        if(x >= 50000) return 'bad';
        if(x > 0) return 'warn';
        return 'good';
      }
      if(kind === 'pressure'){
        if(x >= 3) return 'bad';
        if(x >= 1) return 'warn';
        return 'good';
      }
      // conns
      if(x >= 800) return 'warn';
      return 'good';
    }

    function _pmTrafficTone(inCount, outCount){
      const inN = _pmNum(inCount);
      const outN = _pmNum(outCount);
      if(inN === null || outN === null) return '';
      if(inN <= 0){
        if(outN <= 0) return 'warn';
        return 'good';
      }
      const ratio = outN / inN;
      if(ratio < 0.25) return 'bad';
      if(ratio <= 0.5) return 'warn';
      return 'good';
    }

    function _tagHtml(tone, label){
      const cls = tone ? ('tag ' + tone) : 'tag';
      return `<span class="${cls}">${esc(label)}</span>`;
    }

    function _titleWithTip(label, tipText){
      const safeLabel = esc(label || '');
      if(!tipText) return safeLabel;
      return `${safeLabel} <span class="tip" data-tip="${esc(tipText)}">ⓘ</span>`;
    }

    function _box(titleHtml, tagTone, tagLabel, inner){
      return `<div class="pmtaBox">`+
        `<div class="pmtaTitle"><span>${titleHtml}</span>${tagLabel ? _tagHtml(tagTone, tagLabel) : ''}</div>`+
        (inner || '')+
      `</div>`;
    }

    function _kv(k, v, tone, big, tipText){
      const cls = 'pmtaVal' + (tone ? (' ' + tone) : '') + (big ? ' pmtaBig' : '');
      const kHtml = _titleWithTip(k, tipText);
      return `<div class="pmtaRow"><span class="pmtaKey">${kHtml}</span><span class="${cls}">${esc(String(v))}</span></div>`;
    }

    function _renderPmtaPanel(pm, pr){
      if(!pm || !pm.enabled){
        return `<div class="pmtaBanner warn">PMTA: disabled</div>`;
      }
      if(!pm.ok){
        const why = (pm.reason || 'unreachable').toString();
        return `<div class="pmtaBanner bad">PMTA monitor unreachable<br><span class="muted">${esc(why)}</span></div>`;
      }

      const spR = _pmFmt(pm.spool_recipients);
      const spM = _pmFmt(pm.spool_messages);
      const qR  = _pmFmt(pm.queued_recipients);
      const qM  = _pmFmt(pm.queued_messages);
      const con = _pmFmt(pm.active_connections);
      const conIn = _pmFmt(pm.smtp_in_connections);
      const conOut = _pmFmt(pm.smtp_out_connections);
      const hrIn = _pmFmt(pm.traffic_last_hr_in);
      const hrOut = _pmFmt(pm.traffic_last_hr_out);
      const minIn = _pmFmt(pm.traffic_last_min_in);
      const minOut = _pmFmt(pm.traffic_last_min_out);
      const ts  = pm.ts ? String(pm.ts) : '';

      const spR_n = _pmNum(pm.spool_recipients);
      const qR_n  = _pmNum(pm.queued_recipients);
      const con_n = _pmNum(pm.active_connections);
      const hrIn_n = _pmNum(pm.traffic_last_hr_in);
      const hrOut_n = _pmNum(pm.traffic_last_hr_out);
      const minIn_n = _pmNum(pm.traffic_last_min_in);
      const minOut_n = _pmNum(pm.traffic_last_min_out);

      const toneSp = _pmTone('backlog', spR_n);
      const toneQ  = _pmTone('backlog', qR_n);
      const toneHr = _pmTrafficTone(hrIn_n, hrOut_n);
      const toneMin = _pmTrafficTone(minIn_n, minOut_n);
      const toneC  = _pmTone('conns', con_n);

      // top queues
      let topTxt = '—';
      try{
        const tqs = Array.isArray(pm.top_queues) ? pm.top_queues : [];
        if(tqs.length){
          const top = tqs.slice(0, 4).map(x => {
            const qn = (x.queue ?? '').toString();
            const dm = (x.domain ?? '').toString();
            const rr = (x.recipients ?? 0);
            const dd = (x.deferred ?? 0);
            const le = (x.last_error ?? '').toString();
            const base = `${qn}=${rr}` + (dd ? (`(def:${dd})`) : '');
            const domPart = dm ? (` [${dm}]`) : '';
            const errPart = le ? (` · err: ${le.slice(0,70)}`) : '';
            return base + domPart + errPart;
          });
          topTxt = top.join(' · ');
        }
      }catch(e){ topTxt = '—'; }

      const html = `
        <div class="pmtaGrid">
          ${_box(_titleWithTip('Spool', 'Current PMTA spool backlog snapshot.'), toneSp, 'rcpt', _kv('RCPT', spR, toneSp, true, 'Recipient count currently in spool.') + _kv('MSG', spM, toneSp, false))}
          ${_box(_titleWithTip('Queue', 'Current PMTA queue backlog snapshot.'), toneQ, 'rcpt', _kv('RCPT', qR, toneQ, true, 'Recipient count currently in PMTA queue.') + _kv('MSG', qM, toneQ, false))}
          ${_box(_titleWithTip('Connections', 'Live PMTA SMTP connection usage.'), toneC, '', _kv('SMTP In', conIn, toneC, true) + _kv('SMTP Out', conOut, toneC, true) + _kv('Total', con, toneC, false))}
          ${_box(_titleWithTip('Last minute', 'Traffic recipients seen by PMTA in the last minute.'), toneMin, '', _kv('In', minIn, toneMin, true) + _kv('Out', minOut, toneMin, true) + `<div class="pmtaSub">traffic recipients / minute</div>`)}
          ${_box(_titleWithTip('Last hour', 'Traffic recipients seen by PMTA in the last hour.'), toneHr, '', _kv('In', hrIn, toneHr, true) + _kv('Out', hrOut, toneHr, true) + `<div class="pmtaSub">traffic recipients / hour</div>`)}
          ${_box(_titleWithTip('Top queues', 'Largest PMTA queues by recipient load and recent defer/error context.'), (topTxt === '—' ? 'good' : 'warn'), '', `<div class="pmtaSub">${esc(topTxt)}</div>`)}
          ${_box(_titleWithTip('Time', 'Timestamp of the PMTA live snapshot.'), 'good', '', `<div class="pmtaSub">${esc(ts || '—')}</div>`)}
        </div>
      `;
      return html;
    }

    if(pmEl){
      const pm = j.pmta_live || null;
      const pr = j.pmta_pressure || null;
      pmEl.innerHTML = _renderPmtaPanel(pm, pr);
    }

    const monitorStatusEl = qk(card,'monitorStatus');
    if(monitorStatusEl){
      const pm = j.pmta_live || {};
      const connected = !!(pm && pm.enabled && pm.ok);
      monitorStatusEl.classList.remove('good','bad');
      monitorStatusEl.classList.add(connected ? 'good' : 'bad');
      monitorStatusEl.innerHTML = `<span class="liveDot"></span>${connected ? 'Connected' : 'Disconnected'}`;
    }

    // PMTA diagnostics snapshot (point 7)

    if(pmDiagEl){
      const d = j.pmta_diag || {};
      if(d && d.enabled && d.ok){
        const cls = (d.class || '');
        const dom = (d.domain || '');
        const def = (d.queue_deferrals ?? '—');
        const err = (d.queue_errors ?? '—');
        const hint = (d.remote_hint || '');
        const samp = Array.isArray(d.errors_sample) ? d.errors_sample.slice(0,2).join(' / ') : '';
        pmDiagEl.textContent = `Diag: class=${cls} dom=${dom} def=${def} err=${err}` + (hint ? (` · hint=${hint}`) : '') + (samp ? (` · sample=${samp}`) : '');
      } else if(d && d.enabled && !d.ok) {
        pmDiagEl.textContent = `Diag: ${d.reason || '—'}`;
      } else {
        pmDiagEl.textContent = 'Diag: —';
      }
    }

    // 6) Counters
    const counters = [
      `safe_total=${Number(j.safe_list_total||0)}`,
      `safe_invalid=${Number(j.safe_list_invalid||0)}`,
      `invalid_filtered=${Number(j.invalid||0)}`,
      `skipped=${Number(j.skipped||0)}`,
      `backoff_events=${Number(j.chunks_backoff||0)}`,
      `abandoned_chunks=${Number(j.chunks_abandoned||0)}`,
      `paused=${j.paused ? 'yes' : 'no'}`,
      `stop_requested=${j.stop_requested ? 'yes' : 'no'}`
    ];
    qk(card,'counters').textContent = counters.join(' · ');

    // Outcomes panel + trend (last ~20 minutes)
    const outEl = qk(card,'outcomes');
    const trEl = qk(card,'outcomeTrend');
    if(outEl){
      const ts = (j.accounting_last_ts || '').toString();
      const deliveredN = Number(j.delivered||0);
      const bouncedN = Number(j.bounced||0);
      const deferredN = Number(j.deferred||0);
      const complainedN = Number(j.complained||0);
      const sentN = Number(j.sent||0);
      const pendingByOutcome = Math.max(0, sentN - deliveredN - bouncedN - complainedN);
      const queuedNow = Number((((j.pmta_live || {}).queued_recipients) ?? 0) || 0);
      outEl.innerHTML = `
        <div class="outcomesGrid">
          <div class="outChip del"><span class="k">Delivered</span><span class="v">${deliveredN}</span></div>
          <div class="outChip bnc"><span class="k">Bounced</span><span class="v">${bouncedN}</span></div>
          <div class="outChip def"><span class="k">Deferred</span><span class="v">${deferredN}</span></div>
          <div class="outChip cmp"><span class="k">Complained</span><span class="v">${complainedN}</span></div>
        </div>
        <div class="outMeta">Pending (sent - final outcomes): <b>${pendingByOutcome}</b> · PMTA queue now: <b>${queuedNow}</b></div>
        <div class="outMeta">${ts ? (`Last accounting update: ${esc(ts)}`) : 'Last accounting update: —'}</div>
      `;
    }
    function spark(vals){
      const chars = '▁▂▃▄▅▆▇█';
      const mx = Math.max(1, ...vals.map(v=>Number(v||0)));
      return vals.map(v => {
        const x = Number(v||0);
        const idx = Math.max(0, Math.min(chars.length-1, Math.round((x/mx)*(chars.length-1))));
        return chars[idx];
      }).join('');
    }
    if(trEl){
      const s = Array.isArray(j.outcome_series) ? j.outcome_series : [];
      const tail = s.slice(-20);
      const delV = tail.map(x=>Number(x.delivered||0));
      const bncV = tail.map(x=>Number(x.bounced||0));
      const defV = tail.map(x=>Number(x.deferred||0));
      const cmpV = tail.map(x=>Number(x.complained||0));
      if(tail.length){
        trEl.innerHTML = [
          `<span class="trendHead">Trend <span class="tip" data-tip="Mini sparkline trend for delivered, bounced, deferred, and complained outcomes.">ⓘ</span></span>`,
          `<span class="trendSeg del"><span class="lbl">DEL</span><span class="spark">${esc(spark(delV))}</span></span>`,
          `<span class="trendSeg bnc"><span class="lbl">BNC</span><span class="spark">${esc(spark(bncV))}</span></span>`,
          `<span class="trendSeg def"><span class="lbl">DEF</span><span class="spark">${esc(spark(defV))}</span></span>`,
          `<span class="trendSeg cmp"><span class="lbl">CMP</span><span class="spark">${esc(spark(cmpV))}</span></span>`
        ].join(' ');
      } else {
        trEl.innerHTML = `Trend <span class="tip" data-tip="Mini sparkline trend for delivered, bounced, deferred, and complained outcomes.">ⓘ</span> · —`;
      }
    }

    // 5) Top domains
    renderTopDomains(card, j);

    // 7) Error types + last errors
    renderErrorTypes(card, j);

    // 8) Chunk history
    renderChunkHist(card, j);

    // 10) Alerts (simple)
    const alertsEl = qk(card,'alerts');
    const failRatio = (done > 0) ? (failed / done) : 0;
    const nearSpam = cs.find(x => (x.spam_score !== null && x.spam_score !== undefined && Number(x.spam_score) > (Number(j.spam_threshold||4) * 0.9)));

    const alerts = [];
    if((st||'').toLowerCase() === 'backoff') alerts.push('⚠ backoff');
    if(Number(j.chunks_abandoned||0) > 0) alerts.push('❌ abandoned chunks');
    if(done >= 20 && failRatio >= 0.1) alerts.push('⚠ high fail rate');
    if(nearSpam) alerts.push('⚠ spam near limit');

    const alertsTip = '<span class="tip" data-tip="Live warning summary for backoff, abandoned chunks, high fail ratio, or near-threshold spam.">ⓘ</span>';
    alertsEl.innerHTML = alerts.length
      ? ('Alerts: ' + esc(alerts.join(' · ')) + ' ' + alertsTip)
      : ('Alerts: — ' + alertsTip);

    // Notifications
    const pm = j.pmta_live || null;
    const pmStateNow = (pm && pm.enabled)
      ? (pm.ok ? 'ok' : 'bad')
      : 'disabled';
    const pmStatePrev = state.lastPmtaMonitor[jobId];
    if(pmStatePrev !== pmStateNow){
      if(pmStateNow === 'ok'){
        toast('✅ PowerMTA Monitor connected', `Job ${jobId}: Live monitor connection is active.`, 'good');
      }else if(pmStateNow === 'bad'){
        toast('❌ PowerMTA Monitor disconnected', `Job ${jobId}: ${pm?.reason || 'Monitor unreachable.'}`, 'bad');
      }
      state.lastPmtaMonitor[jobId] = pmStateNow;
    }

    const prevStatus = state.lastStatus[jobId];
    if(prevStatus && prevStatus !== st){
      if((st||'').toLowerCase() === 'backoff') toast('Backoff', `Job ${jobId} entered backoff.`, 'warn');
      if((st||'').toLowerCase() === 'done') toast('Done', `Job ${jobId} finished.`, 'good');
      if((st||'').toLowerCase() === 'error') toast('Error', `Job ${jobId} errored: ${j.last_error || ''}`, 'bad');
      if((st||'').toLowerCase() === 'stopped') toast('Stopped', `Job ${jobId} stopped: ${j.stop_reason || ''}`, 'warn');
      if((st||'').toLowerCase() === 'paused') toast('Paused', `Job ${jobId} paused.`, 'warn');
      if((st||'').toLowerCase() === 'running' && (prevStatus||'').toLowerCase() === 'paused') toast('Resumed', `Job ${jobId} resumed.`, 'good');
    }
    state.lastStatus[jobId] = st;

    const prevAb = Number(state.lastAbandoned[jobId] || 0);
    const abNow = Number(j.chunks_abandoned || 0);
    if(abNow > prevAb){
      toast('Abandoned chunk', `Job ${jobId}: abandoned_chunks=${abNow}`, 'bad');
    }
    state.lastAbandoned[jobId] = abNow;

    const prevBf = Number(state.lastBackoff[jobId] || 0);
    const bfNow = Number(j.chunks_backoff || 0);
    if(bfNow > prevBf){
      toast('Backoff event', `Job ${jobId}: backoff_events=${bfNow}`, 'warn');
    }
    state.lastBackoff[jobId] = bfNow;

    const prevFail = Number(state.lastFailed[jobId] || 0);
    const failNow = Number(j.failed || 0);
    if(failNow > prevFail && done >= 20 && failRatio >= 0.1){
      toast('High fail rate', `Job ${jobId}: failed=${failNow}/${done} (${Math.round(failRatio*100)}%)`, 'warn');
    }
    state.lastFailed[jobId] = failNow;

    // Adaptive pressure toasts (health/accounting-driven)
    try{
      const ah = (j.current_chunk_info && j.current_chunk_info.adaptive_health) ? j.current_chunk_info.adaptive_health : null;
      if(ah && ah.ok){
        const targetDomain = ((j.current_chunk_info && j.current_chunk_info.target_domain) || '').toString();
        const signature = [
          Number(ah.level || 0),
          !!ah.reduced,
          (ah.action || '').toString(),
          JSON.stringify(ah.applied || {}),
          (ah.reason || '').toString(),
          targetDomain
        ].join('|');
        if(signature && state.lastAdaptive[jobId] !== signature){
          if(ah.reduced){
            const ap = ah.applied || {};
            toast(
              'Adaptive throttle',
              `Job ${jobId}${targetDomain ? (' · ' + targetDomain) : ''}: reduced pressure (L${Number(ah.level||0)}) · workers=${Number(ap.workers||0)} chunk=${Number(ap.chunk_size||0)} delay=${Number(ap.delay_s||0)}s`,
              'warn'
            );
          }else if((ah.action || '') === 'speed_up'){
            toast('Adaptive speed-up', `Job ${jobId}: healthy delivery, increasing throughput gradually.`, 'good');
          }
          state.lastAdaptive[jobId] = signature;
        }
      }
    }catch(e){ /* ignore */ }

    // Route/IP/domain switch toast per provider domain
    try{
      const ci2 = j.current_chunk_info || {};
      const pDom = (ci2.target_domain || '').toString();
      const senderNow = (ci2.sender || '').toString();
      if(pDom && senderNow){
        const key = `${jobId}:${pDom}`;
        const prevSender = (state.lastRoute[key] || '').toString();
        if(prevSender && prevSender !== senderNow){
          toast('Route switched', `Provider ${pDom}: switched sender/IP from ${prevSender} to ${senderNow}.`, 'warn');
        }
        state.lastRoute[key] = senderNow;
      }
    }catch(e){ /* ignore */ }

    // Disable/enable controls based on state
    const btnPause = card.querySelector('[data-action="pause"]');
    const btnResume = card.querySelector('[data-action="resume"]');
    const btnStop = card.querySelector('[data-action="stop"]');
    if(btnPause) btnPause.disabled = !!j.paused || (st||'').toLowerCase() === 'done' || (st||'').toLowerCase() === 'error' || (st||'').toLowerCase() === 'stopped';
    if(btnResume) btnResume.disabled = !j.paused || (st||'').toLowerCase() === 'done' || (st||'').toLowerCase() === 'error' || (st||'').toLowerCase() === 'stopped';
    if(btnStop) btnStop.disabled = (st||'').toLowerCase() === 'done' || (st||'').toLowerCase() === 'error' || (st||'').toLowerCase() === 'stopped';
  }

  async function tickCard(card){
    const jobId = card.dataset.jobid;
    try{
      const r = await fetch(`/api/job/${jobId}`);
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && !j.error){
        updateCard(card, j);
      }
    }catch(e){
      // ignore
    }
  }

  function bindControls(card){
    const jobId = card.dataset.jobid;
    const btns = card.querySelectorAll('button[data-action]');
    btns.forEach(b => {
      b.addEventListener('click', () => {
        const action = b.getAttribute('data-action');
        if(action === 'delete'){
          deleteJob(jobId, card);
          return;
        }
        controlJob(jobId, action);
      });
    });
  }

  let cards = Array.from(document.querySelectorAll('.job[data-jobid]'));
  cards.forEach(bindControls);

  function refreshCardsCollection(){
    cards = Array.from(document.querySelectorAll('.job[data-jobid]'));
    return cards;
  }

  async function tickAll(){
    const currentCards = refreshCardsCollection();
    for(const c of currentCards){
      await tickCard(c);
    }
  }

  async function bridgeDebugTick(){
    try{
      const r = await fetch('/api/accounting/bridge/status');
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && j.ok && j.bridge){
        const b = j.bridge || {};
        console.log('[Bridge↔Shiva Debug]', {
          connected: !!b.connected,
          last_ok: !!b.last_ok,
          last_error: b.last_error || '',
          last_attempt_ts: b.last_attempt_ts || '',
          last_success_ts: b.last_success_ts || '',
          attempts: Number(b.attempts || 0),
          success_count: Number(b.success_count || 0),
          failure_count: Number(b.failure_count || 0),
          req_url: b.last_req_url || b.pull_url_masked || '',
          bridge_return_keys: Array.isArray(b.last_response_keys) ? b.last_response_keys : [],
          bridge_return_count: Number(b.last_bridge_count || 0),
          processed_by_shiva: Number(b.last_processed || 0),
          accepted_by_shiva: Number(b.last_accepted || 0),
          lines_sample: Array.isArray(b.last_lines_sample) ? b.last_lines_sample : [],
          duration_ms: Number(b.last_duration_ms || 0),
        });
      } else {
        console.warn('[Bridge↔Shiva Debug] bridge status failed', {http_status: r.status, payload: j});
      }
    }catch(e){
      console.error('[Bridge↔Shiva Debug] bridge status exception', e);
    }
  }

  let jobsDigestSignature = '';
  const campaignId = new URLSearchParams(location.search).get('c') || '';

  async function refreshJobsDigest(){
    try{
      const qp = campaignId ? `?c=${encodeURIComponent(campaignId)}` : '';
      const r = await fetch(`/api/jobs_digest${qp}`);
      const j = await r.json().catch(()=>({}));
      if(!r.ok || !j || !j.ok || !Array.isArray(j.jobs)) return;

      const ids = j.jobs.map(x => (x && x.id ? x.id : '')).filter(Boolean);
      const sig = ids.join('|');
      if(!jobsDigestSignature){
        jobsDigestSignature = sig;
        return;
      }
      if(sig !== jobsDigestSignature){
        jobsDigestSignature = sig;
        location.reload();
      }
    }catch(e){ /* ignore */ }
  }

  document.getElementById('btnRefreshAll')?.addEventListener('click', async () => {
    await tickAll();
    await refreshJobsDigest();
  });

  tickAll();
  bridgeDebugTick();
  refreshJobsDigest();
  setInterval(tickAll, 1200);
  setInterval(bridgeDebugTick, 5000);
  setInterval(refreshJobsDigest, 1500);
</script>
</body>
</html>
"""

PAGE_CAMPAIGNS = r"""
<!doctype html>
<html lang="en" dir="ltr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Campaigns</title>
  <style>
    :root{
      --bg1:#0b1020; --bg2:#0a1a2b;
      --card: rgba(255,255,255,.08);
      --card2: rgba(255,255,255,.06);
      --border: rgba(255,255,255,.14);
      --text: rgba(255,255,255,.92);
      --muted: rgba(255,255,255,.65);
      --good: #35e49a;
      --bad: #ff5e73;
      --warn: #ffc14d;
      --accent:#7aa7ff;
      --shadow: 0 20px 60px rgba(0,0,0,.35);
      --radius: 18px;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family: system-ui, -apple-system, "Segoe UI", Tahoma, Arial;
      color: var(--text);
      background:
        radial-gradient(1000px 700px at 80% 20%, rgba(122,167,255,.22), transparent 60%),
        radial-gradient(900px 700px at 20% 30%, rgba(53,228,154,.16), transparent 60%),
        linear-gradient(180deg, var(--bg1), var(--bg2));
      min-height:100vh;
      padding: 28px 14px;
    }
    a{ color: var(--accent); }
    .wrap{max-width: 1100px; margin: 0 auto;}
    .top{
      display:flex; gap:14px; align-items:flex-start; justify-content:space-between;
      flex-wrap:wrap; margin-bottom: 18px;
    }
    h1{ margin:0; font-size: 22px; letter-spacing: .2px; }
    .sub{
      margin-top:6px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
      max-width: 760px;
    }
    .card{
      background: linear-gradient(180deg, var(--card), var(--card2));
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 16px;
      backdrop-filter: blur(10px);
      margin-bottom: 12px;
    }
    .row{ display:flex; gap:12px; flex-wrap:wrap; align-items:center; justify-content:space-between; }
    .left{ display:flex; flex-direction:column; gap:4px; }
    .mini{ font-size: 12px; color: var(--muted); }
    code{background:rgba(255,255,255,.08); padding:2px 6px; border-radius:8px;}

    .actions{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
    .btn{
      border: 1px solid rgba(255,255,255,.18);
      background: rgba(122,167,255,.18);
      color: var(--text);
      padding: 10px 12px;
      border-radius: 14px;
      cursor:pointer;
      font-weight: 700;
      letter-spacing:.2px;
      text-decoration:none;
      display:inline-flex;
      align-items:center;
      gap:8px;
    }
    .btn:hover{filter: brightness(1.06)}
    .btn.secondary{ background: rgba(255,255,255,.08); }
    .btn.danger{ background: rgba(255,94,115,.18); }

    input{
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,.16);
      background: rgba(0,0,0,.18);
      color: var(--text);
      outline: none;
      min-width: 220px;
    }

    form.inline{ display:inline-flex; gap:8px; flex-wrap:wrap; align-items:center; margin:0; }

    .pill{
      display:inline-flex; align-items:center; gap:8px;
      padding: 10px 12px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 999px;
      box-shadow: var(--shadow);
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
      text-decoration:none;
    }

    .dangerTitle{ font-weight:900; color: var(--warn); }
  </style>
</head>
<body>
  <div class="wrap">

    <div class="top">
      <div>
        <h1>Campaigns</h1>
        <div class="sub">
          Create multiple saved campaigns. Each campaign stores its own SMTP settings, message, controls, recipients, etc (SQLite).
        </div>
      </div>
      <div class="actions">
        <a class="btn" href="/campaigns/new">➕ New Campaign</a>
        <a class="pill" href="/campaigns">📌 Campaigns</a>
      </div>
    </div>

    {% for c in campaigns %}
      <div class="card">
        <div class="row">
          <div class="left">
            <div style="font-weight:900">{{c.name}}</div>
            <div class="mini">ID: <code>{{c.id}}</code> · Created: {{c.created_at}}</div>
          </div>
          <div class="mini">Updated: {{c.updated_at}}</div>
        </div>

        <div class="actions" style="margin-top:12px">
          <a class="btn" href="/campaign/{{c.id}}">Open</a>

          <form method="post" action="/campaign/{{c.id}}/rename" class="inline">
            <input name="name" value="{{c.name}}" />
            <button class="btn secondary" type="submit">Rename</button>
          </form>

          <form method="post" action="/campaign/{{c.id}}/delete" class="inline" onsubmit="return confirm('Delete this campaign?');">
            <button class="btn danger" type="submit">Delete</button>
          </form>
        </div>
      </div>
    {% endfor %}

    {% if campaigns|length == 0 %}
      <div class="card">
        <div class="mini">No campaigns yet. Click “New Campaign”.</div>
      </div>
    {% endif %}

    <div class="card">
      <div class="row">
        <div>
          <div class="dangerTitle">Danger zone</div>
          <div class="mini">This clears SQLite tables (campaigns + forms). Use only if you really want to reset.</div>
        </div>
        <form method="post" action="/campaigns/wipe" class="inline" onsubmit="return confirm('Wipe ALL campaigns and saved data?');">
          <button class="btn danger" type="submit">🧨 Wipe DB</button>
        </form>
      </div>
    </div>

  </div>
</body>
</html>
"""


PAGE_CONFIG = r"""
<!doctype html>
<html lang="en" dir="ltr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Config</title>
  <style>
    :root{
      --bg1:#0b1020; --bg2:#0a1a2b;
      --card: rgba(255,255,255,.08);
      --card2: rgba(255,255,255,.06);
      --border: rgba(255,255,255,.14);
      --text: rgba(255,255,255,.92);
      --muted: rgba(255,255,255,.65);
      --good: #35e49a;
      --bad: #ff5e73;
      --warn: #ffc14d;
      --accent:#7aa7ff;
      --shadow: 0 20px 60px rgba(0,0,0,.35);
      --radius: 18px;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family: system-ui, -apple-system, "Segoe UI", Tahoma, Arial;
      color: var(--text);
      background:
        radial-gradient(1000px 700px at 80% 20%, rgba(122,167,255,.22), transparent 60%),
        radial-gradient(900px 700px at 20% 30%, rgba(53,228,154,.16), transparent 60%),
        linear-gradient(180deg, var(--bg1), var(--bg2));
      min-height:100vh;
      padding: 28px 14px;
    }
    .wrap{max-width: 1200px; margin: 0 auto;}
    .top{display:flex; gap:14px; align-items:flex-start; justify-content:space-between; flex-wrap:wrap; margin-bottom: 14px;}
    h1{ margin:0; font-size: 22px; letter-spacing: .2px; }
    .sub{margin-top:6px; color: var(--muted); font-size: 13px; line-height: 1.6; max-width: 860px;}

    .card{background: linear-gradient(180deg, var(--card), var(--card2)); border: 1px solid var(--border); border-radius: var(--radius);
      box-shadow: var(--shadow); padding: 16px; backdrop-filter: blur(10px); margin-bottom: 12px;}

    .nav{display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-top:10px}
    .btn{border: 1px solid rgba(255,255,255,.18); background: rgba(122,167,255,.18); color: var(--text); padding: 10px 12px;
      border-radius: 14px; cursor:pointer; font-weight: 700; letter-spacing:.2px; text-decoration:none; display:inline-flex; align-items:center; gap:8px;}
    .btn:hover{filter:brightness(1.06)}
    .btn.secondary{ background: rgba(255,255,255,.08); }
    .btn.danger{ background: rgba(255,94,115,.18); }

    input[type="text"], input[type="number"], input[type="password"], textarea{
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,.16);
      background: rgba(0,0,0,.18);
      color: var(--text);
      outline: none;
      width: 100%;
    }
    textarea{ min-height: 44px; resize: vertical; white-space: pre-wrap; word-break: break-word; }

    table{width:100%; border-collapse:collapse; font-size: 12.5px; table-layout: fixed;}
    th,td{padding:10px 8px; border-bottom:1px solid rgba(255,255,255,.10); text-align:left; vertical-align:top; word-break: break-word; overflow-wrap:anywhere;}
    th{color: rgba(255,255,255,.86)}
    code{background:rgba(255,255,255,.08); padding:2px 6px; border-radius:8px; white-space:pre-wrap; word-break:break-word; overflow-wrap:anywhere; max-width:100%;}
    td .mini code{display:inline-block; max-width:100%;}
    /* Column widths (responsive, wraps instead of forcing horizontal scroll) */
    th:nth-child(1), td:nth-child(1){width:22%;}
    th:nth-child(2), td:nth-child(2){width:26%;}
    th:nth-child(3), td:nth-child(3){width:14%;}
    th:nth-child(4), td:nth-child(4){width:28%;}
    th:nth-child(5), td:nth-child(5){width:10%;}
    .mini{font-size:12px; color: var(--muted); line-height:1.55}

    .pill{display:inline-flex; align-items:center; gap:8px; padding:6px 10px; border-radius:999px; border:1px solid rgba(255,255,255,.14); background:rgba(255,255,255,.06); font-size:12px;}
    .pill.good{border-color: rgba(53,228,154,.35); color: var(--good); font-weight:900}
    .pill.warn{border-color: rgba(255,193,77,.35); color: var(--warn); font-weight:900}
    .pill.bad{border-color: rgba(255,94,115,.35); color: var(--bad); font-weight:900}

    .right{display:flex; gap:10px; flex-wrap:nowrap; align-items:center; justify-content:flex-end;}
    .q{flex:1 1 320px; min-width:220px; max-width: 520px;}
    .btnRow{display:flex; gap:10px; align-items:center; flex:0 0 auto; white-space:nowrap;}
    @media (max-width: 720px){
      .right{flex-wrap:wrap; justify-content:stretch;}
      .q{flex:1 1 100%; max-width:none;}
      .btnRow{width:100%; justify-content:flex-end;}
    }

    /* Tooltip */
    .tip{display:inline-flex; align-items:center; justify-content:center; width:18px; height:18px; border-radius:999px;
      border:1px solid rgba(255,255,255,.18); background: rgba(0,0,0,.18); color: rgba(255,255,255,.86);
      font-size: 12px; margin-left:8px; cursor: help; position: relative; user-select:none}
    .tip:hover::after{
      content: attr(data-tip);
      position: absolute;
      left: 0;
      top: 24px;
      min-width: 280px;
      max-width: 520px;
      background: rgba(0,0,0,.72);
      border: 1px solid rgba(255,255,255,.18);
      box-shadow: 0 18px 55px rgba(0,0,0,.35);
      backdrop-filter: blur(10px);
      color: rgba(255,255,255,.92);
      padding: 10px 12px;
      border-radius: 14px;
      z-index: 999;
      white-space: normal;
    }

    /* Toast */
    .toast-wrap{ position: fixed; right: 16px; bottom: 16px; z-index: 9999; display:flex; flex-direction:column; gap:10px; }
    .toast{ min-width: 280px; max-width: 460px; background: rgba(0,0,0,.55); border: 1px solid rgba(255,255,255,.18);
      box-shadow: 0 18px 55px rgba(0,0,0,.35); backdrop-filter: blur(10px); border-radius: 14px; padding: 12px 14px;
      color: rgba(255,255,255,.92); font-size: 13px; line-height: 1.5; animation: pop .18s ease-out; }
    @keyframes pop{ from{ transform: translateY(6px); opacity: .2; } to{ transform: translateY(0); opacity: 1; } }
    .toast .t{font-weight:900; margin-bottom:4px}
    .toast.good{ border-color: rgba(53,228,154,.35); }
    .toast.bad{ border-color: rgba(255,94,115,.35); }
    .toast.warn{ border-color: rgba(255,193,77,.35); }

    /* Accordion */
    .acc-list{display:flex; flex-direction:column; gap:10px}
    .acc-item{border:1px solid rgba(255,255,255,.12); border-radius:14px; background:rgba(0,0,0,.14); overflow:hidden}
    .acc-item summary{list-style:none; cursor:pointer; padding:12px 14px; display:flex; align-items:center; justify-content:space-between; gap:12px; font-weight:800}
    .acc-item summary::-webkit-details-marker{display:none}
    .acc-item summary .meta{font-size:12px; color:var(--muted); font-weight:600}
    .acc-item[open] summary{border-bottom:1px solid rgba(255,255,255,.09)}
    .acc-body{padding:8px 12px 12px}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h1>Config · <span style="color: var(--muted)">{{campaign_name}}</span></h1>
        <div class="sub">
          Edit the app-wide <b>environment variables</b> (and the script’s default values) from a single panel.
          Values saved here are stored in <code>SQLite</code> and override <b>ENV</b> for this app.
          <br><span style="color: var(--warn)">⚠️</span> Some keys apply immediately, and some require an app restart.
        </div>
        <div class="nav">
          <a class="btn secondary" href="/campaign/{{campaign_id}}">← Back to Campaign</a>
          <a class="btn secondary" href="/jobs?c={{campaign_id}}">📄 Jobs</a>
          <a class="btn secondary" href="/campaigns">📌 Campaigns</a>
        </div>
      </div>
      <div class="right">
        <input class="q" id="q" type="text" placeholder="Search key or group..." />
        <div class="btnRow">
          <button class="btn secondary" type="button" id="btnReload">🔄 Reload</button>
          <button class="btn" type="button" id="btnSaveAll">💾 Save All</button>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="mini" id="status">—</div>
      <div class="mini" style="margin-top:6px">
        <b>Source labels:</b>
        <span class="pill good">ui</span> saved here ·
        <span class="pill warn">env</span> OS environment ·
        <span class="pill">default</span> script default
      </div>
    </div>

    <div class="card" style="overflow-x:auto; overflow-y:visible">
      <div id="groups" class="acc-list">
        <div class="mini">Loading…</div>
      </div>
    </div>
  </div>

  <div class="toast-wrap" id="toastWrap"></div>

<script>
  const esc = (s) => (s ?? '').toString().replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;');

  function toast(title, msg, kind){
    const wrap = document.getElementById('toastWrap');
    const div = document.createElement('div');
    div.className = `toast ${kind || 'warn'}`;
    const safeMsg = esc(msg).split(/\r?\n/).join("<br>");
    div.innerHTML = `<div class="t">${esc(title)}</div><div>${safeMsg}</div>`;
    wrap.appendChild(div);
    setTimeout(() => {
      div.style.opacity = '0';
      div.style.transform = 'translateY(6px)';
      div.style.transition = 'all .22s ease';
      setTimeout(()=>div.remove(), 260);
    }, 3600);
  }

  let ITEMS = [];
  const CHANGED = new Map();

  function pill(source){
    if(source === 'ui') return '<span class="pill good">ui</span>';
    if(source === 'env') return '<span class="pill warn">env</span>';
    return '<span class="pill">default</span>';
  }

  function render(){
    const groupsWrap = document.getElementById('groups');
    const q = (document.getElementById('q')?.value || '').trim().toLowerCase();

    const grouped = new Map();
    for(const it of ITEMS){
      const key = it.key;
      const group = (it.group || 'Other');
      const t = (it.type || 'str');
      const desc = (it.desc || '');
      const isSecret = !!it.secret;

      const hay = (key + ' ' + group + ' ' + desc).toLowerCase();
      if(q && !hay.includes(q)) continue;

      const restart = !!it.restart_required;
      const restartPill = restart ? '<span class="pill bad">restart</span>' : '<span class="pill good">live</span>';

      // input
      let inp = '';
      const id = 'v_' + key.replaceAll(/[^a-zA-Z0-9_]/g, '_');
      const cur = (it.value ?? '');

      if(t === 'bool'){
        const checked = (String(cur) === '1' || String(cur).toLowerCase() === 'true' || String(cur).toLowerCase() === 'yes' || String(cur).toLowerCase() === 'on');
        inp = `<label class="mini" style="display:flex; gap:10px; align-items:center; margin:0">
          <input id="${esc(id)}" data-k="${esc(key)}" data-type="bool" type="checkbox" ${checked ? 'checked' : ''} />
          <span>${checked ? 'true' : 'false'}</span>
        </label>`;
      } else if(t === 'int'){
        inp = `<input id="${esc(id)}" data-k="${esc(key)}" data-type="int" type="number" value="${esc(cur)}" />`;
      } else if(t === 'float'){
        inp = `<input id="${esc(id)}" data-k="${esc(key)}" data-type="float" type="number" step="0.01" value="${esc(cur)}" />`;
      } else {
        const s = (cur ?? '').toString();
        if(isSecret){
          inp = `<input autocomplete="off" id="${esc(id)}" data-k="${esc(key)}" data-type="str" type="password" value="${esc(s)}" />`;
        } else {
          const isLong = (s.length > 60) || s.includes(',') || s.includes('\n');
          if(isLong){
            inp = `<textarea rows="2" id="${esc(id)}" data-k="${esc(key)}" data-type="str">${esc(s)}</textarea>`;
          } else {
            inp = `<input id="${esc(id)}" data-k="${esc(key)}" data-type="str" type="text" value="${esc(s)}" />`;
          }
        }
      }

      const row = `<tr data-key="${esc(key)}">`+
        `<td>`+
          `<div><code>${esc(key)}</code>`+
            `<span class="tip" data-tip="${esc(desc)}">ⓘ</span>`+
          `</div>`+
        `</td>`+
        `<td>${inp}<div class="mini" style="margin-top:6px">${restart ? 'Changes need restart to fully apply.' : 'Applies immediately (live reload).'} </div></td>`+
        `<td>`+
          `${pill(it.source)} ${restartPill}`+
          `<div class="mini" style="margin-top:6px">Type: <b>${esc(t)}</b></div>`+
        `</td>`+
        `<td class="mini">`+
          `<div><b>default:</b> <code>${esc(it.default_value ?? '')}</code></div>`+
          `<div><b>env:</b> <code>${esc(it.env_value ?? '')}</code></div>`+
          `<div><b>ui:</b> <code>${esc(it.ui_value ?? '')}</code></div>`+
        `</td>`+
        `<td>`+
          `<button class="btn" type="button" data-act="save" data-k="${esc(key)}">Save</button>`+
          ` <button class="btn danger" type="button" data-act="reset" data-k="${esc(key)}">Reset</button>`+
        `</td>`+
      `</tr>`;

      if(!grouped.has(group)) grouped.set(group, []);
      grouped.get(group).push({key, row});
    }

    const sections = [];
    const groups = Array.from(grouped.entries()).sort((a,b)=>a[0].localeCompare(b[0]));
    for(const [groupName, rows] of groups){
      rows.sort((a,b)=>a.key.localeCompare(b.key));
      sections.push(
        `<details class="acc-item" open>`+
          `<summary><span>${esc(groupName)}</span><span class="meta">${rows.length} option(s)</span></summary>`+
          `<div class="acc-body">`+
            `<table>`+
              `<thead>`+
                `<tr>`+
                  `<th style="min-width:310px">Key</th>`+
                  `<th style="min-width:260px">Value</th>`+
                  `<th style="min-width:190px">Info</th>`+
                  `<th style="min-width:320px">Default / ENV / UI</th>`+
                  `<th style="min-width:160px">Actions</th>`+
                `</tr>`+
              `</thead>`+
              `<tbody>${rows.map(r => r.row).join('')}</tbody>`+
            `</table>`+
          `</div>`+
        `</details>`
      );
    }

    groupsWrap.innerHTML = sections.join('') || `<div class="mini">No matches.</div>`;

    // bind input changes
    groupsWrap.querySelectorAll('input[data-k], textarea[data-k]').forEach(el => {
      el.addEventListener('input', () => {
        const k = el.getAttribute('data-k');
        const t = el.getAttribute('data-type');
        let v = '';
        if(t === 'bool') v = el.checked ? '1' : '0';
        else v = (el.value ?? '').toString();
        CHANGED.set(k, {value: v, type: t});
        document.getElementById('status').textContent = `Changed: ${CHANGED.size}`;
      });
      el.addEventListener('change', () => {
        const k = el.getAttribute('data-k');
        const t = el.getAttribute('data-type');
        let v = '';
        if(t === 'bool') v = el.checked ? '1' : '0';
        else v = (el.value ?? '').toString();
        CHANGED.set(k, {value: v, type: t});
        document.getElementById('status').textContent = `Changed: ${CHANGED.size}`;
      });
    });

    // bind actions
    groupsWrap.querySelectorAll('button[data-act]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const act = btn.getAttribute('data-act');
        const k = btn.getAttribute('data-k');
        if(!k) return;
        if(act === 'reset'){
          await resetKey(k);
          return;
        }
        await saveKey(k);
      });
    });
  }

  async function load(){
    try{
      const r = await fetch('/api/config');
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && j.ok){
        ITEMS = j.items || [];
        document.getElementById('status').textContent = `Loaded ${ITEMS.length} keys · saved_overrides=${j.saved_overrides || 0}`;
        CHANGED.clear();
        render();
        return;
      }
      toast('Config', (j && (j.error || j.detail)) ? (j.error || j.detail) : ('HTTP '+r.status), 'bad');
    }catch(e){
      toast('Config', e?.toString?.() || 'Failed', 'bad');
    }
  }

  function readCurrentInput(key){
    const row = document.querySelector(`tr[data-key="${CSS.escape(key)}"]`);
    if(!row) return null;
    const el = row.querySelector('input[data-k], textarea[data-k]');
    if(!el) return null;
    const t = el.getAttribute('data-type');
    let v = '';
    if(t === 'bool') v = el.checked ? '1' : '0';
    else v = (el.value ?? '').toString();
    return {key, value: v};
  }

  async function saveKey(key){
    const payload = readCurrentInput(key);
    if(!payload){ toast('Save', 'Missing input', 'bad'); return; }

    try{
      const r = await fetch('/api/config/set', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(payload)
      });
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && j.ok){
        toast('Saved', `${key} updated`, 'good');
        await load();
      } else {
        toast('Save failed', (j && (j.error||j.detail)) ? (j.error||j.detail) : ('HTTP '+r.status), 'bad');
      }
    }catch(e){ toast('Save failed', e?.toString?.() || 'Unknown', 'bad'); }
  }

  async function resetKey(key){
    const ok = confirm(`Reset ${key}?
This removes the UI override and falls back to ENV/default.`);
    if(!ok) return;

    try{
      const r = await fetch('/api/config/reset', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({key})
      });
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && j.ok){
        toast('Reset', `${key} reset`, 'good');
        await load();
      } else {
        toast('Reset failed', (j && (j.error||j.detail)) ? (j.error||j.detail) : ('HTTP '+r.status), 'bad');
      }
    }catch(e){ toast('Reset failed', e?.toString?.() || 'Unknown', 'bad'); }
  }

  async function saveAll(){
    if(CHANGED.size === 0){ toast('Save All', 'No changes', 'warn'); return; }
    const items = {};
    for(const [k,v] of CHANGED.entries()) items[k] = v.value;

    try{
      const r = await fetch('/api/config/set', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({items})
      });
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && j.ok){
        toast('Saved', `Saved ${j.saved || 0} keys`, 'good');
        await load();
      } else {
        toast('Save All failed', (j && (j.error||j.detail)) ? (j.error||j.detail) : ('HTTP '+r.status), 'bad');
      }
    }catch(e){ toast('Save All failed', e?.toString?.() || 'Unknown', 'bad'); }
  }

  document.getElementById('btnReload')?.addEventListener('click', load);
  document.getElementById('btnSaveAll')?.addEventListener('click', saveAll);
  document.getElementById('q')?.addEventListener('input', render);

  load();
</script>
</body>
</html>
"""


PAGE_DOMAINS = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Domains Stats</title>
  <style>
    body{font-family:system-ui; margin:0; background:#0b1020; color:#fff;}
    .wrap{max-width: 1200px; margin: 0 auto; padding:18px 14px;}
    a{color:#7aa7ff}
    .card{background:rgba(255,255,255,.06); border:1px solid rgba(255,255,255,.14); border-radius:14px; padding:14px; margin-bottom:12px;}
    .row{display:flex; gap:12px; flex-wrap:wrap; align-items:center}
    .muted{color:rgba(255,255,255,.65)}
    input{padding:10px 12px; border-radius:12px; border:1px solid rgba(255,255,255,.18); background:rgba(0,0,0,.18); color:#fff;}
    table{width:100%; border-collapse:collapse; font-size: 13px;}
    th,td{padding:8px; border-bottom:1px solid rgba(255,255,255,.10); text-align:left; vertical-align:top}
    code{background:rgba(255,255,255,.08); padding:2px 6px; border-radius:8px;}
    .good{color:#35e49a; font-weight:800}
    .bad{color:#ff5e73; font-weight:800}
    .warn{color:#ffc14d; font-weight:800}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="row" style="justify-content:space-between; margin-bottom:12px;">
      <div>
        <h2 style="margin:0">Domains stats</h2>
        <div class="muted"><a href="/campaigns" id="backLink">← Back</a> · This page analyzes <b>Recipients</b> and <b>Maillist Safe</b> for the selected campaign (SQLite).</div>
      </div>
      <div class="row">
        <input id="q" placeholder="Search domain..." />
        <a href="#" id="btnReload">Reload</a>
      </div>
    </div>

    <div class="card">
      <div class="row">
        <div><b>Recipients:</b> <span id="rTotals" class="muted">—</span></div>
        <div><b>Safe list:</b> <span id="sTotals" class="muted">—</span></div>
        <div class="muted">MX check is best-effort: MX → A fallback → none/unknown.</div>
      </div>
    </div>

    <div class="card">
      <h3 style="margin:0 0 10px">Recipients domains</h3>
      <div style="overflow:auto">
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>Emails</th>
              <th>MX</th>
              <th>MX hosts</th>
              <th>Mail IP(s)</th>
              <th>Listed</th>
            </tr>
          </thead>
          <tbody id="tblR"></tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h3 style="margin:0 0 10px">Safe list domains</h3>
      <div style="overflow:auto">
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>Emails</th>
              <th>MX</th>
              <th>MX hosts</th>
              <th>Mail IP(s)</th>
              <th>Listed</th>
            </tr>
          </thead>
          <tbody id="tblS"></tbody>
        </table>
      </div>
    </div>
  </div>

<script>
  // Saved values are stored server-side in SQLite per campaign (no localStorage).
  const CAMPAIGN_ID = new URLSearchParams(location.search).get('c') || '';
  if(!CAMPAIGN_ID){
    document.getElementById('tblR').innerHTML = `<tr><td colspan="6" class="bad">Missing campaign id. Open Domains from a campaign.</td></tr>`;
    document.getElementById('tblS').innerHTML = `<tr><td colspan="6" class="bad">Missing campaign id. Open Domains from a campaign.</td></tr>`;
  }
  const back = document.getElementById('backLink');
  if(back && CAMPAIGN_ID){ back.href = `/campaign/${CAMPAIGN_ID}`; }
  const esc = (s) => (s ?? '').toString().replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');

  function statusBadge(mx){
    if(mx === 'mx') return '<span class="good">MX</span>';
    if(mx === 'a_fallback') return '<span class="warn">A</span>';
    if(mx === 'none') return '<span class="bad">NONE</span>';
    return '<span class="warn">UNKNOWN</span>';
  }

  function listedBadge(v){
    return v ? '<span class="bad">Listed</span>' : '<span class="good">Not listed</span>';
  }

  async function loadSaved(){
    try{
      const r = await fetch(`/api/campaign/${CAMPAIGN_ID}/form`);
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && j.ok && j.data && typeof j.data === 'object'){
        return j.data;
      }
    }catch(e){ /* ignore */ }
    return {};
  }

  async function run(){
    const saved = await loadSaved();
    const q = (document.getElementById('q').value || '').trim().toLowerCase();

    const payload = {
      recipients: saved.recipients || '',
      maillist_safe: saved.maillist_safe || ''
    };

    const r = await fetch('/api/domains_stats', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const j = await r.json();

    if(!j.ok){
      document.getElementById('tblR').innerHTML = `<tr><td colspan="6" class="bad">${esc(j.error || 'error')}</td></tr>`;
      document.getElementById('tblS').innerHTML = `<tr><td colspan="6" class="bad">${esc(j.error || 'error')}</td></tr>`;
      return;
    }

    document.getElementById('rTotals').textContent = `${j.recipients.total_emails} emails · ${j.recipients.unique_domains} domains · invalid=${j.recipients.invalid_emails}`;
    document.getElementById('sTotals').textContent = `${j.safe.total_emails} emails · ${j.safe.unique_domains} domains · invalid=${j.safe.invalid_emails}`;

    function renderRows(items){
      const rows = [];
      for(const it of items){
        if(q && !it.domain.toLowerCase().includes(q)) continue;
        const mxHosts = (it.mx_hosts || []).slice(0,4).join(', ');
        const ips = (it.mail_ips || []).join(', ');
        rows.push(`<tr>`+
          `<td><code>${esc(it.domain)}</code></td>`+
          `<td>${it.count}</td>`+
          `<td>${statusBadge(it.mx_status)}</td>`+
          `<td class="muted">${esc(mxHosts || '—')}</td>`+
          `<td class="muted">${esc(ips || '—')}</td>`+
          `<td>${listedBadge(!!it.any_listed)}</td>`+
        `</tr>`);
      }
      return rows.join('') || `<tr><td colspan="6" class="muted">No results.</td></tr>`;
    }

    document.getElementById('tblR').innerHTML = renderRows(j.recipients.domains);
    document.getElementById('tblS').innerHTML = renderRows(j.safe.domains);
  }

  document.getElementById('q').addEventListener('input', run);
  document.getElementById('btnReload').addEventListener('click', (e)=>{ e.preventDefault(); run(); });
  run();
</script>
</body>
</html>
"""


PAGE_JOB = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Job {{job_id}}</title>
  <style>
    :root{
      --bg:#0b1020; --card: rgba(255,255,255,.06); --border: rgba(255,255,255,.14);
      --text:#fff; --muted: rgba(255,255,255,.65);
      --good:#35e49a; --bad:#ff5e73; --warn:#ffc14d; --accent:#7aa7ff;
    }
    body{font-family:system-ui; margin:0; background:var(--bg); color:var(--text);}
    .wrap{max-width: 1100px; margin: 0 auto; padding: 18px 14px;}
    a{color:var(--accent); text-decoration:none}
    .card{background:var(--card); border:1px solid var(--border); border-radius:14px; padding:14px; margin-bottom:12px;}
    .muted{color:var(--muted)}
    .row{display:flex; gap:12px; flex-wrap:wrap; align-items:center}
    code{background:rgba(255,255,255,.08); padding:2px 6px; border-radius:8px;}
    .bar{height: 12px; background: rgba(255,255,255,.10); border:1px solid rgba(255,255,255,.14); border-radius:999px; overflow:hidden;}
    .bar > div{height:100%; width:0%; background: rgba(122,167,255,.65);}
    table{width:100%; border-collapse:collapse; font-size: 13px;}
    th,td{padding:8px; border-bottom:1px solid rgba(255,255,255,.10); text-align:left; vertical-align:top}
    .ok{color:var(--good); font-weight:800}
    .no{color:var(--bad); font-weight:800}
    .pill{padding:6px 10px; border-radius:999px; border:1px solid rgba(255,255,255,.14); background:rgba(255,255,255,.06);}

    .nav{display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-top:8px}
    .nav form{display:inline; margin:0;}
    .navBtn{
      display:inline-flex; align-items:center; gap:8px;
      padding:8px 10px;
      border:1px solid rgba(255,255,255,.14);
      background: rgba(255,255,255,.06);
      border-radius: 12px;
      color: rgba(255,255,255,.92);
      cursor:pointer;
      font: inherit;
      text-decoration:none;
    }
    .navBtn:hover{filter:brightness(1.06)}
    .navBtn.primary{ background: rgba(122,167,255,.14); font-weight:800; }

    .nav a, .nav button{
      display:inline-flex; align-items:center; gap:8px;
      padding:8px 10px;
      border:1px solid rgba(255,255,255,.14);
      background: rgba(255,255,255,.06);
      border-radius: 12px;
      cursor:pointer;
      font: inherit;
      color: rgba(255,255,255,.92);
    }
    .nav a:hover{filter:brightness(1.06)}

    .smallBar{height:8px; border-radius:999px; background:rgba(255,255,255,.10); border:1px solid rgba(255,255,255,.12); overflow:hidden}
    .smallBar > div{height:100%; width:0%; background: rgba(53,228,154,.55);}
    .extractBtn{
      border:1px solid rgba(122,167,255,.45);
      background: linear-gradient(135deg, rgba(122,167,255,.32), rgba(53,228,154,.18));
      color:#fff;
      font-weight:800;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.16), 0 8px 20px rgba(7,12,28,.35);
      transition: transform .12s ease, filter .12s ease, box-shadow .12s ease;
    }
    .extractBtn:hover{
      filter:brightness(1.08);
      transform: translateY(-1px);
      box-shadow: inset 0 1px 0 rgba(255,255,255,.2), 0 10px 24px rgba(7,12,28,.4);
    }
    .extractBtn:active{transform: translateY(0)}
    .extractBtn:disabled{opacity:.65; cursor:not-allowed; transform:none; filter:none; box-shadow:none;}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="row" style="justify-content:space-between; margin-bottom:12px;">
      <div>
        <h2 style="margin:0">Job <code>{{job_id}}</code></h2>
        <div class="nav">
          {% if campaign_id %}
            <form method="get" action="/campaign/{{campaign_id}}">
              <button class="navBtn primary" type="submit">← Back to Campaign</button>
            </form>
            <a class="navBtn" href="/jobs?c={{campaign_id}}">📄 Jobs</a>
            <a class="navBtn" href="/campaigns">📌 Campaigns</a>
          {% else %}
            <a class="navBtn primary" href="/campaigns">← Campaigns</a>
            <a class="navBtn" href="/jobs">All Jobs</a>
          {% endif %}
        </div>
      </div>
      <div class="pill" id="statusPill">Loading...</div>
    </div>

    <div class="card">
      <div class="row">
        <div><b>Total:</b> <span id="total">0</span></div>
        <div><b>Sent:</b> <span id="sent" class="ok">0</span></div>
        <div><b>Failed:</b> <span id="failed" class="no">0</span></div>
        <div><b>Skipped:</b> <span id="skipped">0</span></div>
        <div><b>Invalid:</b> <span id="invalid">0</span></div>
      </div>
      <div style="margin-top:10px" class="bar"><div id="barFill"></div></div>
      <div class="muted" style="margin-top:10px" id="lastError"></div>
    </div>

    <div class="card">
      <h3 style="margin:0 0 10px">Domain State (live)</h3>
      <div class="muted" style="margin-bottom:8px">Per recipient domain: sent/failed out of planned total.</div>
      <div class="bar"><div id="domBarFill"></div></div>
      <div class="muted" style="margin-top:10px" id="domBarText">—</div>
      <div style="overflow:auto; margin-top:10px">
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>Planned</th>
              <th>Sent</th>
              <th>Failed</th>
              <th style="min-width:180px">Progress</th>
            </tr>
          </thead>
          <tbody id="domState"></tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h3 style="margin:0 0 10px">Chunks & Backoff</h3>
      <div class="muted" id="chunkMeta">—</div>
      <div style="overflow:auto; margin-top:10px">
        <table>
          <thead>
            <tr>
              <th>Chunk</th>
              <th>Status</th>
              <th>Size</th>
              <th>Sender</th>
              <th>Spam</th>
              <th>Blacklist</th>
              <th>Attempt</th>
              <th>Next retry</th>
            </tr>
          </thead>
          <tbody id="chunkTbl"></tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="row" style="margin-bottom:8px; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap">
        <h3 style="margin:0">Recent Results</h3>
        <div class="row" style="gap:8px; align-items:center; flex-wrap:wrap">
          <button class="btn extractBtn" id="extractShivaSentBtn" type="button">Extract mail sent by Shiva</button>
          <button class="btn extractBtn" id="extractPmtaDeliveredBtn" type="button">Extract mail sent by PowerMTA</button>
        </div>
      </div>
      <div class="row" style="margin-bottom:8px; align-items:center; gap:8px">
        <button class="navBtn" id="resultsPrevBtn" type="button">← Prev</button>
        <button class="navBtn" id="resultsNextBtn" type="button">Next →</button>
        <span class="muted" id="resultsPageMeta">Page 1</span>
      </div>
      <div style="overflow:auto">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Email</th>
              <th>OK</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody id="results"></tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h3 style="margin:0 0 10px">Logs (last 80)</h3>
      <div id="logs" class="muted" style="white-space:pre-wrap; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px"></div>
    </div>
  </div>

<script>
  const jobId = "{{job_id}}";
  const RESULTS_PAGE_SIZE = 100;
  let resultsPage = 1;
  let resultsTotalPages = 1;
  function esc(s){ return (s ?? "").toString().replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;"); }

  function pct(n,d){
    const nn = Number(n||0), dd = Number(d||0);
    return dd ? Math.min(100, Math.round((nn/dd)*100)) : 0;
  }

  function renderResultsPager(){
    const meta = document.getElementById('resultsPageMeta');
    const prevBtn = document.getElementById('resultsPrevBtn');
    const nextBtn = document.getElementById('resultsNextBtn');
    const total = Number(resultsTotalPages || 1);
    const page = Number(resultsPage || 1);
    if(meta) meta.textContent = `Page ${page} / ${total} · ${RESULTS_PAGE_SIZE} emails per page`;
    if(prevBtn) prevBtn.disabled = page <= 1;
    if(nextBtn) nextBtn.disabled = page >= total;
  }

  async function tick(){
    const qp = new URLSearchParams({
      recent_page: String(resultsPage),
      recent_page_size: String(RESULTS_PAGE_SIZE),
    });
    const r = await fetch(`/api/job/${jobId}?${qp.toString()}`);
    if(!r.ok){ return; }
    const j = await r.json();

    document.getElementById("total").textContent = j.total;
    document.getElementById("sent").textContent = j.sent;
    document.getElementById("failed").textContent = j.failed;
    document.getElementById("skipped").textContent = j.skipped;
    document.getElementById("invalid").textContent = j.invalid;

    const chunkStates = Array.isArray(j.chunk_states) ? j.chunk_states : [];
    const latestChunkStatus = new Map();
    for(const x of chunkStates){
      const cidx = Number(x && x.chunk);
      if(Number.isFinite(cidx)) latestChunkStatus.set(cidx, (x.status || '').toString().toLowerCase());
    }
    const allChunksBackoff = latestChunkStatus.size > 0 && Array.from(latestChunkStatus.values()).every(s => s === 'backoff');
    const statusShown = (j.status === 'running' && allChunksBackoff) ? 'backoff' : j.status;

    document.getElementById("statusPill").textContent = `Status: ${statusShown}`;
    document.getElementById("lastError").textContent = j.last_error ? ("Last error: " + j.last_error) : "";

    const denom = (j.total || 0);
    const done = (j.sent + j.failed + j.skipped);
    document.getElementById("barFill").style.width = pct(done, denom) + "%";

    // Domain state
    const plan = j.domain_plan || {};
    const sentMap = j.domain_sent || {};
    const failMap = j.domain_failed || {};

    const rows = Object.entries(plan).map(([dom, planned]) => {
      const p = Number(planned||0);
      const s = Number(sentMap[dom]||0);
      const f = Number(failMap[dom]||0);
      const done2 = s + f;
      return {dom, p, s, f, done2, pct: pct(done2, p)};
    }).sort((a,b)=>b.p-a.p).slice(0, 300);

    const domainStateMap = new Map();
    for(const x of chunkStates){
      const rd = (x.receiver_domain || '').toString().trim().toLowerCase();
      if(!rd) continue;
      const st = (x && x.status ? x.status : '').toString().trim().toLowerCase();
      domainStateMap.set(rd, st);
    }
    const domBody = document.getElementById('domState');
    if(domBody){
      domBody.innerHTML = rows.map(x => {
        const bar = `<div class="smallBar"><div style="width:${x.pct}%"></div></div>`;
        const domKey = (x.dom || '').toString().trim().toLowerCase();
        const showBackoff = domainStateMap.get(domKey) === 'backoff' && x.done2 < x.p;
        const domLabel = showBackoff ? `${esc(x.dom)} <span class="no">(backoff)</span>` : esc(x.dom);
        return `<tr>`+
          `<td>${domLabel}</td>`+
          `<td>${x.p}</td>`+
          `<td class="ok">${x.s}</td>`+
          `<td class="no">${x.f}</td>`+
          `<td>${bar}<div class="muted" style="font-size:12px; margin-top:4px">${x.done2}/${x.p} (${x.pct}%)</div></td>`+
        `</tr>`;
      }).join('') || `<tr><td colspan="5" class="muted">No domains yet.</td></tr>`;
    }

    const totalPlanned = Object.values(plan).reduce((a,v)=>a+Number(v||0),0);
    const totalDone = rows.reduce((a,x)=>a+Number(x.done2||0),0);
    const dp = pct(totalDone, totalPlanned);
    const domFill = document.getElementById('domBarFill');
    const domTxt = document.getElementById('domBarText');
    if(domFill) domFill.style.width = dp + '%';
    if(domTxt) domTxt.textContent = `Domains progress: ${dp}% (${totalDone}/${totalPlanned})`;

    // Chunk state
    const chunkMeta = document.getElementById('chunkMeta');
    if(chunkMeta){
      chunkMeta.textContent = `chunks_done=${j.chunks_done || 0} · chunks_total≈${j.chunks_total || 0} · backoff_events=${j.chunks_backoff || 0} · current_chunk=${(j.current_chunk ?? -1)}`;
    }

    const chunkTbl = document.getElementById('chunkTbl');
    const cs = chunkStates.slice().reverse();
    if(chunkTbl){
      chunkTbl.innerHTML = cs.map(x => {
        const next = x.next_retry_ts ? new Date(Number(x.next_retry_ts)*1000).toLocaleTimeString() : '';
        const bl = (x.blacklist || '').toString();
        const blShort = bl.length > 40 ? (bl.slice(0,40) + '…') : bl;
        const spam = (x.spam_score === null || x.spam_score === undefined) ? '' : Number(x.spam_score).toFixed(2);
        return `<tr>`+
          `<td>${Number(x.chunk)+1}</td>`+
          `<td>${esc(x.status || '')}</td>`+
          `<td>${Number(x.size||0)}</td>`+
          `<td>${esc(x.sender || '')}</td>`+
          `<td>${esc(spam)}</td>`+
          `<td title="${esc(bl)}">${esc(blShort)}</td>`+
          `<td>${esc(String(x.attempt ?? ''))}</td>`+
          `<td>${esc(next)}</td>`+
        `</tr>`;
      }).join('') || `<tr><td colspan="8" class="muted">No chunk states yet.</td></tr>`;
    }

    // Recent results (paginated at API level)
    resultsPage = Number(j.recent_page || 1);
    resultsTotalPages = Number(j.recent_total_pages || 1);
    const rrows = (j.recent_results || []).map(x => {
      const ok = x.ok ? '<span class="ok">YES</span>' : '<span class="no">NO</span>';
      return `<tr><td>${esc(x.ts)}</td><td>${esc(x.email)}</td><td>${ok}</td><td>${esc(x.detail)}</td></tr>`;
    }).join("");
    document.getElementById("results").innerHTML = rrows || `<tr><td colspan="4" class="muted">No results yet...</td></tr>`;
    renderResultsPager();

    // Logs
    const logs = (j.logs || []).slice(-80).map(l => `[${l.ts}] ${l.level}: ${l.message}`).join("\n");
    document.getElementById("logs").textContent = logs;

    if(j.status === "done" || j.status === "error"){
      clearInterval(window._t);
      window._t = setInterval(tick, 3500);
    }
  }

  const prevBtn = document.getElementById('resultsPrevBtn');
  if(prevBtn){
    prevBtn.addEventListener('click', async () => {
      if(resultsPage <= 1) return;
      resultsPage -= 1;
      await tick();
    });
  }

  const nextBtn = document.getElementById('resultsNextBtn');
  if(nextBtn){
    nextBtn.addEventListener('click', async () => {
      if(resultsPage >= resultsTotalPages) return;
      resultsPage += 1;
      await tick();
    });
  }

  const extractShivaSentBtn = document.getElementById('extractShivaSentBtn');
  if(extractShivaSentBtn){
    extractShivaSentBtn.addEventListener('click', () => {
      window.location.href = `/api/job/${jobId}/extract/shiva-sent`;
    });
  }

  const extractPmtaDeliveredBtn = document.getElementById('extractPmtaDeliveredBtn');
  if(extractPmtaDeliveredBtn){
    extractPmtaDeliveredBtn.addEventListener('click', () => {
      window.location.href = `/api/job/${jobId}/extract/pmta-delivered`;
    });
  }

  renderResultsPager();
  tick();
  window._t = setInterval(tick, 1200);
</script>
</body>
</html>
"""

# =========================
# SMTP Helpers
# =========================

def smtp_test_connection(
    smtp_host: str,
    smtp_port: int,
    smtp_security: str,  # starttls | ssl | none
    smtp_timeout: int,
    smtp_user: str,
    smtp_pass: str,
) -> dict:
    """Test connect + optional auth. Does NOT send emails."""
    t0 = time.perf_counter()
    server = None
    steps: List[str] = []
    try:
        if smtp_security == "ssl":
            steps.append("connect:ssl")
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=smtp_timeout, context=context)
        else:
            steps.append("connect:plain")
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=smtp_timeout)
            server.ehlo()
            steps.append("ehlo")
            if smtp_security == "starttls":
                steps.append("starttls")
                context = ssl.create_default_context()
                server.starttls(context=context)
                server.ehlo()
                steps.append("ehlo2")

        # Optional auth
        if smtp_user and smtp_pass:
            steps.append("auth")
            server.login(smtp_user, smtp_pass)
            steps.append("auth_ok")
        else:
            steps.append("auth_skipped")

        # Optional NOOP
        try:
            server.noop()
            steps.append("noop")
        except Exception:
            pass

        ms = int((time.perf_counter() - t0) * 1000)
        detail = "Connected OK"
        if smtp_security == "starttls":
            detail = "Connected + STARTTLS OK"
        if smtp_security == "ssl":
            detail = "Connected (SSL/TLS) OK"
        if smtp_user and smtp_pass:
            detail += " + AUTH OK"

        return {
            "ok": True,
            "detail": detail,
            "time_ms": ms,
            "steps": steps,
        }

    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        return {
            "ok": False,
            "error": str(e),
            "time_ms": ms,
            "steps": steps,
        }
    finally:
        try:
            if server:
                server.quit()
        except Exception:
            pass


# =========================
# Spam score helper
# =========================

_SPAM_LINE_RE = re.compile(r"^Spam:[ 	]*(True|False)[ 	]*;[ 	]*([-0-9.]+)[ 	]*/[ 	]*([-0-9.]+)", re.IGNORECASE)
_X_STATUS_RE = re.compile(r"score=([-0-9.]+)", re.IGNORECASE)


def _build_spam_test_message(*, subject: str, body: str, body_format: str, from_email: str) -> bytes:
    # Build a realistic raw message for scoring.
    msg = EmailMessage()
    msg["From"] = from_email or "sender@example.com"
    msg["To"] = "test@example.com"
    msg["Subject"] = subject
    msg["Date"] = format_datetime(datetime.now(timezone.utc))
    # Message-ID is useful for tracing in PMTA/accounting.
    # Keep it self-contained (no external variables).
    msg["Message-ID"] = f"<{uuid.uuid4().hex}@local>"

    if body_format == "html":
        msg.set_content("This email contains HTML content.")
        msg.add_alternative(body, subtype="html")
    else:
        msg.set_content(body)

    return msg.as_bytes(policy=email_policy.SMTP)


def _score_via_spamd(raw_msg: bytes) -> Tuple[Optional[float], str]:
    """Talk directly to spamd (SpamAssassin daemon)."""
    # spamd prefers CRLF; convert LF -> CRLF
    LF = bytes([10])
    CRLF = bytes([13, 10])
    payload = raw_msg.replace(LF, CRLF)

    header = b"REPORT SPAMC/1.5" + CRLF
    header += b"Content-length: " + str(len(payload)).encode("ascii") + CRLF
    header += CRLF

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(SPAMD_TIMEOUT)
    try:
        s.connect((SPAMD_HOST, SPAMD_PORT))
        s.sendall(header)
        s.sendall(payload)

        chunks: List[bytes] = []
        while True:
            try:
                b = s.recv(4096)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)

        data = b"".join(chunks)
        text = data.decode("utf-8", errors="ignore")

        for line in text.splitlines():
            m = _SPAM_LINE_RE.match(line.strip())
            if m:
                score = float(m.group(2))
                # Keep report concise
                return score, text[:1800].strip()

        return None, "spamd: could not parse response"
    except Exception as e:
        return None, f"spamd error: {e} (host={SPAMD_HOST} port={SPAMD_PORT})"
    finally:
        try:
            s.close()
        except Exception:
            pass


def _score_via_spamc_cli(raw_msg: bytes) -> Tuple[Optional[float], str]:
    """Use spamc CLI (client for spamd) if installed."""
    try:
        # -c prints: "score/required" and exits.
        p = subprocess.run(
            ["spamc", "-c"],
            input=raw_msg,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=SPAMD_TIMEOUT,
        )
        out = p.stdout.decode("utf-8", errors="ignore").strip()
        # expected: "2.3/5.0"
        if "/" in out:
            left = out.split("/", 1)[0].strip()
            try:
                return float(left), "spamc(-c) => " + out
            except Exception:
                pass
        return None, "spamc: could not parse output: " + out[:220]
    except FileNotFoundError:
        return None, "spamc CLI not found"
    except Exception as e:
        return None, "spamc error: " + str(e)



def _score_via_spamassassin_cli(raw_msg: bytes) -> Tuple[Optional[float], str]:
    """Run spamassassin CLI if installed."""
    try:
        p = subprocess.run(
            ["spamassassin", "-t"],
            input=raw_msg,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=SPAMD_TIMEOUT,
        )
        out = p.stdout.decode("utf-8", errors="ignore")

        for line in out.splitlines():
            if line.lower().startswith("x-spam-status:"):
                m = _X_STATUS_RE.search(line)
                if m:
                    return float(m.group(1)), out[:1800].strip()

        m2 = _X_STATUS_RE.search(out)
        if m2:
            return float(m2.group(1)), out[:1800].strip()

        return None, "spamassassin: could not parse output"
    except FileNotFoundError:
        return None, "spamassassin CLI not found"
    except Exception as e:
        return None, f"spamassassin error: {e}"


def _score_via_module(subject: str, body: str, msg_string: str) -> Tuple[Optional[float], str]:
    """Try python module `spamcheck` (best-effort).

    Preferred API (your example):
      spamcheck.check(msg_string, report=True) -> {'score': <num>, 'report': <text>}
    """
    if spamcheck is None:
        return None, "spamcheck module not available"

    # 1) Preferred API: spamcheck.check(msg_string, report=True)
    fn_check = getattr(spamcheck, "check", None)
    if callable(fn_check):
        try:
            res = fn_check(msg_string, report=True)
            if isinstance(res, dict):
                s = res.get("score")
                rep = res.get("report", res.get("detail", ""))
                if s is not None:
                    return float(s), str(rep or "")
            if isinstance(res, (int, float)):
                return float(res), ""
            if isinstance(res, (list, tuple)) and res:
                try:
                    return float(res[0]), " ".join(str(x) for x in res[1:])
                except Exception:
                    return None, str(res)
        except Exception as e:
            return None, f"spamcheck.check error: {e}"

    # 2) Fallback: introspect other possible APIs
    def interpret(res: Any) -> Tuple[Optional[float], str]:
        if res is None:
            return None, "no result"
        if isinstance(res, (int, float)):
            return float(res), ""
        if isinstance(res, dict):
            s = res.get("score", res.get("spam_score", res.get("total")))
            detail = res.get("detail", res.get("report", res.get("reason", "")))
            try:
                return (float(s) if s is not None else None), str(detail or "")
            except Exception:
                return None, str(detail or "")
        if isinstance(res, (list, tuple)) and res:
            try:
                return float(res[0]), " ".join(str(x) for x in res[1:])
            except Exception:
                return None, str(res)
        try:
            return float(str(res).strip()), ""
        except Exception:
            return None, f"unrecognized result type: {type(res).__name__}"

    def try_call(fn: Any) -> Any:
        # Try common calling styles
        for attempt in (
            lambda: fn(msg_string, report=True),
            lambda: fn(msg_string),
            lambda: fn(subject=subject, body=body),
            lambda: fn(subject, body),
            lambda: fn({"subject": subject, "body": body}),
        ):
            try:
                return attempt()
            except TypeError:
                continue
        return None

    for name in ("score", "check", "run", "evaluate", "spam_score", "get_score"):
        fn = getattr(spamcheck, name, None)
        if callable(fn):
            try:
                return interpret(try_call(fn))
            except Exception as e:
                return None, f"spamcheck.{name} error: {e}"

    return None, "spamcheck module loaded but no known scoring function found"


def compute_spam_score(*, subject: str, body: str, body_format: str, from_email: str) -> Tuple[Optional[float], str]:
    """Compute a SpamAssassin-style score.

    Backends:
      - spamd (direct TCP)
      - spamc (CLI client for spamd)
      - spamassassin (CLI)
      - spamcheck module (python)

    NOTE: This must be syntactically valid (no raw newlines inside string literals).
    """
    if SPAMCHECK_BACKEND == "off":
        return None, "spam scoring disabled"

    raw = _build_spam_test_message(subject=subject, body=body, body_format=body_format, from_email=from_email)
    # For python module spamcheck.check(msg.as_string()), we provide a string too.
    msg_string = raw.decode("utf-8", errors="ignore")

    # Try selected backend first
    if SPAMCHECK_BACKEND == "spamd":
        s, d = _score_via_spamd(raw)
        if s is not None:
            return s, "backend=spamd\n" + d

    elif SPAMCHECK_BACKEND == "spamc":
        s, d = _score_via_spamc_cli(raw)
        if s is not None:
            return s, "backend=spamc\n" + d

    elif SPAMCHECK_BACKEND == "spamassassin":
        s, d = _score_via_spamassassin_cli(raw)
        if s is not None:
            return s, "backend=spamassassin\n" + d

    elif SPAMCHECK_BACKEND == "module":
        s, d = _score_via_module(subject, body, msg_string)
        if s is not None:
            return s, "backend=spamcheck-module\n" + d

    # Fallback order
    s, d = _score_via_spamd(raw)
    if s is not None:
        return s, "backend=spamd\n" + d

    s, d = _score_via_spamc_cli(raw)
    if s is not None:
        return s, "backend=spamc\n" + d

    s, d = _score_via_spamassassin_cli(raw)
    if s is not None:
        return s, "backend=spamassassin\n" + d

    s, d = _score_via_module(subject, body, msg_string)
    if s is not None:
        return s, "backend=spamcheck-module\n" + d

    return None, d


# =========================
# Reputation / Blacklist (DNSBL)
# =========================
# Your JS example was scraping sites via CORS proxies.
# Here we do it server-side using DNSBL lookups (no CORS issues).
#
# Configure zones (comma-separated):
#   RBL_ZONES=zen.spamhaus.org,bl.spamcop.net,cbl.abuseat.org
#   DBL_ZONES=dbl.spamhaus.org
# You can disable either list by setting it to empty.

_RBL_ZONES_RAW = (os.getenv("RBL_ZONES") or "zen.spamhaus.org,bl.spamcop.net,cbl.abuseat.org").strip()
_DBL_ZONES_RAW = (os.getenv("DBL_ZONES") or "dbl.spamhaus.org").strip()
SEND_DNSBL = (os.getenv("SEND_DNSBL") or "1").strip().lower() in {"1", "true", "yes", "on"}


def _parse_zones(raw: str) -> List[str]:
    out: List[str] = []
    for part in (raw or "").split(","):
        z = (part or "").strip().lower().strip(".")
        if not z:
            continue
        if z not in out:
            out.append(z)
    return out


RBL_ZONES_LIST = _parse_zones(_RBL_ZONES_RAW)
DBL_ZONES_LIST = _parse_zones(_DBL_ZONES_RAW)


def _is_ipv4(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return s.count(".") == 3
    except Exception:
        return False


def _resolve_ipv4(host: str) -> List[str]:
    host = (host or "").strip()
    if not host:
        return []
    if _is_ipv4(host):
        return [host]
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        # keep ipv4 only
        out = []
        seen = set()
        for ip in ips or []:
            if _is_ipv4(ip) and ip not in seen:
                seen.add(ip)
                out.append(ip)
        return out
    except Exception:
        return []


def _reverse_ipv4(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def _dns_a_lookup(name: str) -> Optional[str]:
    # Return A record if exists, else None
    try:
        return socket.gethostbyname(name)
    except Exception:
        return None


def check_ip_dnsbl(ip: str) -> List[dict]:
    """Return a list of {'zone': zone, 'answer': a} where listed."""
    if not _is_ipv4(ip):
        return []
    rev = _reverse_ipv4(ip)
    listed: List[dict] = []
    for zone in RBL_ZONES_LIST:
        q = f"{rev}.{zone}"
        a = _dns_a_lookup(q)
        if a:
            listed.append({"zone": zone, "answer": a})
    return listed


def _extract_domain_from_email(email: str) -> str:
    e = (email or "").strip().lower()
    if "@" not in e:
        return ""
    dom = e.split("@", 1)[1].strip().strip(".")
    return dom


def check_domain_dnsbl(domain: str) -> List[dict]:
    """Return a list of {'zone': zone, 'answer': a} where listed (DBL-style)."""
    d = (domain or "").strip().lower().strip(".")
    if not d:
        return []
    listed: List[dict] = []
    for zone in DBL_ZONES_LIST:
        q = f"{d}.{zone}"
        a = _dns_a_lookup(q)
        if a:
            listed.append({"zone": zone, "answer": a})
    return listed


def domain_mail_route(domain: str) -> dict:
    """Best-effort mail route check using MX + A fallback.

    Returns dict:
      {
        'domain': str,
        'status': 'mx' | 'a_fallback' | 'none' | 'unknown',
        'mx_hosts': List[str]
      }

    Rules:
    - If MX exists -> status=mx.
    - If no MX but A exists -> status=a_fallback (some MTAs deliver to A per RFC fallback).
    - If neither MX nor A -> status=none.
    - If DNS queries fail (timeouts) -> status=unknown.
    """
    d = (domain or "").strip().lower().strip(".")
    if not d:
        return {"domain": d, "status": "none", "mx_hosts": []}

    now_ts = time.time()
    exp = float(_MX_CACHE_EXPIRES_AT.get(d, 0.0) or 0.0)
    if d in _MX_CACHE and exp > now_ts:
        return _MX_CACHE[d]
    if d in _MX_CACHE and exp <= now_ts:
        _MX_CACHE.pop(d, None)
        _MX_CACHE_EXPIRES_AT.pop(d, None)

    def _cache_and_return(out: dict) -> dict:
        ttl = MX_CACHE_TTL_OK if out.get("status") in {"mx", "a_fallback"} else MX_CACHE_TTL_SOFT_FAIL
        _MX_CACHE[d] = out
        _MX_CACHE_EXPIRES_AT[d] = time.time() + float(ttl)
        return out

    mx_hosts: List[str] = []

    # If dnspython is available, use it.
    if DNS_RESOLVER is not None:
        try:
            ans = DNS_RESOLVER.resolve(d, "MX")  # type: ignore
            for r in ans:
                exch = str(getattr(r, "exchange", "")).rstrip(".")
                if exch:
                    mx_hosts.append(exch)
            if mx_hosts:
                out = {"domain": d, "status": "mx", "mx_hosts": mx_hosts[:8]}
                return _cache_and_return(out)
        except Exception as e:
            # If clearly no MX, we'll check A fallback below.
            msg = str(e).lower()
            # Treat timeouts/servfail as unknown.
            if "timeout" in msg or "servfail" in msg or "refused" in msg:
                out = {"domain": d, "status": "unknown", "mx_hosts": []}
                return _cache_and_return(out)

        # A fallback
        try:
            a = DNS_RESOLVER.resolve(d, "A")  # type: ignore
            has_a = any(str(x) for x in a)
            out = {"domain": d, "status": ("a_fallback" if has_a else "none"), "mx_hosts": []}
            return _cache_and_return(out)
        except Exception as e:
            msg = str(e).lower()
            if "timeout" in msg or "servfail" in msg or "refused" in msg:
                out = {"domain": d, "status": "unknown", "mx_hosts": []}
                return _cache_and_return(out)
            out = {"domain": d, "status": "none", "mx_hosts": []}
            return _cache_and_return(out)

    # Fallback without dnspython: do not hard-fail; try A resolution only.
    try:
        _ = socket.gethostbyname(d)
        out = {"domain": d, "status": "a_fallback", "mx_hosts": []}
        return _cache_and_return(out)
    except Exception:
        out = {"domain": d, "status": "unknown", "mx_hosts": []}
        return _cache_and_return(out)


def filter_emails_by_mx(emails: List[str]) -> Tuple[List[str], List[str], dict]:
    """Filter emails by domain MX/A existence (best-effort).

    Returns:
      ok_emails, bad_emails, meta

    meta includes per-domain route status.
    """
    ok: List[str] = []
    bad: List[str] = []
    meta: dict = {"domains": {}}

    for e in emails:
        d = _extract_domain_from_email(e)
        if not d:
            bad.append(e)
            continue

        r = domain_mail_route(d)
        meta["domains"][d] = r

        # Only hard-reject when status is 'none'.
        if r.get("status") == "none":
            bad.append(e)
        else:
            ok.append(e)

    return ok, bad, meta


def _smtp_rcpt_probe(email: str, route: dict) -> dict:
    """Best-effort SMTP RCPT probe (no DATA).

    Notes:
    - Not all providers allow RCPT verification before DATA.
    - Catch-all domains may return accepted for any user.
    """
    rcpt = (email or "").strip().lower()
    dom = _extract_domain_from_email(rcpt)
    hosts = list(route.get("mx_hosts") or [])
    host = hosts[0] if hosts else dom
    if not host:
        return {"ok": False, "code": 0, "detail": "no_host"}

    server = None
    try:
        server = smtplib.SMTP(host=host, port=25, timeout=float(RECIPIENT_FILTER_SMTP_TIMEOUT or 5.0))
        server.ehlo_or_helo_if_needed()
        server.mail("<>")
        code, detail = server.rcpt(rcpt)
        text = ""
        if isinstance(detail, bytes):
            text = detail.decode("utf-8", errors="ignore")
        else:
            text = str(detail or "")

        # accepted / cannot-verify-yet
        if int(code or 0) in {250, 251, 252}:
            return {"ok": True, "code": int(code or 0), "detail": text[:220], "host": host}
        return {"ok": False, "code": int(code or 0), "detail": text[:220], "host": host}
    except Exception as e:
        return {"ok": False, "code": 0, "detail": str(e)[:220], "host": host}
    finally:
        try:
            if server is not None:
                server.quit()
        except Exception:
            pass


def pre_send_recipient_filter(emails: List[str], *, smtp_probe: bool = True) -> Tuple[List[str], List[str], dict]:
    """Pre-send recipient filter with syntax/domain checks + optional SMTP probes."""
    ok: List[str] = []
    bad: List[str] = []

    report: Dict[str, Any] = {
        "enabled": True,
        "checks": ["syntax", "mx_or_a"],
        "smtp_probe": bool(smtp_probe and RECIPIENT_FILTER_ENABLE_SMTP_PROBE),
        "smtp_probe_limit": int(max(0, RECIPIENT_FILTER_SMTP_PROBE_LIMIT or 0)),
        "smtp_probe_used": 0,
        "rejected": {"no_route": 0, "smtp": 0},
        "domains": {},
    }

    seen_domain_probe: Set[str] = set()

    for e in emails or []:
        em = (e or "").strip()
        d = _extract_domain_from_email(em)
        if not d:
            bad.append(em)
            continue

        route = domain_mail_route(d)
        status = route.get("status", "unknown")
        report["domains"][d] = route

        if status == "none":
            bad.append(em)
            report["rejected"]["no_route"] += 1
            continue

        do_probe = (
            report["smtp_probe"]
            and status in {"mx", "a_fallback"}
            and d not in seen_domain_probe
            and int(report["smtp_probe_used"] or 0) < int(report["smtp_probe_limit"] or 0)
        )
        if do_probe:
            probe = _smtp_rcpt_probe(em, route)
            seen_domain_probe.add(d)
            report["smtp_probe_used"] = int(report["smtp_probe_used"] or 0) + 1
            report["domains"][d] = {**route, "smtp_probe": probe}
            if not probe.get("ok") and int(probe.get("code") or 0) >= 500:
                bad.append(em)
                report["rejected"]["smtp"] += 1
                continue

        ok.append(em)

    report["kept"] = len(ok)
    report["dropped"] = len(bad)
    return ok, bad, report


def resolve_sender_domain_ips(domain: str) -> List[str]:
    """Resolve IPv4 addresses for a sending domain.

    Goal: show the IP(s) that are actually linked to the *mail* infra for the sender domain.

    Priority:
      1) MX records (if dnspython is installed)
      2) A records for: root domain, mail.<domain>, smtp.<domain>

    Examples:
      support@mediapaypro.info -> mediapaypro.info
    """
    d = (domain or "").strip().lower().strip(".")
    if not d:
        return []

    out: List[str] = []
    seen: Set[str] = set()

    # 1) MX -> resolve exchange hostnames to IPv4
    try:
        if dns is not None:  # type: ignore
            answers = dns.resolver.resolve(d, "MX")  # type: ignore
            for r in answers:
                exch = str(getattr(r, "exchange", "")).rstrip(".")
                if not exch:
                    continue
                for ip in _resolve_ipv4(exch):
                    if ip not in seen:
                        seen.add(ip)
                        out.append(ip)
    except Exception:
        pass

    # 2) Common hostnames (fallback)
    for h in (d, f"mail.{d}", f"smtp.{d}"):
        for ip in _resolve_ipv4(h):
            if ip not in seen:
                seen.add(ip)
                out.append(ip)

    return out


def db_mark_job_recipient(job_id: str, campaign_id: str, rcpt: str) -> None:
    jid = (job_id or "").strip().lower()
    cid = (campaign_id or "").strip()
    em = (rcpt or "").strip().lower()
    if not jid or not em:
        return
    ts = now_iso()
    with DB_LOCK:
        conn = _db_conn()
        try:
            try:
                conn.execute(
                    "INSERT INTO job_recipients(job_id, campaign_id, rcpt, first_seen_at, last_seen_at) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(job_id, rcpt) DO UPDATE SET campaign_id=excluded.campaign_id, last_seen_at=excluded.last_seen_at",
                    (jid, cid, em, ts, ts),
                )
            except sqlite3.OperationalError as e:
                # Backward-compat for older SQLite builds that don't support UPSERT.
                if "near \"ON\"" not in str(e):
                    raise
                cur = conn.execute(
                    "UPDATE job_recipients SET campaign_id=?, last_seen_at=? WHERE job_id=? AND rcpt=?",
                    (cid, ts, jid, em),
                )
                if cur.rowcount == 0:
                    conn.execute(
                        "INSERT INTO job_recipients(job_id, campaign_id, rcpt, first_seen_at, last_seen_at) VALUES(?,?,?,?,?)",
                        (jid, cid, em, ts, ts),
                    )
            conn.commit()
        finally:
            conn.close()


def db_find_job_ids_by_recipient(rcpt: str, limit: int = 8) -> List[str]:
    em = (rcpt or "").strip().lower()
    if not em:
        return []
    lim = max(1, min(int(limit or 1), 50))
    with DB_LOCK:
        conn = _db_conn()
        try:
            rows = conn.execute(
                "SELECT job_id FROM job_recipients WHERE rcpt=? ORDER BY last_seen_at DESC LIMIT ?",
                (em, lim),
            ).fetchall()
            return [str(r[0]).strip().lower() for r in (rows or []) if r and str(r[0]).strip()]
        except Exception:
            return []
        finally:
            conn.close()


# =========================
# PowerMTA Monitoring (optional)
# =========================
# If you run PowerMTA, you can health-check it via the Web Monitor / HTTP Monitoring API before creating a send job.
# This prevents starting jobs while PowerMTA is down or overloaded.
#
# Enable (recommended explicit):
#   # Derived from SMTP Host automatically (no need to set PMTA_MONITOR_BASE_URL):
#   PMTA monitor base = http://<smtp_host>:8080
# Optional:
#   PMTA_MONITOR_TIMEOUT_S=3
#   PMTA_MONITOR_API_KEY=... (if you enabled http-api-key)
#   PMTA_HEALTH_REQUIRED=1 (block if monitor unreachable) or 0 (warn-only)
try:
    PMTA_MONITOR_TIMEOUT_S = float((os.getenv("PMTA_MONITOR_TIMEOUT_S", "3") or "3").strip())
except Exception:
    PMTA_MONITOR_TIMEOUT_S = 3.0

# PMTA monitor base URL / scheme
# - Some PMTA builds force HTTPS on :8080 (HTTP returns: "Please use HTTPS instead").
# - Use PMTA_MONITOR_SCHEME=auto|https|http (auto defaults to https-first).
# - Or override fully with PMTA_MONITOR_BASE_URL (e.g. https://194.116.172.135:8080)
PMTA_MONITOR_BASE_URL = (os.getenv("PMTA_MONITOR_BASE_URL", "") or "").strip()
PMTA_MONITOR_SCHEME = (os.getenv("PMTA_MONITOR_SCHEME", "auto") or "auto").strip().lower()
if PMTA_MONITOR_SCHEME not in {"auto", "http", "https"}:
    PMTA_MONITOR_SCHEME = "auto"

PMTA_MONITOR_API_KEY = (os.getenv("PMTA_MONITOR_API_KEY", "") or "").strip()
PMTA_HEALTH_REQUIRED = (os.getenv("PMTA_HEALTH_REQUIRED", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}


def _pmta_norm_base(base: str) -> str:
    b = (base or "").strip()
    if not b:
        return ""
    # Remove UI suffix if someone pasted it
    for suf in ("/ui", "/ui/", "/ui/index.html"):
        if b.endswith(suf):
            b = b[: -len(suf)]
    return b.rstrip("/")


def _pmta_base_from_smtp_host(smtp_host: str) -> str:
    """Build PMTA monitor base URL from SMTP host.

    Examples:
      smtp_host="194.116.172.135"       -> http://194.116.172.135:8080
      smtp_host="mail.example.com"      -> http://mail.example.com:8080
      smtp_host="http://x.y.z:2525"     -> http://x.y.z:8080

    Notes:
    - Strips scheme/path/port if user pasted them by mistake.
    - Removes trailing /ui if present.
    """
    h = (smtp_host or "").strip()
    if not h:
        return ""

    # If someone pasted a URL, try to parse hostname
    if "://" in h:
        try:
            from urllib.parse import urlparse
            u = urlparse(h)
            h = (u.hostname or "").strip()
        except Exception:
            h = h.split("://", 1)[-1]

    # Drop any path
    h = h.split("/", 1)[0].strip()

    # Drop port if included as host:port (IPv4/hostname)
    if h and (":" in h) and (not h.startswith("[")):
        h = h.split(":", 1)[0].strip()

    if not h:
        return ""

    # Explicit override (monitor host may differ from smtp_host)
    if (PMTA_MONITOR_BASE_URL or "").strip():
        return _pmta_norm_base(PMTA_MONITOR_BASE_URL)

    scheme = (PMTA_MONITOR_SCHEME or "auto").strip().lower()
    if scheme == "http":
        return _pmta_norm_base(f"http://{h}:8080")

    # Default: https (works with PMTA builds that refuse plain HTTP)
    return _pmta_norm_base(f"https://{h}:8080")


def _pmta_headers() -> dict:
    h = {"Accept": "application/json"}
    if PMTA_MONITOR_API_KEY:
        # Common pattern: pmta uses http-api-key -> header X-API-Key
        h["X-API-Key"] = PMTA_MONITOR_API_KEY
    return h


def _dict_get_ci(d: Any, *names: str) -> Any:
    """Case-insensitive dict getter.

    PMTA's JSON field names vary by version (and sometimes casing differs).
    """
    if not isinstance(d, dict):
        return None
    lower = {str(k).strip().lower(): k for k in d.keys()}
    for n in names:
        kk = str(n).strip().lower()
        if kk in lower:
            return d.get(lower[kk])
    return None


def _pmta_has_any_counts(pm: dict) -> bool:
    if not isinstance(pm, dict):
        return False
    for k in ("spool_recipients", "spool_messages", "queued_recipients", "queued_messages", "active_connections"):
        v = pm.get(k)
        if v is not None:
            return True
    return False


def _http_get_json(url: str, *, timeout_s: float) -> Tuple[bool, dict, str]:
    """Fetch JSON from a URL with best-effort handling for PMTA monitor setups.

    Why this exists:
    - Some deployments redirect HTTP -> HTTPS.
    - Some HTTPS endpoints use old/self-signed certs or weak keys (e.g., 1024-bit),
      which can fail with: CERTIFICATE_VERIFY_FAILED / certificate key too weak.

    Strategy:
    1) Try strict/default.
    2) If we hit an SSL verify / weak-key error, retry with an unverified SSL context
       and a lower OpenSSL security level (SECLEVEL=1) to allow weak keys.

    NOTE: The retry is only used for the PMTA monitor calls (internal monitoring). If you
    want a fully secure setup, fix the PMTA HTTPS cert (use RSA-2048+), or keep monitor on HTTP.
    """

    def _attempt(ctx: Optional[ssl.SSLContext]) -> Tuple[bool, dict, str]:
        try:
            req = Request(url, headers=_pmta_headers(), method="GET")
            if ctx is None:
                with urlopen(req, timeout=timeout_s) as resp:
                    raw = resp.read().decode("utf-8", errors="ignore")
            else:
                with urlopen(req, timeout=timeout_s, context=ctx) as resp:
                    raw = resp.read().decode("utf-8", errors="ignore")
            try:
                return True, json.loads(raw or "{}"), ""
            except Exception as e:
                return False, {}, f"invalid JSON: {e}"
        except HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return False, {}, f"HTTPError {getattr(e, 'code', '')} {body[:220]}"
        except URLError as e:
            return False, {}, f"URLError: {e}"
        except Exception as e:
            return False, {}, str(e)

    ok, js, err = _attempt(None)
    if ok:
        return ok, js, err

    # Retry for SSL/cert issues (often caused by HTTP->HTTPS redirects or weak/self-signed certs)
    err_l = (err or "").lower()
    if ("certificate_verify_failed" in err_l) or ("key too weak" in err_l) or ("ssl:" in err_l):
        try:
            ctx = ssl._create_unverified_context()
            # Allow weaker keys on some servers (OpenSSL security level)
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
            except Exception:
                pass
            ok2, js2, err2 = _attempt(ctx)
            if ok2:
                return ok2, js2, err2
            # If retry failed, include both errors for clarity
            return False, {}, f"{err} (retry insecure failed: {err2})"
        except Exception as e:
            return False, {}, f"{err} (retry insecure failed: {e})"

    return ok, js, err


def _http_get_text(url: str, *, timeout_s: float) -> Tuple[bool, str, str, dict]:
    """Fetch raw text + metadata from PMTA monitor endpoints (debug/probing)."""

    def _attempt(ctx: Optional[ssl.SSLContext]) -> Tuple[bool, str, str, dict]:
        try:
            req = Request(url, headers=_pmta_headers(), method="GET")
            if ctx is None:
                with urlopen(req, timeout=timeout_s) as resp:
                    raw_b = resp.read()
                    meta = {
                        "status": getattr(resp, "status", None),
                        "final_url": getattr(resp, "geturl", lambda: url)(),
                        "content_type": (resp.headers.get("Content-Type") if hasattr(resp, "headers") else None),
                        "len": len(raw_b or b""),
                    }
            else:
                with urlopen(req, timeout=timeout_s, context=ctx) as resp:
                    raw_b = resp.read()
                    meta = {
                        "status": getattr(resp, "status", None),
                        "final_url": getattr(resp, "geturl", lambda: url)(),
                        "content_type": (resp.headers.get("Content-Type") if hasattr(resp, "headers") else None),
                        "len": len(raw_b or b""),
                    }
            return True, (raw_b or b"").decode("utf-8", errors="ignore"), "", meta
        except HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return False, body, f"HTTPError {getattr(e, 'code', '')}", {"status": getattr(e, "code", None), "final_url": url}
        except URLError as e:
            return False, "", f"URLError: {e}", {"final_url": url}
        except Exception as e:
            return False, "", str(e), {"final_url": url}

    ok, txt, err, meta = _attempt(None)
    if ok:
        return ok, txt, err, meta

    err_l = (err or "").lower()
    if ("certificate_verify_failed" in err_l) or ("key too weak" in err_l) or ("ssl:" in err_l):
        try:
            ctx = ssl._create_unverified_context()
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
            except Exception:
                pass
            ok2, txt2, err2, meta2 = _attempt(ctx)
            if ok2:
                meta2["insecure_ssl"] = True
                return ok2, txt2, err2, meta2
            return False, txt, f"{err} (retry insecure failed: {err2})", meta
        except Exception as e:
            return False, txt, f"{err} (retry insecure failed: {e})", meta

    return ok, txt, err, meta


def pmta_probe_endpoints(*, smtp_host: str) -> dict:
    """Probe the common PMTA Web Monitor endpoints and return a quick diagnostic."""
    base = _pmta_base_from_smtp_host(smtp_host)
    if not base:
        return {"ok": False, "error": "missing/invalid smtp_host", "base": ""}

    paths = [
        ("status", "/status?format=json"),
        ("queues", "/queues?format=json"),
        ("domains", "/domains?format=json"),
        ("vmtas", "/vmtas?format=json"),
        ("jobs", "/jobs?format=json"),
        ("logs", "/logs?format=json"),
        ("localips", "/getlocalips"),
    ]

    out = {"ok": True, "base": base, "host": smtp_host, "endpoints": {}}

    for name, p in paths:
        url = base + p
        ok, txt, err, meta = _http_get_text(url, timeout_s=min(6.0, max(2.0, PMTA_MONITOR_TIMEOUT_S)))
        entry: Dict[str, Any] = {"ok": bool(ok), "url": url, "meta": meta}
        if ok:
            # try parse JSON keys to understand schema
            parsed = None
            try:
                parsed = json.loads(txt or "{}")
            except Exception:
                parsed = None
            if isinstance(parsed, dict):
                entry["json_type"] = "dict"
                entry["keys"] = list(parsed.keys())[:40]
            elif isinstance(parsed, list):
                entry["json_type"] = "list"
                entry["items"] = len(parsed)
                if parsed and isinstance(parsed[0], dict):
                    entry["item_keys"] = list(parsed[0].keys())[:40]
            else:
                entry["json_type"] = "non_json"
            entry["snippet"] = (txt or "")[:280]
        else:
            entry["error"] = err
            entry["snippet"] = (txt or "")[:280]
        out["endpoints"][name] = entry

    return out


def _to_int(v: Any) -> Optional[int]:
    """Safe int coercion for PMTA schemas.

    IMPORTANT:
    - Never coerce dict/list/tuple/etc (to avoid turning {'cur':0,'max':1200,'top':2} into 12002).
    - For strings, extract the FIRST integer token instead of concatenating all digits.
    """
    try:
        if v is None:
            return None
        if isinstance(v, bool):
            return None
        if isinstance(v, (dict, list, tuple, set)):
            return None
        if isinstance(v, (int, float)):
            return int(v)
        s = str(v).strip()
        if not s:
            return None
        m = re.search(r"-?\d+", s)
        if not m:
            return None
        return int(m.group(0))
    except Exception:
        return None


def _deep_find_first_int(obj: Any, keys: Set[str], *, max_nodes: int = 2500) -> Optional[int]:
    # Best-effort: walk nested dict/list and return the first int-like value for a key.
    seen = 0

    def walk(x: Any) -> Optional[int]:
        nonlocal seen
        if seen > max_nodes:
            return None
        seen += 1

        if isinstance(x, dict):
            for k, v in x.items():
                kk = str(k).strip().lower()
                if kk in keys:
                    iv = _to_int(v)
                    if iv is not None:
                        return iv
                # continue walking
                r = walk(v)
                if r is not None:
                    return r
        elif isinstance(x, list):
            for it in x:
                r = walk(it)
                if r is not None:
                    return r
        return None

    return walk(obj)


def _sum_queue_counts(obj: Any) -> Tuple[Optional[int], Optional[int]]:
    """Try to sum queued recipients/messages from /queues JSON.

    PMTA /queues schemas differ across versions. We use a conservative heuristic:
    - Find the first list-of-dicts anywhere in the payload (queue items).
    - For each item, try direct keys first, then a small deep-search within the item.

    Returns: (queued_recipients, queued_messages)
    """

    def _find_list_of_dicts(x: Any, *, max_nodes: int = 4000) -> List[dict]:
        seen = 0

        def walk(v: Any) -> Optional[List[dict]]:
            nonlocal seen
            if seen > max_nodes:
                return None
            seen += 1
            if isinstance(v, list) and v and isinstance(v[0], dict):
                return [i for i in v if isinstance(i, dict)]
            if isinstance(v, dict):
                for vv in v.values():
                    r = walk(vv)
                    if r is not None:
                        return r
            if isinstance(v, list):
                for vv in v:
                    r = walk(vv)
                    if r is not None:
                        return r
            return None

        return walk(x) or []

    items = _find_list_of_dicts(obj)
    if not items:
        return None, None

    rcpt_direct = ("rcp", "rcpt", "rcpts", "recipients", "recipientcount", "queued_recipients", "queuedrecipients")
    msg_direct = ("msg", "msgs", "messages", "messagecount", "queued_messages", "queuedmessages")

    sum_rcpt = 0
    sum_msg = 0
    got_rcpt = False
    got_msg = False

    for it in items:
        lower_map = {str(k).strip().lower(): k for k in it.keys()}

        # recipients
        rcp_val: Optional[int] = None
        for kk in rcpt_direct:
            k0 = lower_map.get(kk)
            if not k0:
                continue
            rcp_val = _to_int(it.get(k0))
            if rcp_val is not None:
                break
        if rcp_val is None:
            rcp_val = _deep_find_first_int(it, {"rcp", "rcpt", "recipients", "queued_recipients", "queuedrecipients"}, max_nodes=700)
        if rcp_val is not None:
            sum_rcpt += int(rcp_val)
            got_rcpt = True

        # messages
        msg_val: Optional[int] = None
        for kk in msg_direct:
            k0 = lower_map.get(kk)
            if not k0:
                continue
            msg_val = _to_int(it.get(k0))
            if msg_val is not None:
                break
        if msg_val is None:
            msg_val = _deep_find_first_int(it, {"msg", "messages", "queued_messages", "queuedmessages"}, max_nodes=700)
        if msg_val is not None:
            sum_msg += int(msg_val)
            got_msg = True

    return (sum_rcpt if got_rcpt else None), (sum_msg if got_msg else None)


def _normalize_pmta_queue_to_domain(name: Any) -> str:
    """Normalize PMTA queue/domain labels to a recipient domain key.

    PMTA queue names are often shaped like:
      gmail.com/pmta-mpp-info
      gmail.com/*
      *.example.net/vmta-1
    We only need the domain part for Shiva domain-level counters.
    """
    s = str(name or "").strip().lower()
    if not s:
        return ""
    # Keep left-most queue segment before '/' (domain-like in PMTA queues page).
    if "/" in s:
        s = s.split("/", 1)[0].strip()
    s = s.strip(".")
    # Avoid wildcard placeholders.
    if s.startswith("*."):
        s = s[2:]
    if s in {"*", "*.*", "*/*"}:
        return ""
    return s if "." in s else ""


def _queues_extract_top(obj: Any, *, top_n: int = 6) -> List[dict]:
    """Best-effort: extract top queues (by recipients) from /queues JSON.

    If schema is unknown, we scan for the first list-of-dicts anywhere in the payload.
    """
    n = max(0, int(top_n or 0))
    if n <= 0:
        return []

    def _find_list_of_dicts(x: Any, *, max_nodes: int = 3500) -> List[dict]:
        seen = 0

        def walk(v: Any) -> Optional[List[dict]]:
            nonlocal seen
            if seen > max_nodes:
                return None
            seen += 1
            if isinstance(v, list) and v and isinstance(v[0], dict):
                return [i for i in v if isinstance(i, dict)]
            if isinstance(v, dict):
                for vv in v.values():
                    r = walk(vv)
                    if r is not None:
                        return r
            if isinstance(v, list):
                for vv in v:
                    r = walk(vv)
                    if r is not None:
                        return r
            return None

        return walk(x) or []

    items = _find_list_of_dicts(obj)
    if not items:
        return []

    def pick_queue_name(it: dict) -> str:
        for k in ("queue", "qname", "name", "id"):
            v = it.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        # fallback: some schemas use 'domain' + 'vmta'
        d = it.get("domain")
        v = it.get("vmta")
        if isinstance(d, str) and d.strip() and isinstance(v, str) and v.strip():
            return f"{d.strip()}/{v.strip()}"
        return ""

    def pick_int(it: dict, keys: Tuple[str, ...]) -> Optional[int]:
        lower_map = {str(k).strip().lower(): k for k in it.keys()}
        for kk in keys:
            k0 = lower_map.get(kk)
            if not k0:
                continue
            iv = _to_int(it.get(k0))
            if iv is not None:
                return int(iv)
        return None

    out: List[dict] = []
    for it in items:
        qn = pick_queue_name(it)
        if not qn:
            continue

        dom = _normalize_pmta_queue_to_domain(qn)

        rcpt = pick_int(it, ("recipients", "rcp", "rcpts", "queued_recipients", "recipientcount"))
        msgs = pick_int(it, ("messages", "msg", "msgs", "queued_messages", "messagecount"))
        defer = pick_int(it, ("deferred", "deferrals", "deferred_recipients", "deferredrecipients"))

        last_err = ""
        for k in ("lasterror", "last_error", "error", "reason", "diag", "lastdiag", "last_diag"):
            v = it.get(k)
            if isinstance(v, str) and v.strip():
                last_err = v.strip()
                break

        if rcpt is None:
            rcpt = _deep_find_first_int(it, {"recipients", "rcpt", "queued"})
        if msgs is None:
            msgs = _deep_find_first_int(it, {"messages", "msg"})
        if defer is None:
            defer = _deep_find_first_int(it, {"deferred", "deferrals"})

        out.append({
            "queue": qn,
            "domain": dom,
            "recipients": int(rcpt or 0),
            "messages": int(msgs or (rcpt or 0)),
            "deferred": int(defer or 0),
            "last_error": last_err,
        })

    out.sort(key=lambda x: int(x.get("recipients") or 0), reverse=True)
    return out[:n]


def pmta_health_check(*, smtp_host: str) -> dict:
    """Health check PowerMTA via Web Monitor.

    IMPORTANT:
    - PMTA 5.0r1 (enterprise-plus) returns /status like:
        {"data":{"mta":{"status":{...}}},"status":"success"}
      (so counts are under data.mta.status.*)

    Returns:
      {
        enabled: bool,
        ok: bool,
        required: bool,
        busy: bool,
        reason: str,
        status_url: str,
        spool_recipients: Optional[int],
        spool_messages: Optional[int],
        queued_recipients: Optional[int],
        queued_messages: Optional[int],
      }
    """

    base = _pmta_base_from_smtp_host(smtp_host)
    if not base:
        return {"enabled": False, "ok": True, "required": False, "busy": False, "reason": "disabled", "status_url": ""}

    status_url = f"{base}/status?format=json"

    ok, js, err = _http_get_json(status_url, timeout_s=PMTA_MONITOR_TIMEOUT_S)
    if not ok:
        return {
            "enabled": True,
            "ok": False,
            "required": bool(PMTA_HEALTH_REQUIRED),
            "busy": False,
            "reason": f"monitor unreachable: {err}",
            "status_url": status_url,
            "spool_recipients": None,
            "spool_messages": None,
            "queued_recipients": None,
            "queued_messages": None,
        }

    def _status_node(obj: Any) -> dict:
        if not isinstance(obj, dict):
            return {}
        # Some versions: {"status": { ... }}
        st = obj.get("status")
        if isinstance(st, dict):
            return st
        # PMTA 5.0r1: {"data": {"mta": {"status": { ... }}}}
        data = obj.get("data")
        if isinstance(data, dict):
            mta = data.get("mta")
            if isinstance(mta, dict):
                st2 = mta.get("status")
                if isinstance(st2, dict):
                    return st2
        # Fallback: if someone returns {"mta": {"status": ...}}
        mta2 = obj.get("mta")
        if isinstance(mta2, dict) and isinstance(mta2.get("status"), dict):
            return mta2.get("status")  # type: ignore
        return {}

    stn = _status_node(js)

    # Spool counts
    spool_rcpt: Optional[int] = None
    spool_msg: Optional[int] = None
    spool = stn.get("spool") if isinstance(stn.get("spool"), dict) else {}
    if isinstance(spool, dict) and spool:
        spool_rcpt = _to_int(spool.get("totalRcp"))
        files = spool.get("files") if isinstance(spool.get("files"), dict) else {}
        if isinstance(files, dict) and files:
            # closest to "messages" in spool: number of spool files in use
            spool_msg = _to_int(files.get("inUse"))
            if spool_msg is None:
                spool_msg = _to_int(files.get("total"))

    # Queue counts from /status (fast, always present on 5.0r1)
    queued_rcpt_status: Optional[int] = None
    queue = stn.get("queue") if isinstance(stn.get("queue"), dict) else {}
    if isinstance(queue, dict) and queue:
        s = 0
        got = False
        for v in queue.values():
            if isinstance(v, dict):
                iv = _to_int(v.get("rcp"))
                if iv is not None:
                    s += int(iv)
                    got = True
        if got:
            queued_rcpt_status = int(s)

    # Best-effort queued counts from /queues (more detailed if available)
    queued_rcpt: Optional[int] = None
    queued_msg: Optional[int] = None
    queues_url = f"{base}/queues?format=json"
    ok2, js2, _err2 = _http_get_json(queues_url, timeout_s=min(6.0, max(2.0, PMTA_MONITOR_TIMEOUT_S)))
    if ok2:
        queued_rcpt, queued_msg = _sum_queue_counts(js2)

    # Fallback to /status queue sum
    if queued_rcpt is None:
        queued_rcpt = queued_rcpt_status
    if queued_msg is None and queued_rcpt is not None:
        queued_msg = int(queued_rcpt)

    # If spool not extracted, try last-resort deep search (safe; _to_int ignores dict/list)
    if spool_rcpt is None:
        spool_rcpt = _deep_find_first_int(js, {"totalrcp", "spool_totalrcp", "spooltotalrcp", "spoolrecipients", "spool_recipients"})
    if spool_msg is None:
        spool_msg = _deep_find_first_int(js, {"inuse", "spoolfiles", "spool_messages", "spoolmessages", "total"})

    # Thresholds
    max_spool_rcpt = cfg_get_int("PMTA_MAX_SPOOL_RECIPIENTS", 200000)
    max_spool_msg = cfg_get_int("PMTA_MAX_SPOOL_MESSAGES", 50000)
    max_q_rcpt = cfg_get_int("PMTA_MAX_QUEUED_RECIPIENTS", 250000)
    max_q_msg = cfg_get_int("PMTA_MAX_QUEUED_MESSAGES", 60000)

    busy_reasons: List[str] = []
    if spool_rcpt is not None and spool_rcpt > max_spool_rcpt:
        busy_reasons.append(f"spool_recipients={spool_rcpt}>{max_spool_rcpt}")
    if spool_msg is not None and spool_msg > max_spool_msg:
        busy_reasons.append(f"spool_messages={spool_msg}>{max_spool_msg}")
    if queued_rcpt is not None and queued_rcpt > max_q_rcpt:
        busy_reasons.append(f"queued_recipients={queued_rcpt}>{max_q_rcpt}")
    if queued_msg is not None and queued_msg > max_q_msg:
        busy_reasons.append(f"queued_messages={queued_msg}>{max_q_msg}")

    busy = bool(busy_reasons)

    return {
        "enabled": True,
        "ok": True,
        "required": bool(PMTA_HEALTH_REQUIRED),
        "busy": busy,
        "reason": ("; ".join(busy_reasons) if busy else "ok"),
        "status_url": status_url,
        "spool_recipients": spool_rcpt,
        "spool_messages": spool_msg,
        "queued_recipients": queued_rcpt,
        "queued_messages": queued_msg,
    }


# -------------------------
# PMTA Live Panel + Adaptive Backoff (optional)
# -------------------------
# Extra diagnostics (optional)
PMTA_DIAG_ON_ERROR = (os.getenv("PMTA_DIAG_ON_ERROR", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}
try:
    PMTA_DIAG_RATE_S = float((os.getenv("PMTA_DIAG_RATE_S", "1.0") or "1.0").strip())
except Exception:
    PMTA_DIAG_RATE_S = 1.0
try:
    PMTA_QUEUE_TOP_N = int((os.getenv("PMTA_QUEUE_TOP_N", "6") or "6").strip())
except Exception:
    PMTA_QUEUE_TOP_N = 6


# -------------------------
# PMTA Live Panel + Adaptive Backoff (optional)
# -------------------------
# Extra diagnostics (optional)
PMTA_DIAG_ON_ERROR = (os.getenv("PMTA_DIAG_ON_ERROR", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}
try:
    PMTA_DIAG_RATE_S = float((os.getenv("PMTA_DIAG_RATE_S", "1.0") or "1.0").strip())
except Exception:
    PMTA_DIAG_RATE_S = 1.0
try:
    PMTA_QUEUE_TOP_N = int((os.getenv("PMTA_QUEUE_TOP_N", "6") or "6").strip())
except Exception:
    PMTA_QUEUE_TOP_N = 6

# -------------------------
# PMTA Live Panel + Adaptive Backoff (optional)
# -------------------------
# Uses PMTA monitor base derived from SMTP host: http://<smtp_host>:8080
PMTA_QUEUE_BACKOFF = (os.getenv("PMTA_QUEUE_BACKOFF", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}
PMTA_QUEUE_REQUIRED = (os.getenv("PMTA_QUEUE_REQUIRED", "0") or "0").strip().lower() in {"1", "true", "yes", "on"}

try:
    PMTA_LIVE_POLL_S = float((os.getenv("PMTA_LIVE_POLL_S", "3") or "3").strip())
except Exception:
    PMTA_LIVE_POLL_S = 3.0

try:
    PMTA_DOMAIN_CHECK_TOP_N = int((os.getenv("PMTA_DOMAIN_CHECK_TOP_N", "2") or "2").strip())
except Exception:
    PMTA_DOMAIN_CHECK_TOP_N = 2

try:
    PMTA_DETAIL_CACHE_TTL_S = float((os.getenv("PMTA_DETAIL_CACHE_TTL_S", "3") or "3").strip())
except Exception:
    PMTA_DETAIL_CACHE_TTL_S = 3.0

# Thresholds (defaults are conservative)
def _env_int(name: str, default: int) -> int:
    try:
        return int((os.getenv(name, str(default)) or str(default)).strip())
    except Exception:
        return default

def _env_float(name: str, default: float) -> float:
    try:
        return float((os.getenv(name, str(default)) or str(default)).strip())
    except Exception:
        return default

PMTA_DOMAIN_DEFERRALS_BACKOFF = _env_int("PMTA_DOMAIN_DEFERRALS_BACKOFF", 80)
PMTA_DOMAIN_ERRORS_BACKOFF   = _env_int("PMTA_DOMAIN_ERRORS_BACKOFF", 6)
PMTA_DOMAIN_DEFERRALS_SLOW   = _env_int("PMTA_DOMAIN_DEFERRALS_SLOW", 25)
PMTA_DOMAIN_ERRORS_SLOW      = _env_int("PMTA_DOMAIN_ERRORS_SLOW", 3)
PMTA_SLOW_DELAY_S            = _env_float("PMTA_SLOW_DELAY_S", 0.35)
PMTA_SLOW_WORKERS_MAX        = _env_int("PMTA_SLOW_WORKERS_MAX", 3)

# -------------------------
# PMTA pressure control (global) + domain snapshot (optional)
# -------------------------
PMTA_PRESSURE_CONTROL = (os.getenv("PMTA_PRESSURE_CONTROL", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}
try:
    PMTA_PRESSURE_POLL_S = float((os.getenv("PMTA_PRESSURE_POLL_S", "3") or "3").strip())
except Exception:
    PMTA_PRESSURE_POLL_S = 3.0

PMTA_DOMAIN_STATS = (os.getenv("PMTA_DOMAIN_STATS", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}
try:
    PMTA_DOMAINS_POLL_S = float((os.getenv("PMTA_DOMAINS_POLL_S", "4") or "4").strip())
except Exception:
    PMTA_DOMAINS_POLL_S = 4.0
try:
    PMTA_DOMAINS_TOP_N = int((os.getenv("PMTA_DOMAINS_TOP_N", "6") or "6").strip())
except Exception:
    PMTA_DOMAINS_TOP_N = 6

# Pressure thresholds (queued/spool recipients + deferrals)
PMTA_PRESSURE_Q1 = _env_int("PMTA_PRESSURE_Q1", 50000)
PMTA_PRESSURE_Q2 = _env_int("PMTA_PRESSURE_Q2", 120000)
PMTA_PRESSURE_Q3 = _env_int("PMTA_PRESSURE_Q3", 250000)
PMTA_PRESSURE_S1 = _env_int("PMTA_PRESSURE_S1", 30000)
PMTA_PRESSURE_S2 = _env_int("PMTA_PRESSURE_S2", 80000)
PMTA_PRESSURE_S3 = _env_int("PMTA_PRESSURE_S3", 160000)
PMTA_PRESSURE_D1 = _env_int("PMTA_PRESSURE_D1", 200)
PMTA_PRESSURE_D2 = _env_int("PMTA_PRESSURE_D2", 800)
PMTA_PRESSURE_D3 = _env_int("PMTA_PRESSURE_D3", 2000)

# Default actions per pressure level
PMTA_PRESSURE_L1_DELAY_MIN = _env_float("PMTA_PRESSURE_L1_DELAY_MIN", 0.15)
PMTA_PRESSURE_L1_WORKERS_MAX = _env_int("PMTA_PRESSURE_L1_WORKERS_MAX", 6)
PMTA_PRESSURE_L1_CHUNK_MAX = _env_int("PMTA_PRESSURE_L1_CHUNK_MAX", 80)
PMTA_PRESSURE_L1_SLEEP_MIN = _env_float("PMTA_PRESSURE_L1_SLEEP_MIN", 0.5)

PMTA_PRESSURE_L2_DELAY_MIN = _env_float("PMTA_PRESSURE_L2_DELAY_MIN", 0.35)
PMTA_PRESSURE_L2_WORKERS_MAX = _env_int("PMTA_PRESSURE_L2_WORKERS_MAX", 3)
PMTA_PRESSURE_L2_CHUNK_MAX = _env_int("PMTA_PRESSURE_L2_CHUNK_MAX", 45)
PMTA_PRESSURE_L2_SLEEP_MIN = _env_float("PMTA_PRESSURE_L2_SLEEP_MIN", 2.0)

PMTA_PRESSURE_L3_DELAY_MIN = _env_float("PMTA_PRESSURE_L3_DELAY_MIN", 0.75)
PMTA_PRESSURE_L3_WORKERS_MAX = _env_int("PMTA_PRESSURE_L3_WORKERS_MAX", 2)
PMTA_PRESSURE_L3_CHUNK_MAX = _env_int("PMTA_PRESSURE_L3_CHUNK_MAX", 25)
PMTA_PRESSURE_L3_SLEEP_MIN = _env_float("PMTA_PRESSURE_L3_SLEEP_MIN", 4.0)


def pmta_pressure_policy_from_live(live: dict) -> dict:
    """Compute adaptive speed limits based on PMTA load (/status + /queues).

    Output (recommendations):
      {
        enabled, ok,
        level: 0..3,
        reason: str,
        delay_min, workers_max, chunk_size_max, sleep_min,
        metrics: {...}
      }
    """
    if not PMTA_PRESSURE_CONTROL:
        return {"enabled": False, "ok": True, "level": 0, "reason": "disabled"}

    if not isinstance(live, dict) or not live.get("enabled"):
        return {"enabled": True, "ok": False, "level": 0, "reason": "no live data"}

    if not live.get("ok"):
        return {"enabled": True, "ok": False, "level": 0, "reason": str(live.get("reason") or "unreachable")}

    q = _to_int(live.get("queued_recipients")) or 0
    s = _to_int(live.get("spool_recipients")) or 0
    d = _to_int(live.get("deferred_total")) or 0
    a = _to_int(live.get("active_connections"))

    lvl_q = 3 if q >= PMTA_PRESSURE_Q3 else (2 if q >= PMTA_PRESSURE_Q2 else (1 if q >= PMTA_PRESSURE_Q1 else 0))
    lvl_s = 3 if s >= PMTA_PRESSURE_S3 else (2 if s >= PMTA_PRESSURE_S2 else (1 if s >= PMTA_PRESSURE_S1 else 0))
    lvl_d = 3 if d >= PMTA_PRESSURE_D3 else (2 if d >= PMTA_PRESSURE_D2 else (1 if d >= PMTA_PRESSURE_D1 else 0))

    lvl = max(lvl_q, lvl_s, lvl_d)

    if lvl <= 0:
        return {
            "enabled": True,
            "ok": True,
            "level": 0,
            "reason": "ok",
            "delay_min": None,
            "workers_max": None,
            "chunk_size_max": None,
            "sleep_min": None,
            "metrics": {"queued": q, "spool": s, "deferred": d, "active_conns": a},
        }

    if lvl == 1:
        delay_min = PMTA_PRESSURE_L1_DELAY_MIN
        workers_max = PMTA_PRESSURE_L1_WORKERS_MAX
        chunk_max = PMTA_PRESSURE_L1_CHUNK_MAX
        sleep_min = PMTA_PRESSURE_L1_SLEEP_MIN
    elif lvl == 2:
        delay_min = PMTA_PRESSURE_L2_DELAY_MIN
        workers_max = PMTA_PRESSURE_L2_WORKERS_MAX
        chunk_max = PMTA_PRESSURE_L2_CHUNK_MAX
        sleep_min = PMTA_PRESSURE_L2_SLEEP_MIN
    else:
        delay_min = PMTA_PRESSURE_L3_DELAY_MIN
        workers_max = PMTA_PRESSURE_L3_WORKERS_MAX
        chunk_max = PMTA_PRESSURE_L3_CHUNK_MAX
        sleep_min = PMTA_PRESSURE_L3_SLEEP_MIN

    reason = f"lvl={lvl} queued={q} spool={s} deferred={d}"
    return {
        "enabled": True,
        "ok": True,
        "level": int(lvl),
        "reason": reason,
        "delay_min": float(delay_min),
        "workers_max": int(workers_max),
        "chunk_size_max": int(chunk_max),
        "sleep_min": float(sleep_min),
        "metrics": {"queued": q, "spool": s, "deferred": d, "active_conns": a},
    }


def pmta_domains_overview(*, smtp_host: str) -> dict:
    """Fetch /domains and build a compact domain -> {queued,deferred,active} map.

    Many PMTA versions return nested payloads (sometimes under data.*). We therefore:
    - parse JSON,
    - then locate a list-of-dicts anywhere inside the payload.

    Output:
      { ok, reason, url, domains: { "gmail.com": {queued,deferred,active}, ... } }
    """

    base = _pmta_base_from_smtp_host(smtp_host)
    if not base:
        return {"ok": False, "reason": "disabled", "url": "", "domains": {}}

    url = f"{base}/domains?format=json"
    ok, js, err = _http_get_json(url, timeout_s=min(6.0, max(2.0, PMTA_MONITOR_TIMEOUT_S)))
    if not ok:
        return {"ok": False, "reason": err, "url": url, "domains": {}}

    def _find_list_of_dicts(x: Any, *, max_nodes: int = 4500) -> List[dict]:
        seen = 0

        def walk(v: Any) -> Optional[List[dict]]:
            nonlocal seen
            if seen > max_nodes:
                return None
            seen += 1
            if isinstance(v, list) and v and isinstance(v[0], dict):
                return [i for i in v if isinstance(i, dict)]
            if isinstance(v, dict):
                for vv in v.values():
                    r = walk(vv)
                    if r is not None:
                        return r
            if isinstance(v, list):
                for vv in v:
                    r = walk(vv)
                    if r is not None:
                        return r
            return None

        return walk(x) or []

    items = _find_list_of_dicts(js)

    def pick_name(it: dict) -> str:
        for k in ("domain", "name", "qname", "queue", "id"):
            v = it.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip().lower().strip(".")
        return ""

    out: Dict[str, dict] = {}
    for it in items:
        raw_name = pick_name(it)
        dom = _normalize_pmta_queue_to_domain(raw_name)
        if not dom:
            continue

        queued = _deep_find_first_int(it, {"queued", "queued_recipients", "queuedrecipients", "recipientqueued", "queue_recipients", "queue", "rcpt", "rcp", "recipients"})
        active = _deep_find_first_int(it, {"active", "activeconnections", "active_connections", "connections", "activeconns"})
        deferred = _deep_find_first_int(it, {"deferred", "deferrals", "deferred_recipients", "deferredrecipients"})

        # safer fallback: sum all keys that look like queue/defer
        if queued is None:
            queued = _deep_sum_ints_by_key_pred(it, lambda k: ("queue" in k) or ("queued" in k), max_nodes=800)
        if deferred is None:
            deferred = _deep_sum_ints_by_key_pred(it, lambda k: "defer" in k, max_nodes=800)

        old = out.get(dom) or {}
        out[dom] = {
            # multiple queues/vMTAs can belong to same domain, so aggregate
            "queued": int(old.get("queued") or 0) + int(queued or 0),
            "deferred": int(old.get("deferred") or 0) + int(deferred or 0),
            "active": (
                (int(old.get("active") or 0) + int(active or 0))
                if (active is not None or old.get("active") is not None)
                else None
            ),
        }

    return {"ok": True, "reason": "ok", "url": url, "domains": out}

_PMTA_DETAIL_CACHE: Dict[str, Tuple[float, dict]] = {}


def _deep_sum_ints_by_key_pred(obj: Any, pred, *, max_nodes: int = 3500) -> int:
    seen = 0
    total = 0

    def walk(x: Any):
        nonlocal seen, total
        if seen > max_nodes:
            return
        seen += 1
        if isinstance(x, dict):
            for k, v in x.items():
                kk = str(k).strip().lower()
                if pred(kk):
                    iv = _to_int(v)
                    if iv is not None:
                        total += int(iv)
                walk(v)
        elif isinstance(x, list):
            for it in x:
                walk(it)

    walk(obj)
    return int(total)


def _deep_find_first_list(obj: Any, keys: Set[str], *, max_nodes: int = 2500) -> Optional[list]:
    seen = 0

    def walk(x: Any) -> Optional[list]:
        nonlocal seen
        if seen > max_nodes:
            return None
        seen += 1
        if isinstance(x, dict):
            for k, v in x.items():
                kk = str(k).strip().lower()
                if kk in keys and isinstance(v, list):
                    return v
                r = walk(v)
                if r is not None:
                    return r
        elif isinstance(x, list):
            for it in x:
                r = walk(it)
                if r is not None:
                    return r
        return None

    return walk(obj)


def pmta_live_panel(*, smtp_host: str) -> dict:
    """Fetch /status + /queues to build a compact live panel.

    Supports PMTA 5.0r1 (enterprise-plus) where /status JSON is under data.mta.status.*.

    Returns:
      {
        enabled, ok, reason, ts,
        spool_recipients, spool_messages,
        queued_recipients, queued_messages,
        active_connections, smtp_in_connections, smtp_out_connections,
        traffic_last_hr_in, traffic_last_hr_out,
        traffic_last_min_in, traffic_last_min_out,
        deferred_total,
        top_queues,
        status_url, queues_url
      }
    """

    base = _pmta_base_from_smtp_host(smtp_host)
    if not base:
        return {"enabled": False, "ok": True, "reason": "disabled", "ts": now_iso()}

    status_url = f"{base}/status?format=json"
    ok, js, err = _http_get_json(status_url, timeout_s=PMTA_MONITOR_TIMEOUT_S)
    if not ok:
        return {"enabled": True, "ok": False, "reason": f"monitor unreachable: {err}", "status_url": status_url, "ts": now_iso()}

    def _status_node(obj: Any) -> dict:
        if not isinstance(obj, dict):
            return {}
        st = obj.get("status")
        if isinstance(st, dict):
            return st
        data = obj.get("data")
        if isinstance(data, dict):
            if isinstance(data.get("status"), dict):
                return data.get("status")  # type: ignore
            mta = data.get("mta")
            if isinstance(mta, dict) and isinstance(mta.get("status"), dict):
                return mta.get("status")  # type: ignore
        mta2 = obj.get("mta")
        if isinstance(mta2, dict) and isinstance(mta2.get("status"), dict):
            return mta2.get("status")  # type: ignore
        return {}

    stn = _status_node(js)

    # Spool
    spool_rcpt: Optional[int] = None
    spool_msg: Optional[int] = None
    spool = stn.get("spool") if isinstance(stn.get("spool"), dict) else {}
    if isinstance(spool, dict) and spool:
        spool_rcpt = _to_int(spool.get("totalRcp"))
        files = spool.get("files") if isinstance(spool.get("files"), dict) else {}
        if isinstance(files, dict) and files:
            # closest to "messages" in spool: number of spool files in use
            spool_msg = _to_int(files.get("inUse"))
            if spool_msg is None:
                spool_msg = _to_int(files.get("total"))

    # Queue sums from /status (fallback)
    queued_rcpt_status: Optional[int] = None
    queue = stn.get("queue") if isinstance(stn.get("queue"), dict) else {}
    if isinstance(queue, dict) and queue:
        s = 0
        got = False
        for v in queue.values():
            if isinstance(v, dict):
                iv = _to_int(v.get("rcp"))
                if iv is not None:
                    s += int(iv)
                    got = True
        if got:
            queued_rcpt_status = int(s)

    # Connections (sum in+out)
    active_conns: Optional[int] = None
    smtp_in_conns: Optional[int] = None
    smtp_out_conns: Optional[int] = None
    conn = stn.get("conn") if isinstance(stn.get("conn"), dict) else {}
    if isinstance(conn, dict) and conn:
        smtp_in = conn.get("smtpIn") if isinstance(conn.get("smtpIn"), dict) else {}
        smtp_out = conn.get("smtpOut") if isinstance(conn.get("smtpOut"), dict) else {}
        a = 0
        got = False
        if isinstance(smtp_in, dict):
            iv = _to_int(smtp_in.get("cur"))
            if iv is not None:
                smtp_in_conns = int(iv)
                a += int(iv)
                got = True
        if isinstance(smtp_out, dict):
            iv = _to_int(smtp_out.get("cur"))
            if iv is not None:
                smtp_out_conns = int(iv)
                a += int(iv)
                got = True
        if got:
            active_conns = int(a)

    # Traffic stats (recipients): last hour + last minute (in/out)
    traffic_last_hr_in: Optional[int] = None
    traffic_last_hr_out: Optional[int] = None
    traffic_last_min_in: Optional[int] = None
    traffic_last_min_out: Optional[int] = None
    traffic = stn.get("traffic") if isinstance(stn.get("traffic"), dict) else {}
    if isinstance(traffic, dict) and traffic:
        last_hr = traffic.get("lastHr") if isinstance(traffic.get("lastHr"), dict) else {}
        if isinstance(last_hr, dict) and last_hr:
            hr_in = last_hr.get("in") if isinstance(last_hr.get("in"), dict) else {}
            hr_out = last_hr.get("out") if isinstance(last_hr.get("out"), dict) else {}
            if isinstance(hr_in, dict):
                traffic_last_hr_in = _to_int(hr_in.get("rcp"))
            if isinstance(hr_out, dict):
                traffic_last_hr_out = _to_int(hr_out.get("rcp"))

        last_min = traffic.get("lastMin") if isinstance(traffic.get("lastMin"), dict) else {}
        if isinstance(last_min, dict) and last_min:
            min_in = last_min.get("in") if isinstance(last_min.get("in"), dict) else {}
            min_out = last_min.get("out") if isinstance(last_min.get("out"), dict) else {}
            if isinstance(min_in, dict):
                traffic_last_min_in = _to_int(min_in.get("rcp"))
            if isinstance(min_out, dict):
                traffic_last_min_out = _to_int(min_out.get("rcp"))

    # NOTE: Do NOT use deep-int fallback for connections.
    # Some PMTA nodes are dicts like {'cur':0,'max':1200,'top':2} and naive parsing can produce fake numbers (e.g., 12002).

    # Deferred total (not always present in /status on 5.0r1 → default 0)
    deferred_total = _deep_sum_ints_by_key_pred(js, lambda k: "defer" in k)

    # /queues (optional) for queued totals + top queues
    queued_rcpt: Optional[int] = None
    queued_msg: Optional[int] = None
    top_queues: List[dict] = []

    queues_url = f"{base}/queues?format=json"
    ok2, js2, _ = _http_get_json(queues_url, timeout_s=min(6.0, max(2.0, PMTA_MONITOR_TIMEOUT_S)))
    if ok2:
        queued_rcpt, queued_msg = _sum_queue_counts(js2)
        try:
            top_queues = _queues_extract_top(js2, top_n=PMTA_QUEUE_TOP_N)
        except Exception:
            top_queues = []

    # Fallback queued from /status if /queues failed
    if queued_rcpt is None:
        queued_rcpt = queued_rcpt_status
    if queued_msg is None and queued_rcpt is not None:
        queued_msg = int(queued_rcpt)

    # If /queues didn't provide top queues, build from /status.queue
    if not top_queues and isinstance(queue, dict) and queue:
        tmp = []
        for name, v in queue.items():
            if not isinstance(v, dict):
                continue
            rcp = _to_int(v.get("rcp"))
            if rcp is None:
                continue
            tmp.append({
                "queue": str(name),
                "recipients": int(rcp),
                "messages": int(rcp),
                "deferred": 0,
            })
        tmp.sort(key=lambda x: int(x.get("recipients") or 0), reverse=True)
        top_queues = tmp[: max(0, int(PMTA_QUEUE_TOP_N or 0))]

    # PMTA 5.0r1 always includes these nodes; prefer 0 (real counter) over None (UI shows “—”).
    if stn:
        if spool_rcpt is None:
            spool_rcpt = 0
        if spool_msg is None:
            spool_msg = 0
        if queued_rcpt is None:
            queued_rcpt = 0
        if queued_msg is None:
            queued_msg = int(queued_rcpt)
        if active_conns is None:
            active_conns = 0
        if smtp_in_conns is None:
            smtp_in_conns = 0
        if smtp_out_conns is None:
            smtp_out_conns = 0
        if traffic_last_hr_in is None:
            traffic_last_hr_in = 0
        if traffic_last_hr_out is None:
            traffic_last_hr_out = 0
        if traffic_last_min_in is None:
            traffic_last_min_in = 0
        if traffic_last_min_out is None:
            traffic_last_min_out = 0

    return {
        "enabled": True,
        "ok": True,
        "reason": "ok",
        "status_url": status_url,
        "queues_url": queues_url,
        "spool_recipients": spool_rcpt,
        "spool_messages": spool_msg,
        "queued_recipients": queued_rcpt,
        "queued_messages": queued_msg,
        "active_connections": active_conns,
        "smtp_in_connections": smtp_in_conns,
        "smtp_out_connections": smtp_out_conns,
        "traffic_last_hr_in": traffic_last_hr_in,
        "traffic_last_hr_out": traffic_last_hr_out,
        "traffic_last_min_in": traffic_last_min_in,
        "traffic_last_min_out": traffic_last_min_out,
        "deferred_total": int(deferred_total or 0),
        "top_queues": top_queues,
        "ts": now_iso(),
    }



def _pmta_detail_metrics(js: Any) -> dict:
    deferrals = _deep_sum_ints_by_key_pred(js, lambda k: "defer" in k)
    # try to find a list of recent errors / events
    err_list = _deep_find_first_list(js, {"errors", "lasterrors", "last_errors", "recent_errors", "recipient_events"})
    errors_count = 0
    errors_sample: List[str] = []
    if isinstance(err_list, list):
        errors_count = len(err_list)
        for it in err_List[:3]:
            errors_sample.append(str(it)[:140])
    else:
        errors_count = _deep_find_first_int(js, {"errorcount", "errorscount", "last_errors_count"}) or 0
    return {"deferrals": int(deferrals or 0), "errors_count": int(errors_count or 0), "errors_sample": errors_sample}


def _pmta_cached(key: str) -> Optional[dict]:
    try:
        ts, val = _PMTA_DETAIL_CACHE.get(key, (0.0, {}))
        if not val:
            return None
        if (time.time() - float(ts)) <= float(PMTA_DETAIL_CACHE_TTL_S or 0.0):
            return val
    except Exception:
        return None
    return None


def _pmta_cache_put(key: str, val: dict) -> None:
    try:
        _PMTA_DETAIL_CACHE[key] = (time.time(), val)
    except Exception:
        pass


def pmta_domain_detail_metrics(*, smtp_host: str, domain: str) -> dict:
    base = _pmta_base_from_smtp_host(smtp_host)
    if not base:
        return {"ok": False, "reason": "disabled"}

    d = (domain or "").strip().lower().strip(".")
    if not d:
        return {"ok": False, "reason": "missing domain"}

    ck = f"dom:{base}:{d}"
    cached = _pmta_cached(ck)
    if cached is not None:
        return cached

    url = f"{base}/domainDetail?format=json&domain={quote_plus(d)}"
    ok, js, err = _http_get_json(url, timeout_s=min(6.0, max(2.0, PMTA_MONITOR_TIMEOUT_S)))
    if not ok:
        out = {"ok": False, "reason": err, "url": url, "domain": d}
        _pmta_cache_put(ck, out)
        return out

    out = {"ok": True, "url": url, "domain": d, **_pmta_detail_metrics(js)}
    _pmta_cache_put(ck, out)
    return out


def pmta_queue_detail_metrics(*, smtp_host: str, queue: str) -> dict:
    base = _pmta_base_from_smtp_host(smtp_host)
    if not base:
        return {"ok": False, "reason": "disabled"}

    q = (queue or "").strip()
    if not q:
        return {"ok": False, "reason": "missing queue"}

    ck = f"q:{base}:{q}"
    cached = _pmta_cached(ck)
    if cached is not None:
        return cached

    url = f"{base}/queueDetail?format=json&queue={quote_plus(q)}"
    ok, js, err = _http_get_json(url, timeout_s=min(6.0, max(2.0, PMTA_MONITOR_TIMEOUT_S)))
    if not ok:
        out = {"ok": False, "reason": err, "url": url, "queue": q}
        _pmta_cache_put(ck, out)
        return out

    out = {"ok": True, "url": url, "queue": q, **_pmta_detail_metrics(js)}
    _pmta_cache_put(ck, out)
    return out


# -------------------------
# PMTA diagnostics helpers (point 7)
# -------------------------
_PMTA_ERR_DIAG_CACHE: Dict[str, float] = {}


def _classify_send_exception(e: Exception) -> str:
    msg = (str(e) or "").lower()
    if any(x in msg for x in ("timed out", "timeout")):
        return "client_timeout"
    if any(x in msg for x in ("connection refused", "refused", "reset", "broken pipe", "eof", "network is unreachable")):
        return "client_connection"
    if any(x in msg for x in ("auth", "authentication", "login", "535", "530")):
        return "client_auth"
    if any(x in msg for x in ("sender address rejected", "mail from", "sender rejected")):
        return "pmta_sender_reject"
    if any(x in msg for x in ("recipient address rejected", "rcpt to", "user unknown", "550", "551", "552", "553", "554")):
        return "pmta_rcpt_reject"
    if any(x in msg for x in ("too many", "rate", "throttle")):
        return "pmta_throttle"
    return "unknown"


def pmta_diag_on_error(*, smtp_host: str, rcpt: str, exc: Exception) -> dict:
    """Best-effort context to help decide: client vs PMTA vs remote-throttling.

    NOTE: send_message() errors are usually *injection-stage* (client<->PMTA).
    Remote ISP rejections happen later and show up in PMTA queues/domainDetail.
    """
    if not PMTA_DIAG_ON_ERROR:
        return {"enabled": False, "ok": True, "reason": "disabled"}

    dom = _extract_domain_from_email(rcpt)
    base = _pmta_base_from_smtp_host(smtp_host)
    if not dom or not base:
        return {"enabled": True, "ok": False, "reason": "missing domain/pmta"}

    # Simple rate limit per (domain) so we don't slow down sending too much.
    key = f"{base}:{dom}"
    now_t = time.time()
    try:
        last = float(_PMTA_ERR_DIAG_CACHE.get(key, 0.0) or 0.0)
        if (now_t - last) < float(PMTA_DIAG_RATE_S or 0.0):
            return {"enabled": True, "ok": False, "reason": "rate_limited", "domain": dom}
        _PMTA_ERR_DIAG_CACHE[key] = now_t
    except Exception:
        pass

    live = {}
    try:
        live = pmta_live_panel(smtp_host=smtp_host)
    except Exception:
        live = {"enabled": True, "ok": False, "reason": "live_failed"}

    dd = {}
    qd = {}
    try:
        dd = pmta_domain_detail_metrics(smtp_host=smtp_host, domain=dom)
    except Exception:
        dd = {"ok": False, "reason": "domainDetail_failed"}
    try:
        qd = pmta_queue_detail_metrics(smtp_host=smtp_host, queue=f"{dom}/*")
    except Exception:
        qd = {"ok": False, "reason": "queueDetail_failed"}

    def_max = max(int(dd.get("deferrals") or 0), int(qd.get("deferrals") or 0))
    err_max = max(int(dd.get("errors_count") or 0), int(qd.get("errors_count") or 0))
    sample = (dd.get("errors_sample") or qd.get("errors_sample") or [])[:2]

    cls = _classify_send_exception(exc)

    remote_hint = ""
    # If PMTA shows deferrals/errors, it's likely remote throttling/ISP issues (not client injection).
    if def_max >= int(PMTA_DOMAIN_DEFERRALS_SLOW or 25) or err_max >= int(PMTA_DOMAIN_ERRORS_SLOW or 3):
        remote_hint = "remote_throttling_or_isp"

    return {
        "enabled": True,
        "ok": True,
        "domain": dom,
        "class": cls,
        "remote_hint": remote_hint,
        "queue_deferrals": def_max,
        "queue_errors": err_max,
        "errors_sample": sample,
        "live": {
            "queued_recipients": live.get("queued_recipients"),
            "spool_recipients": live.get("spool_recipients"),
            "deferred_total": live.get("deferred_total"),
            "active_connections": live.get("active_connections"),
            "top_queues": live.get("top_queues") if isinstance(live.get("top_queues"), list) else [],
        },
        "ts": now_iso(),
    }


def pmta_chunk_policy(*, smtp_host: str, chunk_domain_counts: Dict[str, int]) -> dict:
    """Decide if we should block/backoff or slow down based on PMTA domain/queue errors.

    Returns:
      {
        enabled, ok,
        blocked: bool,
        slow: {delay_min, workers_max} | None,
        reason: str,
        details: [...]  # per-domain metrics (small)
      }
    """
    if not PMTA_QUEUE_BACKOFF:
        return {"enabled": False, "ok": True, "blocked": False, "slow": None, "reason": "disabled", "details": []}

    if not chunk_domain_counts:
        return {"enabled": True, "ok": True, "blocked": False, "slow": None, "reason": "no domains", "details": []}

    base = _pmta_base_from_smtp_host(smtp_host)
    if not base:
        return {"enabled": False, "ok": True, "blocked": False, "slow": None, "reason": "disabled", "details": []}

    top_n = max(0, int(PMTA_DOMAIN_CHECK_TOP_N or 0))
    if top_n == 0:
        return {"enabled": True, "ok": True, "blocked": False, "slow": None, "reason": "top_n=0", "details": []}

    items = sorted(chunk_domain_counts.items(), key=lambda x: int(x[1] or 0), reverse=True)[:top_n]

    worst_dom, worst_def, worst_err = "", 0, 0
    details = []
    any_ok = False

    for dom, cnt in items:
        d = (dom or "").strip().lower().strip(".")
        if not d:
            continue

        dd = pmta_domain_detail_metrics(smtp_host=smtp_host, domain=d)
        qd = pmta_queue_detail_metrics(smtp_host=smtp_host, queue=f"{d}/*")

        if dd.get("ok") or qd.get("ok"):
            any_ok = True

        def_max = max(int(dd.get("deferrals") or 0), int(qd.get("deferrals") or 0))
        err_max = max(int(dd.get("errors_count") or 0), int(qd.get("errors_count") or 0))

        details.append({
            "domain": d,
            "count": int(cnt or 0),
            "deferrals": def_max,
            "errors": err_max,
            "domain_url": dd.get("url"),
            "queue_url": qd.get("url"),
            "errors_sample": (dd.get("errors_sample") or qd.get("errors_sample") or [])[:2],
        })

        if (def_max > worst_def) or (err_max > worst_err):
            worst_dom = d
            worst_def = max(worst_def, def_max)
            worst_err = max(worst_err, err_max)

    if not any_ok:
        if PMTA_QUEUE_REQUIRED:
            return {"enabled": True, "ok": False, "blocked": True, "slow": None, "reason": "pmta detail unreachable", "details": details}
        return {"enabled": True, "ok": False, "blocked": False, "slow": None, "reason": "pmta detail unreachable", "details": details}

    if worst_def >= PMTA_DOMAIN_DEFERRALS_BACKOFF or worst_err >= PMTA_DOMAIN_ERRORS_BACKOFF:
        return {"enabled": True, "ok": True, "blocked": True, "slow": None, "reason": f"{worst_dom} deferrals={worst_def} errors={worst_err}", "details": details}

    if worst_def >= PMTA_DOMAIN_DEFERRALS_SLOW or worst_err >= PMTA_DOMAIN_ERRORS_SLOW:
        slow = {"delay_min": float(PMTA_SLOW_DELAY_S), "workers_max": int(PMTA_SLOW_WORKERS_MAX)}
        return {"enabled": True, "ok": True, "blocked": False, "slow": slow, "reason": f"{worst_dom} deferrals={worst_def} errors={worst_err}", "details": details}

    return {"enabled": True, "ok": True, "blocked": False, "slow": None, "reason": "ok", "details": details}


# =========================
# PowerMTA Accounting ingestion (official bounces/deferrals/complaints)
# =========================
# Single supported mode:
# Shiva requests accounting from bridge API, and bridge only serves API responses.
PMTA_BRIDGE_PULL_ENABLED = (os.getenv("PMTA_BRIDGE_PULL_ENABLED", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}
PMTA_BRIDGE_PULL_URL = (os.getenv("PMTA_BRIDGE_PULL_URL", "") or "").strip()
PMTA_BRIDGE_PULL_TOKEN = (os.getenv("PMTA_BRIDGE_PULL_TOKEN", "") or "").strip()
try:
    PMTA_BRIDGE_PULL_S = float((os.getenv("PMTA_BRIDGE_PULL_S", "5") or "5").strip())
except Exception:
    PMTA_BRIDGE_PULL_S = 5.0
try:
    PMTA_BRIDGE_PULL_MAX_LINES = int((os.getenv("PMTA_BRIDGE_PULL_MAX_LINES", "2000") or "2000").strip())
except Exception:
    PMTA_BRIDGE_PULL_MAX_LINES = 2000
PMTA_BRIDGE_PULL_KIND = (os.getenv("PMTA_BRIDGE_PULL_KIND", "acct") or "acct").strip().lower()
PMTA_BRIDGE_PULL_ALL_FILES = (os.getenv("PMTA_BRIDGE_PULL_ALL_FILES", "0") or "0").strip().lower() in {"1", "true", "yes", "on"}
PMTA_BRIDGE_PULL_TARGET_MODE = (os.getenv("PMTA_BRIDGE_PULL_TARGET_MODE", "auto") or "auto").strip().lower()  # auto|job|campaign|all
try:
    PMTA_BRIDGE_PULL_TARGET_LIMIT = int((os.getenv("PMTA_BRIDGE_PULL_TARGET_LIMIT", "12") or "12").strip())
except Exception:
    PMTA_BRIDGE_PULL_TARGET_LIMIT = 12

_BRIDGE_DEBUG_LOCK = threading.Lock()
_BRIDGE_DEBUG_STATE: Dict[str, Any] = {
    "last_attempt_ts": "",
    "last_success_ts": "",
    "last_error_ts": "",
    "last_ok": False,
    "connected": False,
    "attempts": 0,
    "success_count": 0,
    "failure_count": 0,
    "last_error": "",
    "last_req_url": "",
    "last_http_ok": False,
    "last_http_status": None,
    "last_duration_ms": 0,
    "last_response_keys": [],
    "last_bridge_count": 0,
    "last_processed": 0,
    "last_accepted": 0,
    "last_lines_sample": [],
    "last_target": {},
}

_BRIDGE_POLLER_LOCK = threading.Lock()
_BRIDGE_POLLER_STARTED = False

_BRIDGE_TARGET_CURSOR_LOCK = threading.Lock()
_BRIDGE_TARGET_CURSOR = 0


def _bridge_debug_update(**kwargs: Any) -> None:
    with _BRIDGE_DEBUG_LOCK:
        _BRIDGE_DEBUG_STATE.update(kwargs)

_PMTA_ACC_HEADERS: Dict[str, List[str]] = {}

# Extract job id from Message-ID we generate:
#   <uuid.<job_id>.<campaign_id>.c<chunk>.w<worker>@local>
_JOBID_RE_1 = re.compile(r"[.][a-f0-9]{8,64}[.]([a-f0-9]{12})[.]([a-f0-9]{8,64}|none)[.]c[0-9]+[.]w[0-9]+@local", re.IGNORECASE)
_JOBID_RE_2 = re.compile(r"[.][a-f0-9]{8,64}[.]([a-f0-9]{12})[.]c[0-9]+[.]w[0-9]+@local", re.IGNORECASE)


def _extract_job_id_from_text(text: str) -> str:
    t = (text or "").strip()
    if not t:
        return ""
    m = _JOBID_RE_1.search(t)
    if m:
        return m.group(1).lower()
    m = _JOBID_RE_2.search(t)
    if m:
        return m.group(1).lower()
    return ""


def _normalize_outcome_type(v: Any) -> str:
    s = ("" if v is None else str(v)).strip().lower()
    if not s:
        return ""
    s = re.sub(r"\s+", " ", s)
    # PMTA accounting often uses a 1-letter type.
    if s in {"d", "delivered", "delivery", "success", "accepted", "ok", "sent"}:
        return "delivered"
    if s in {"b", "bounce", "bounced", "hardbounce", "softbounce", "failed", "failure", "reject", "rejected", "error"}:
        return "bounced"
    if s in {"t", "defer", "deferred", "deferral", "transient"}:
        return "deferred"
    if s in {"c", "complaint", "complained", "fbl"}:
        return "complained"

    # PMTA accounting CSV often stores status words in longer values,
    # e.g. dsnStatus="2.0.0 (success)" or dsnAction="relayed".
    if any(x in s for x in ("success", "2.0.0", "relayed", "delivered", "accepted", "250 ")):
        return "delivered"
    if any(x in s for x in ("bounce", "bounced", "failed", "failure", "reject", "5.", " 550", " 551", " 552", " 553", " 554")):
        return "bounced"
    if any(x in s for x in ("defer", "deferred", "transient", "4.", " 421", " 450", " 451", " 452")):
        return "deferred"
    if any(x in s for x in ("complaint", "fbl", "abuse")):
        return "complained"
    return s


def _event_value(ev: dict, *names: str) -> str:
    if not isinstance(ev, dict):
        return ""
    aliases = {n.strip().lower().replace("_", "-") for n in names if n and n.strip()}
    if not aliases:
        return ""

    for k, v in ev.items():
        kk = str(k or "").strip().lower().replace("_", "-")
        if kk in aliases and str(v or "").strip():
            return str(v).strip()

    for k, v in ev.items():
        kk = str(k or "").strip().lower().replace("_", "-")
        if any(a in kk for a in aliases) and str(v or "").strip():
            return str(v).strip()
    return ""


def _find_job_by_campaign(campaign_id: str) -> Optional[SendJob]:
    cid = (campaign_id or "").strip()
    if not cid:
        return None

    candidates = [j for j in JOBS.values() if (j.campaign_id or "").strip() == cid and not bool(j.deleted)]
    if not candidates:
        return None

    running = [j for j in candidates if (j.status or "") in {"running", "backoff", "paused"}]
    pool = running or candidates

    def _sort_key(j: SendJob) -> Tuple[str, str]:
        return (str(j.updated_at or ""), str(j.created_at or ""))

    pool.sort(key=_sort_key, reverse=True)
    return pool[0]


def _find_job_by_recipient(rcpt: str) -> Optional[SendJob]:
    em = (rcpt or "").strip().lower()
    if not em:
        return None

    # 1) Prefer persisted recipient->job mapping (most reliable when ids are absent in PMTA CSV).
    for jid in db_find_job_ids_by_recipient(em, limit=12):
        job = JOBS.get(jid)
        if job and not bool(job.deleted):
            return job

    # 2) Fallback to in-memory recent send results if DB has no hit.
    candidates: List[SendJob] = []
    for job in JOBS.values():
        if bool(job.deleted):
            continue
        rr = job.recent_results or []
        if any(str(it.get("email") or "").strip().lower() == em for it in rr[-250:]):
            candidates.append(job)

    if not candidates:
        return None

    running = [j for j in candidates if (j.status or "") in {"running", "backoff", "paused"}]
    pool = running or candidates
    pool.sort(key=lambda j: (str(j.updated_at or ""), str(j.created_at or "")), reverse=True)
    return pool[0]


def _parse_accounting_line(line: str, *, path: str = "") -> Optional[dict]:
    """Parse one accounting line.

    Supports:
    - NDJSON: one JSON object per line
    - CSV (with or without header)

    Output is best-effort.
    """
    s = (line or "").strip()
    if not s:
        return None

    # NDJSON
    if s.startswith("{") and s.endswith("}"):
        try:
            ev = json.loads(s)
            if isinstance(ev, dict):
                return ev
        except Exception:
            return None

    # CSV
    delim = ","
    if "\t" in s and s.count("\t") >= s.count(","):
        delim = "\t"
    elif ";" in s and s.count(";") > s.count(","):
        delim = ";"

    try:
        fields = next(csv.reader([s], delimiter=delim))
        fields = [x.strip() for x in fields]
    except Exception:
        return None

    # Header detection
    if fields and any(x.lower() in {"type", "event", "rcpt", "recipient", "msgid", "message-id", "message_id"} for x in fields):
        _PMTA_ACC_HEADERS[path or ""] = [x.strip().lower() for x in fields]
        return None

    hdr = _PMTA_ACC_HEADERS.get(path or "") or []
    ev: Dict[str, Any] = {"raw": s}

    if hdr and len(hdr) == len(fields):
        for k, v in zip(hdr, fields):
            if k:
                ev[k] = v
        return ev

    # Heuristic fallback
    if fields:
        ev["type"] = fields[0]

    # Common PMTA acct CSV fallback mapping (no header).
    # Example:
    # b,<time>,<time>,mailfrom,rcpt,,failed,5.1.1 (...),"smtp;550 ...",...
    if len(fields) >= 9:
        ev["mailfrom"] = fields[3]
        ev["rcpt"] = fields[4]
        ev["status"] = fields[6]
        ev["dsnStatus"] = fields[7]
        ev["dsnDiag"] = fields[8]

    # Recipient fallback: prefer 2nd email-looking token (mailfrom is usually first).
    em_pos = [(i, (f or "").strip()) for i, f in enumerate(fields) if EMAIL_RE.match((f or "").strip())]
    if em_pos:
        if len(em_pos) >= 2:
            ev["rcpt"] = em_pos[1][1]
        elif "rcpt" not in ev:
            ev["rcpt"] = em_pos[0][1]

    for f in fields:
        if "@local" in f or "<" in f:
            ev["msgid"] = f
            break

    return ev


def _normalize_accounting_event(ev: dict) -> dict:
    """Normalize common PMTA/accounting header fields to stable aliases."""
    if not isinstance(ev, dict):
        return {}
    out = dict(ev)
    for k, v in list(ev.items()):
        kk = str(k or "").strip().lower().replace("_", "-")
        if not kk:
            continue
        vv = str(v or "").strip()
        if not vv:
            continue
        if "x-job-id" in kk and not out.get("x-job-id"):
            out["x-job-id"] = vv
        if "x-campaign-id" in kk and not out.get("x-campaign-id"):
            out["x-campaign-id"] = vv
        if "message-id" in kk and not out.get("message-id"):
            out["message-id"] = vv
    return out


def _push_outcome_bucket(job: SendJob, kind: str):
    try:
        now_min = int(time.time() // 60)
        if job.outcome_series and int(job.outcome_series[-1].get("t_min") or 0) == now_min:
            b = job.outcome_series[-1]
        else:
            b = {"t_min": now_min, "delivered": 0, "bounced": 0, "deferred": 0, "complained": 0}
            job.outcome_series.append(b)
            if len(job.outcome_series) > 180:
                job.outcome_series = job.outcome_series[-140:]
        if kind in b:
            b[kind] = int(b.get(kind) or 0) + 1
    except Exception:
        pass


def _apply_outcome_to_job(job: SendJob, rcpt: str, kind: str) -> None:
    """Update job counters in a 'unique per recipient' way using SQLite job_outcomes."""
    r = (rcpt or "").strip().lower()
    k = (kind or "").strip().lower()
    if not r or k not in {"delivered", "bounced", "deferred", "complained"}:
        return

    prev = db_get_outcome(job.id, r)

    # Don't downgrade finals to deferred
    if prev in {"delivered", "bounced", "complained"} and k == "deferred":
        return

    if prev == k:
        _push_outcome_bucket(job, k)
        job.accounting_last_ts = now_iso()
        return

    def dec(st: str):
        if st == "delivered":
            job.delivered = max(0, int(job.delivered or 0) - 1)
        elif st == "bounced":
            job.bounced = max(0, int(job.bounced or 0) - 1)
        elif st == "deferred":
            job.deferred = max(0, int(job.deferred or 0) - 1)
        elif st == "complained":
            job.complained = max(0, int(job.complained or 0) - 1)

    def inc(st: str):
        if st == "delivered":
            job.delivered = int(job.delivered or 0) + 1
        elif st == "bounced":
            job.bounced = int(job.bounced or 0) + 1
        elif st == "deferred":
            job.deferred = int(job.deferred or 0) + 1
        elif st == "complained":
            job.complained = int(job.complained or 0) + 1

    if prev:
        dec(prev)
    inc(k)

    db_set_outcome(job.id, r, k)
    _push_outcome_bucket(job, k)
    job.accounting_last_ts = now_iso()


def _classify_accounting_response(ev: dict, typ: str) -> Tuple[str, str]:
    """Return (kind, full_error_text) using accounting response data.

    kind is one of: accepted, temporary_error, blocked.
    """
    bits = [
        _event_value(ev, "response", "smtp-response", "smtp_response"),
        _event_value(ev, "dsnStatus", "dsn_status", "enhanced-status", "enhanced_status"),
        _event_value(ev, "dsnDiag", "dsn_diag", "diag", "diagnostic", "smtp-diagnostic"),
        _event_value(ev, "status", "result", "state"),
    ]
    parts = [str(x).strip() for x in bits if str(x or "").strip()]
    full = " | ".join(parts)

    probe = " ".join(parts).lower()
    code_match = re.search(r"\b([245])[0-9]{2}\b", probe)
    if not code_match:
        code_match = re.search(r"\b([245])\.[0-9]\.[0-9]\b", probe)

    if code_match:
        lead = code_match.group(1)
        if lead == "2":
            return "accepted", full
        if lead == "4":
            return "temporary_error", full
        if lead == "5":
            return "blocked", full

    # Fallback from normalized outcome when code is missing.
    t = (typ or "").strip().lower()
    if t == "delivered":
        return "accepted", full
    if t == "deferred":
        return "temporary_error", full
    if t in {"bounced", "complained"}:
        return "blocked", full
    return "temporary_error", full


def _record_accounting_error(job: SendJob, rcpt: str, typ: str, ev: dict) -> None:
    kind, detail = _classify_accounting_response(ev, typ)
    job.accounting_error_counts[kind] = int(job.accounting_error_counts.get(kind, 0) or 0) + 1
    entry = {
        "ts": now_iso(),
        "email": (rcpt or "").strip(),
        "type": typ,
        "kind": kind,
        "detail": detail,
    }
    job.accounting_last_errors.append(entry)
    if len(job.accounting_last_errors) > 80:
        job.accounting_last_errors = job.accounting_last_errors[-40:]


def process_pmta_accounting_event(ev: dict) -> dict:
    """Process one accounting event dict. Returns small result info."""
    if not isinstance(ev, dict):
        return {"ok": False, "reason": "not_dict"}
    ev = _normalize_accounting_event(ev)

    typ = _normalize_outcome_type(
        ev.get("type")
        or ev.get("event")
        or ev.get("kind")
        or ev.get("record")
        or ev.get("status")
        or ev.get("result")
        or ev.get("state")
    )
    if typ not in {"delivered", "bounced", "deferred", "complained"}:
        typ = _normalize_outcome_type(
            ev.get("dsnAction")
            or ev.get("dsn_action")
            or ev.get("dsnStatus")
            or ev.get("dsn_status")
            or ev.get("dsnDiag")
            or ev.get("dsn_diag")
        )

    rcpt = (
        ev.get("rcpt")
        or ev.get("recipient")
        or ev.get("email")
        or ev.get("to")
        or ev.get("rcpt_to")
        or ""
    )
    rcpt = str(rcpt or "").strip()

    job_id = _event_value(ev, "x-job-id", "job-id", "job_id", "jobid").lower()
    campaign_id = _event_value(ev, "x-campaign-id", "campaign-id", "campaign_id", "cid")

    if not job_id:
        msgid = _event_value(ev, "msgid", "message-id", "message_id", "messageid", "header_message-id", "header_message_id")
        if not msgid:
            # Pick any field that looks like a Message-ID header (different acct-file schemas)
            for k, v in (ev or {}).items():
                kk = str(k or "").lower().replace("_", "-")
                if "message-id" in kk:
                    msgid = v
                    break
        job_id = _extract_job_id_from_text(str(msgid or ""))

    if not job_id:
        job_id = _extract_job_id_from_text(str(ev.get("raw") or ""))

    if not rcpt or typ not in {"delivered", "bounced", "deferred", "complained"}:
        return {"ok": False, "reason": "missing_fields", "job_id": job_id, "campaign_id": campaign_id, "rcpt": rcpt, "type": typ}

    with JOBS_LOCK:
        job = JOBS.get(job_id) if job_id else None
        if not job and campaign_id:
            job = _find_job_by_campaign(campaign_id)
        if not job and rcpt:
            job = _find_job_by_recipient(rcpt)
        if not job:
            return {"ok": False, "reason": "job_not_found", "job_id": job_id, "campaign_id": campaign_id, "rcpt": rcpt}

        _apply_outcome_to_job(job, rcpt, typ)
        _record_accounting_error(job, rcpt, typ, ev)
        job.maybe_persist()

    return {"ok": True, "job_id": job.id, "campaign_id": job.campaign_id, "type": typ, "rcpt": rcpt}


def process_campaign_accounting_payload(payload: dict) -> dict:
    """Process middleware payload grouped by campaign_id.

    Expected shape:
      {
        "campaign_id": "...",
        "outcomes": [
          {"recipient": "a@b.com", "status": "bounced", "job_id": "..."},
          ...
        ]
      }
    """
    if not isinstance(payload, dict):
        return {"ok": False, "error": "invalid_payload", "processed": 0, "accepted": 0}

    campaign_id = str(payload.get("campaign_id") or "").strip()
    outcomes = payload.get("outcomes")
    if not campaign_id:
        return {"ok": False, "error": "missing_campaign_id", "processed": 0, "accepted": 0}
    if not isinstance(outcomes, list):
        return {"ok": False, "error": "missing_outcomes", "processed": 0, "accepted": 0}

    processed = 0
    accepted = 0
    with JOBS_LOCK:
        fallback_job = _find_job_by_campaign(campaign_id)
        for item in outcomes:
            if not isinstance(item, dict):
                continue
            processed += 1
            rcpt = str(item.get("recipient") or item.get("rcpt") or item.get("email") or "").strip()
            typ = _normalize_outcome_type(item.get("status") or item.get("type") or item.get("event"))
            if not rcpt or typ not in {"delivered", "bounced", "deferred", "complained"}:
                continue

            jid = str(item.get("job_id") or item.get("jobId") or "").strip().lower()
            job = JOBS.get(jid) if jid else None
            if not job or (job.campaign_id or "") != campaign_id:
                job = fallback_job
            if not job:
                continue

            _apply_outcome_to_job(job, rcpt, typ)
            _record_accounting_error(job, rcpt, typ, item)
            job.maybe_persist()
            accepted += 1

    return {"ok": True, "campaign_id": campaign_id, "processed": processed, "accepted": accepted}



def _bridge_collect_pull_targets() -> List[Dict[str, str]]:
    """Collect targeted pull scopes for bridge requests.

    - job: events for one job (multiple recipients)
    - campaign: events for one campaign
    - message: optional one-email scope when message-id is available
    """
    mode = (PMTA_BRIDGE_PULL_TARGET_MODE or "auto").strip().lower()
    if mode in {"", "off", "none"}:
        mode = "all"

    targets: List[Dict[str, str]] = []
    with JOBS_LOCK:
        jobs = [j for j in JOBS.values() if not bool(j.deleted)]

    def _add(kind: str, value: str):
        vv = str(value or "").strip()
        if not vv:
            return
        key = f"{kind}:{vv.lower()}"
        if any(t.get("_k") == key for t in targets):
            return
        t = {"scope": kind}
        if kind == "job":
            t["x-job-id"] = vv
        elif kind == "campaign":
            t["x-campaign-id"] = vv
        elif kind == "message":
            t["message-id"] = vv
        t["_k"] = key
        targets.append(t)

    interesting = [j for j in jobs if (j.status or "") in {"running", "backoff", "paused", "queued"}]
    if not interesting:
        interesting = jobs

    if mode in {"auto", "job"}:
        for j in interesting:
            _add("job", j.id)
    if mode in {"auto", "campaign"}:
        for j in interesting:
            _add("campaign", j.campaign_id)

    if mode == "all" or not targets:
        return [{"scope": "all"}]

    lim = max(1, int(PMTA_BRIDGE_PULL_TARGET_LIMIT or 1))
    if len(targets) > lim:
        targets = targets[:lim]

    for t in targets:
        t.pop("_k", None)
    return targets


def _bridge_pick_target(targets: List[Dict[str, str]]) -> Dict[str, str]:
    if not targets:
        return {"scope": "all"}
    global _BRIDGE_TARGET_CURSOR
    with _BRIDGE_TARGET_CURSOR_LOCK:
        idx = int(_BRIDGE_TARGET_CURSOR or 0) % len(targets)
        _BRIDGE_TARGET_CURSOR = idx + 1
    return targets[idx]

def _poll_accounting_bridge_once() -> dict:
    t0 = time.time()
    url = (PMTA_BRIDGE_PULL_URL or "").strip()
    if not url:
        _bridge_debug_update(
            last_attempt_ts=now_iso(),
            attempts=int(_BRIDGE_DEBUG_STATE.get("attempts", 0)) + 1,
            last_ok=False,
            connected=False,
            last_error="bridge_pull_url_not_configured",
            last_duration_ms=int((time.time() - t0) * 1000),
        )
        return {"ok": False, "error": "bridge_pull_url_not_configured", "processed": 0, "accepted": 0}

    # Accept a bare host:port and default to HTTP to avoid urlopen failures
    # like "unknown url type: 194.116.172.135".
    if url and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = f"http://{url}"

    # Allow passing a base bridge URL (e.g. http://host:8090) and normalize it
    # to the pull endpoint expected by this poller.
    if "/api/v1/pull/latest" not in url:
        url = url.rstrip("/") + "/api/v1/pull/latest"

    sep = "&" if "?" in url else "?"
    req_url = (
        f"{url}{sep}kind={quote_plus(PMTA_BRIDGE_PULL_KIND or 'acct')}"
        f"&max_lines={max(1, int(PMTA_BRIDGE_PULL_MAX_LINES or 1))}"
        f"&all={1 if PMTA_BRIDGE_PULL_ALL_FILES else 0}"
    )

    target = _bridge_pick_target(_bridge_collect_pull_targets())
    _bridge_debug_update(last_req_url=req_url, last_target=target)

    headers = {"Accept": "application/json"}
    if PMTA_BRIDGE_PULL_TOKEN:
        headers["Authorization"] = f"Bearer {PMTA_BRIDGE_PULL_TOKEN}"
    if isinstance(target, dict):
        if target.get("x-job-id"):
            headers["X-Job-ID"] = str(target.get("x-job-id"))
        if target.get("x-campaign-id"):
            headers["X-Campaign-ID"] = str(target.get("x-campaign-id"))
        if target.get("message-id"):
            headers["Message-ID"] = str(target.get("message-id"))

    try:
        req = Request(req_url, headers=headers, method="GET")
        with urlopen(req, timeout=20) as resp:
            code = getattr(resp, "status", None)
            raw = (resp.read() or b"{}").decode("utf-8", errors="replace")
        _bridge_debug_update(last_http_ok=True, last_http_status=code)
    except Exception as e:
        _bridge_debug_update(
            last_attempt_ts=now_iso(),
            attempts=int(_BRIDGE_DEBUG_STATE.get("attempts", 0)) + 1,
            last_ok=False,
            connected=False,
            failure_count=int(_BRIDGE_DEBUG_STATE.get("failure_count", 0)) + 1,
            last_error_ts=now_iso(),
            last_error=f"bridge_request_failed: {e}",
            last_http_ok=False,
            last_duration_ms=int((time.time() - t0) * 1000),
        )
        return {"ok": False, "error": f"bridge_request_failed: {e}", "processed": 0, "accepted": 0}

    try:
        obj = json.loads(raw)
    except Exception:
        _bridge_debug_update(
            last_attempt_ts=now_iso(),
            attempts=int(_BRIDGE_DEBUG_STATE.get("attempts", 0)) + 1,
            last_ok=False,
            connected=False,
            failure_count=int(_BRIDGE_DEBUG_STATE.get("failure_count", 0)) + 1,
            last_error_ts=now_iso(),
            last_error="invalid_bridge_json",
            last_duration_ms=int((time.time() - t0) * 1000),
        )
        return {"ok": False, "error": "invalid_bridge_json", "processed": 0, "accepted": 0}

    lines = obj.get("lines") if isinstance(obj, dict) else None

    # Some bridges return structured rows instead of raw accounting lines,
    # for example: {"results":[{"email":"a@b.com","status":"failed"}, ...]}
    # We support both forms.
    bridge_rows: List[Any] = []
    if isinstance(lines, list):
        bridge_rows = list(lines)
    elif isinstance(obj, dict):
        for key in ("outcomes", "results", "messages", "items", "rows", "data"):
            v = obj.get(key)
            if isinstance(v, list):
                bridge_rows = v
                break

    if not isinstance(bridge_rows, list):
        _bridge_debug_update(
            last_attempt_ts=now_iso(),
            attempts=int(_BRIDGE_DEBUG_STATE.get("attempts", 0)) + 1,
            last_ok=False,
            connected=False,
            failure_count=int(_BRIDGE_DEBUG_STATE.get("failure_count", 0)) + 1,
            last_error_ts=now_iso(),
            last_error="invalid_bridge_payload",
            last_response_keys=list(obj.keys()) if isinstance(obj, dict) else [],
            last_duration_ms=int((time.time() - t0) * 1000),
        )
        return {"ok": False, "error": "invalid_bridge_payload", "processed": 0, "accepted": 0}

    processed = 0
    accepted = 0
    for row in bridge_rows:
        ev: Optional[dict] = None
        if isinstance(row, dict):
            ev = row
        else:
            s = str(row or "").strip()
            if not s:
                continue
            ev = _parse_accounting_line(s, path="bridge")
        if not ev:
            continue
        res = process_pmta_accounting_event(ev)
        processed += 1
        accepted += 1 if res.get("ok") else 0

    _bridge_debug_update(
        last_attempt_ts=now_iso(),
        last_success_ts=now_iso(),
        attempts=int(_BRIDGE_DEBUG_STATE.get("attempts", 0)) + 1,
        success_count=int(_BRIDGE_DEBUG_STATE.get("success_count", 0)) + 1,
        last_ok=True,
        connected=True,
        last_error="",
        last_bridge_count=len(bridge_rows),
        last_processed=processed,
        last_accepted=accepted,
        last_response_keys=list(obj.keys()) if isinstance(obj, dict) else [],
        last_lines_sample=[str(x)[:220] for x in bridge_rows[:3]],
        last_duration_ms=int((time.time() - t0) * 1000),
    )
    return {"ok": True, "processed": processed, "accepted": accepted, "count": len(bridge_rows)}


def _accounting_bridge_poller_thread():
    while True:
        try:
            _poll_accounting_bridge_once()
        except Exception:
            pass
        time.sleep(max(1.0, float(PMTA_BRIDGE_PULL_S or 5.0)))


def start_accounting_bridge_poller_if_needed():
    global _BRIDGE_POLLER_STARTED
    if not PMTA_BRIDGE_PULL_ENABLED:
        return
    with _BRIDGE_POLLER_LOCK:
        if _BRIDGE_POLLER_STARTED:
            return
        t = threading.Thread(target=_accounting_bridge_poller_thread, daemon=True)
        t.start()
        _BRIDGE_POLLER_STARTED = True


# Start PMTA accounting bridge poller if configured.
start_accounting_bridge_poller_if_needed()


# =========================
# SMTP Sender
# =========================

def _smtp_connect(
    smtp_host: str,
    smtp_port: int,
    smtp_security: str,
    smtp_timeout: int,
) -> smtplib.SMTP:
    if smtp_security == "ssl":
        context = ssl.create_default_context()
        return smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=smtp_timeout, context=context)

    server = smtplib.SMTP(smtp_host, smtp_port, timeout=smtp_timeout)
    server.ehlo()
    if smtp_security == "starttls":
        context = ssl.create_default_context()
        server.starttls(context=context)
        server.ehlo()
    return server


def smtp_send_job(
    job_id: str,
    smtp_host: str,
    smtp_port: int,
    smtp_security: str,  # starttls | ssl | none
    smtp_timeout: int,
    smtp_user: str,
    smtp_pass: str,
    sender_names: List[str],
    sender_emails: List[str],
    subjects: List[str],
    reply_to: str,
    body_format: str,  # text | html
    body: str,
    recipients: List[str],
    delay_s: float,
    urls_list: List[str],
    src_list: List[str],
    chunk_size: int,
    thread_workers: int,
    sleep_chunks: float,
    enable_backoff: bool,
    use_ai_rewrite: bool,
    ai_token: str,
):
    """Send job in chunks.

    Key behaviors:
    - Per-CHUNK preflight (Spam score + DNSBL/DBL blacklist checks)
    - Global backoff (option 2): if a chunk is blocked, the whole job pauses and retries that chunk.
    - Rotates sender/subject/body per chunk, and on retry uses next variant (chunk_idx + attempt).
    - Optional AI rewrite chain: when enabled, each chunk rewrites the previous chunk content,
      then uses that rewritten subject/body for sending.
    - Live settings sync (phase 1): before each chunk + each retry, we read campaign_form from SQLite and apply
      delay/workers/sleep/spam_threshold + sender/subject/body lists.
    """

    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job.status = "running"
        job.started_at = job.started_at or now_iso()
        job.updated_at = now_iso()
        job.log(
            "INFO",
            f"Starting job. total={len(recipients)} host={smtp_host}:{smtp_port} security={smtp_security} chunk_size={chunk_size} workers={thread_workers} sleep_chunks={sleep_chunks}s",
        )

    # Guardrails
    if not sender_emails:
        with JOBS_LOCK:
            job.status = "error"
            job.last_error = "No sender emails available"
            job.log("ERROR", job.last_error)
        return

    if not sender_names:
        sender_names = ["Sender"]
    if not subjects:
        subjects = ["(no subject)"]

    ai_enabled = bool(use_ai_rewrite and (ai_token or "").strip())
    ai_subject_chain = [str(x).strip() for x in (subjects or []) if str(x).strip()] or ["(no subject)"]
    ai_body_chain = str(body or "")

    smtp_host_ips = _resolve_ipv4(smtp_host) if smtp_host else []

    # PMTA live polling (Jobs UI)
    last_pmta_live = 0.0
    last_pmta_domains = 0.0
    last_pmta_pressure = 0.0
    last_pressure_level = 0
    last_health_level = -1

    # Backoff tuning
    max_backoff_retries = max(0, min(10, int(cfg_get_int("BACKOFF_MAX_RETRIES", 3))))
    backoff_base_s = max(1.0, float(cfg_get_float("BACKOFF_BASE_S", 60.0)))
    backoff_max_s = max(backoff_base_s, float(cfg_get_float("BACKOFF_MAX_S", 1800.0)))
    backoff_enabled = bool(enable_backoff)

    def _should_stop() -> bool:
        with JOBS_LOCK:
            return bool(job.stop_requested)

    def _wait_ready() -> bool:
        """Wait while paused. Return False if stop requested."""
        while True:
            with JOBS_LOCK:
                if job.stop_requested:
                    return False
                paused = bool(job.paused)
                st = job.status
            if not paused:
                return True
            # show paused status (unless we're already in backoff)
            with JOBS_LOCK:
                if job.status not in {"backoff", "error", "done", "stopped"}:
                    job.status = "paused"
            time.sleep(0.35)

    def _sleep_checked(seconds: float) -> bool:
        """Sleep in small steps so pause/stop works during long waits."""
        end = time.time() + max(0.0, float(seconds or 0.0))
        while time.time() < end:
            if not _wait_ready():
                return False
            # small slice
            time.sleep(min(0.35, max(0.0, end - time.time())))
        return True

    def _stop_job(reason: str):
        with JOBS_LOCK:
            job.status = "stopped"
            job.stop_reason = reason or job.stop_reason or "stopped"
            job.current_chunk = -1
            job.current_chunk_info = {}
            job.current_chunk_domains = {}
            job.log("WARN", f"Job stopped: {job.stop_reason}")
            job.maybe_persist(force=True)

    def _runtime_overrides() -> dict:
        form = db_get_campaign_form_raw(job.campaign_id)
        if not isinstance(form, dict):
            return {}

        def as_int(key: str, default: int) -> int:
            try:
                v = str(form.get(key, "") or "").strip()
                return int(v) if v else default
            except Exception:
                return default

        def as_float(key: str, default: float) -> float:
            try:
                v = str(form.get(key, "") or "").strip()
                return float(v) if v else default
            except Exception:
                return default

        def as_bool(key: str, default: bool) -> bool:
            val = form.get(key, default)
            if isinstance(val, bool):
                return val
            s = str(val or "").strip().lower()
            if s in {"1", "true", "yes", "on"}:
                return True
            if s in {"0", "false", "no", "off"}:
                return False
            return bool(default)

        out: Dict[str, Any] = {}

        out["chunk_size"] = max(1, min(50000, as_int("chunk_size", chunk_size)))
        out["thread_workers"] = max(1, min(200, as_int("thread_workers", thread_workers)))
        out["sleep_chunks"] = max(0.0, min(120.0, as_float("sleep_chunks", sleep_chunks)))
        out["delay_s"] = max(0.0, min(10.0, as_float("delay_s", delay_s)))
        out["enable_backoff"] = as_bool("enable_backoff", backoff_enabled)

        # spam threshold can change while running
        try:
            st = float(str(form.get("score_range", "") or "").strip() or str(job.spam_threshold))
        except Exception:
            st = job.spam_threshold
        out["spam_threshold"] = max(1.0, min(10.0, st))

        # sender + subject lists
        out["from_names"] = parse_multiline(str(form.get("from_name") or ""), dedupe_lower=False) or sender_names
        em_raw = parse_multiline(str(form.get("from_email") or ""), dedupe_lower=True)
        v_em, _ = filter_valid_emails(em_raw)
        out["from_emails"] = v_em or sender_emails
        out["subjects"] = parse_multiline(str(form.get("subject") or ""), dedupe_lower=False) or subjects

        # message
        out["body_format"] = str(form.get("body_format") or body_format).strip().lower() or body_format
        btxt = str(form.get("body") or "").strip()
        out["body_variants"] = split_body_variants(btxt) if btxt else split_body_variants(body)
        out["reply_to"] = str(form.get("reply_to") or reply_to).strip() or reply_to

        out["urls_list"] = parse_multiline(str(form.get("urls_list") or ""), dedupe_lower=False) or urls_list
        out["src_list"] = parse_multiline(str(form.get("src_list") or ""), dedupe_lower=False) or src_list

        return out

    def _blacklist_check(from_email: str) -> Tuple[bool, str]:
        """Return (should_backoff, detail).

        Sender-domain DNSBL hits are reported for visibility but do not trigger
        chunk backoff, because this signal can be noisy for shared/content
        domains. SMTP host IP DNSBL hits trigger backoff only when SEND_DNSBL is disabled.
        """
        parts: List[str] = []
        listed = False

        dom = _extract_domain_from_email(from_email)
        if dom:
            dl = check_domain_dnsbl(dom)
            if dl:
                zones = ",".join(x.get("zone", "") for x in dl if x.get("zone"))
                parts.append(f"domain:{dom}=>{zones or 'listed'} (info-only)")

        for ip in smtp_host_ips:
            hits = check_ip_dnsbl(ip)
            if hits:
                listed = listed or (not SEND_DNSBL)
                zones = ",".join(x.get("zone", "") for x in hits if x.get("zone"))
                mode = "send-enabled" if SEND_DNSBL else "backoff-enabled"
                parts.append(f"ip:{ip}=>{zones or 'listed'} ({mode})")

        return listed, " | ".join([p for p in parts if p])

    def _spam_check(from_email: str, subject: str, body_text: str, body_format2: str) -> Tuple[Optional[float], str]:
        return compute_spam_score(subject=subject, body=body_text, body_format=body_format2, from_email=from_email)

    def _smtp_code_class(detail: str) -> Optional[int]:
        txt = (detail or "").strip()
        if not txt:
            return None
        m = SMTP_CODE_RE.search(txt)
        if m:
            try:
                return int(m.group(1))
            except Exception:
                return None
        m2 = SMTP_ENHANCED_CODE_RE.search(txt)
        if m2:
            try:
                return int(m2.group(1))
            except Exception:
                return None
        return None

    def _accounting_health_policy(
        *,
        workers: int,
        delay: float,
        chunk_sz: int,
        sleep_between: float,
    ) -> dict:
        """Adaptive throttle based on live accounting + SMTP response classes."""
        with JOBS_LOCK:
            delivered = int(job.delivered or 0)
            bounced = int(job.bounced or 0)
            deferred = int(job.deferred or 0)
            complained = int(job.complained or 0)
            recent_results = list(job.recent_results or [])[-140:]

        smtp_4xx = 0
        smtp_5xx = 0
        smtp_sample = 0
        for rr in recent_results:
            if not isinstance(rr, dict):
                continue
            if bool(rr.get("ok")):
                continue
            code_cls = _smtp_code_class(str(rr.get("detail") or ""))
            if code_cls is None:
                continue
            smtp_sample += 1
            if code_cls == 4:
                smtp_4xx += 1
            elif code_cls == 5:
                smtp_5xx += 1

        total_outcomes = delivered + bounced + deferred + complained
        bad_weighted = bounced + complained + (deferred * 0.6)
        bad_ratio = (float(bad_weighted) / float(total_outcomes)) if total_outcomes > 0 else 0.0
        smtp_4xx_ratio = (float(smtp_4xx) / float(smtp_sample)) if smtp_sample > 0 else 0.0
        smtp_5xx_ratio = (float(smtp_5xx) / float(smtp_sample)) if smtp_sample > 0 else 0.0

        level = 0
        if complained >= 3 or bad_ratio >= 0.35 or smtp_5xx_ratio >= 0.20:
            level = 3
        elif bad_ratio >= 0.20 or smtp_5xx_ratio >= 0.10 or smtp_4xx_ratio >= 0.30:
            level = 2
        elif bad_ratio >= 0.10 or smtp_4xx_ratio >= 0.12:
            level = 1

        new_workers = int(max(1, workers))
        new_delay = float(max(0.0, delay))
        new_chunk = int(max(1, chunk_sz))
        new_sleep = float(max(0.0, sleep_between))
        action = "steady"

        if level == 1:
            new_workers = min(new_workers, 8)
            new_chunk = min(new_chunk, 220)
            new_delay = max(new_delay, 0.05)
            action = "soft_slowdown"
        elif level == 2:
            new_workers = min(new_workers, 4)
            new_chunk = min(new_chunk, 120)
            new_delay = max(new_delay, 0.20)
            new_sleep = max(new_sleep, 0.30)
            action = "slowdown"
        elif level == 3:
            new_workers = min(new_workers, 2)
            new_chunk = min(new_chunk, 60)
            new_delay = max(new_delay, 0.60)
            new_sleep = max(new_sleep, 1.00)
            action = "hard_slowdown"
        else:
            # Healthy signals: gently recover throughput.
            if total_outcomes >= 80 and bad_ratio <= 0.03 and smtp_5xx == 0:
                new_workers = min(200, new_workers + 1)
                new_chunk = min(50000, max(new_chunk, int(new_chunk * 1.20)))
                if new_delay > 0:
                    new_delay = max(0.0, round(new_delay * 0.70, 3))
                action = "speed_up"

        reduced = (
            (new_workers < int(max(1, workers)))
            or (new_chunk < int(max(1, chunk_sz)))
            or (new_delay > float(max(0.0, delay)))
            or (new_sleep > float(max(0.0, sleep_between)))
        )

        reason = (
            f"lvl={level} outcomes={total_outcomes} bad={bad_ratio:.2f} "
            f"smtp4xx={smtp_4xx}/{smtp_sample} smtp5xx={smtp_5xx}/{smtp_sample}"
        )
        return {
            "ok": True,
            "level": level,
            "action": action,
            "reason": reason,
            "metrics": {
                "delivered": delivered,
                "bounced": bounced,
                "deferred": deferred,
                "complained": complained,
                "smtp_sample": smtp_sample,
                "smtp_4xx": smtp_4xx,
                "smtp_5xx": smtp_5xx,
            },
            "applied": {
                "workers": int(new_workers),
                "chunk_size": int(new_chunk),
                "delay_s": float(new_delay),
                "sleep_chunks": float(new_sleep),
            },
            "reduced": bool(reduced),
        }

    def _render_body(local_rng: random.Random, base_body: str, urls2: List[str], src2: List[str]) -> str:
        rendered = base_body
        if "[URL]" in rendered:
            rendered = rendered.replace("[URL]", local_rng.choice(urls2) if urls2 else "")
        if "[SRC]" in rendered:
            rendered = rendered.replace("[SRC]", local_rng.choice(src2) if src2 else "")
        return rendered

    def _send_chunk(
        *,
        chunk_idx: int,
        chunk_rcpts: List[str],
        from_name: str,
        from_email: str,
        subject: str,
        body_used: str,
        body_format2: str,
        reply_to2: str,
        delay2: float,
        workers2: int,
        urls2: List[str],
        src2: List[str],
    ):
        def worker_send(worker_idx: int, rcpts: List[str]):
            if not rcpts:
                return

            local_rng = random.Random(f"{job_id}:{chunk_idx}:{worker_idx}")
            server = None
            try:
                server = _smtp_connect(smtp_host, smtp_port, smtp_security, smtp_timeout)
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)

                for rcpt in rcpts:
                    if not _wait_ready():
                        return

                    db_mark_job_recipient(job_id, job.campaign_id or "", rcpt)

                    msg = EmailMessage()
                    msg["From"] = formataddr((from_name, from_email))
                    msg["To"] = rcpt
                    msg["Subject"] = subject
                    msg["Date"] = format_datetime(datetime.now(timezone.utc))
                    # App trace header (helps searching in downstream logs/accounting)
                    msg["X-Job-ID"] = job_id
                    msg["X-Campaign-ID"] = (job.campaign_id or "")
                    msg["X-App-Job"] = job_id
                    msg["X-App-Chunk"] = str(chunk_idx)

                    # Message-ID carries job_id + campaign_id + chunk/worker for offline matching
                    msg["Message-ID"] = f"<{uuid.uuid4().hex}.{job_id}.{(job.campaign_id or 'none')}.c{chunk_idx}.w{worker_idx}@local>"
                    if reply_to2.strip():
                        msg["Reply-To"] = reply_to2.strip()

                    rendered_body = _render_body(local_rng, body_used, urls2, src2)

                    if body_format2 == "html":
                        msg.set_content("This email contains HTML content. Please view it in an HTML-capable client.")
                        msg.add_alternative(rendered_body, subtype="html")
                    else:
                        msg.set_content(rendered_body)

                    dom = _extract_domain_from_email(rcpt)

                    try:
                        server.send_message(msg)
                        with JOBS_LOCK:
                            job.sent += 1
                            if dom:
                                job.domain_sent[dom] = job.domain_sent.get(dom, 0) + 1
                            job.push_result(rcpt, True, f"sent (chunk={chunk_idx})")
                    except Exception as e:
                        # Point (7): fast diagnosis (client vs PMTA queue vs remote throttling)
                        diag = {}
                        try:
                            diag = pmta_diag_on_error(smtp_host=smtp_host, rcpt=rcpt, exc=e)
                        except Exception:
                            diag = {}

                        extra = ""
                        try:
                            if isinstance(diag, dict) and diag.get("enabled") and diag.get("ok"):
                                cls = str(diag.get("class") or "")
                                domx = str(diag.get("domain") or "")
                                qdef = int(diag.get("queue_deferrals") or 0)
                                qerr = int(diag.get("queue_errors") or 0)
                                rh = str(diag.get("remote_hint") or "")
                                sample = diag.get("errors_sample") or []
                                s1 = (" / ".join(str(x) for x in sample[:2])[:140]) if sample else ""
                                extra = f" | diag={cls} dom={domx} def={qdef} err={qerr}" + (f" hint={rh}" if rh else "") + (f" sample={s1}" if s1 else "")
                        except Exception:
                            extra = ""

                        with JOBS_LOCK:
                            job.failed += 1
                            job.last_error = str(e)
                            job.record_error(str(e))
                            if dom:
                                job.domain_failed[dom] = job.domain_failed.get(dom, 0) + 1

                            # Store last diagnostic snapshot on the job (visible in Jobs UI)
                            if isinstance(diag, dict) and diag.get("enabled"):
                                job.pmta_diag = diag
                                job.pmta_diag_ts = str(diag.get("ts") or now_iso())

                            job.push_result(rcpt, False, str(e) + extra)
                            job.log("ERROR", f"Failed {rcpt}: {e}{extra}")

                    if delay2 > 0:
                        if not _sleep_checked(delay2):
                            return

            except Exception as e:
                with JOBS_LOCK:
                    job.failed += 1
                    job.last_error = str(e)
                    job.record_error(str(e))
                    job.log("ERROR", f"Worker error (chunk={chunk_idx} w={worker_idx}): {e}")
            finally:
                try:
                    if server:
                        server.quit()
                except Exception:
                    pass

        wc = max(1, min(int(workers2 or 1), len(chunk_rcpts)))
        groups: List[List[str]] = [[] for _ in range(wc)]
        for i2, r2 in enumerate(chunk_rcpts):
            groups[i2 % wc].append(r2)

        with ThreadPoolExecutor(max_workers=wc) as ex:
            futs = []
            for widx, g in enumerate(groups):
                if not g:
                    continue
                futs.append(ex.submit(worker_send, widx, g))
            for f in futs:
                f.result()

    try:
        # Dynamic chunking (chunk_size can change during run)
        total = len(recipients)
        chunk_idx = 0

        # Provider-aware queues: one recipient domain per queue.
        # Chunks are scheduled in round-robin between domains, so each domain/provider
        # gets short sending windows and cool-down gaps before its next chunk.
        provider_buckets, provider_order = build_provider_buckets(recipients)
        provider_cursor = 0

        # Per-provider sender rotation cursor: if a provider has many recipients,
        # chunk#1 can use sender/IP-A, chunk#2 sender/IP-B, ... then wrap.
        provider_sender_cursor: Dict[str, int] = {}
        # Backoff is scoped to relation: (receiver_domain, sender_domain).
        # This allows other receivers and other sender domains to keep flowing.
        relation_backoff_until: Dict[Tuple[str, str], float] = {}
        relation_backoff_attempts: Dict[Tuple[str, str], int] = {}
        provider_next_retry_ts: Dict[str, float] = {}

        def _remaining_total() -> int:
            return sum(len(v) for v in provider_buckets.values())

        def _next_ready_in() -> float:
            if not provider_next_retry_ts:
                return 0.0
            now_ts = time.time()
            waits = [max(0.0, float(v or 0.0) - now_ts) for v in provider_next_retry_ts.values() if float(v or 0.0) > now_ts]
            return min(waits) if waits else 0.0

        def _next_provider_domain() -> Optional[str]:
            nonlocal provider_cursor
            if not provider_order:
                return None
            now_ts = time.time()
            n = len(provider_order)
            for step in range(n):
                idx2 = (provider_cursor + step) % n
                dom2 = provider_order[idx2]
                if not provider_buckets.get(dom2):
                    continue
                wait_until = float(provider_next_retry_ts.get(dom2, 0.0) or 0.0)
                if wait_until > now_ts:
                    continue
                if dom2 in provider_next_retry_ts:
                    provider_next_retry_ts.pop(dom2, None)
                if provider_buckets.get(dom2):
                    provider_cursor = (idx2 + 1) % n
                    return dom2
            return None

        with JOBS_LOCK:
            # initial estimate
            cs0 = max(1, int(chunk_size or 1))
            job.chunks_total = (total + cs0 - 1) // cs0
            job.log("INFO", f"Prepared dynamic chunks (initial chunk_size={cs0}).")

        while _remaining_total() > 0:
            if not _wait_ready():
                _stop_job("stop requested")
                return

            rt = _runtime_overrides()

            cs = int(rt.get("chunk_size", chunk_size))
            workers2 = int(rt.get("thread_workers", thread_workers))
            sleep2 = float(rt.get("sleep_chunks", sleep_chunks))
            delay2 = float(rt.get("delay_s", delay_s))
            backoff_enabled = bool(rt.get("enable_backoff", backoff_enabled))
            job.spam_threshold = float(rt.get("spam_threshold", job.spam_threshold))

            from_names2 = rt.get("from_names") or sender_names
            from_emails2 = rt.get("from_emails") or sender_emails
            subjects2 = rt.get("subjects") or subjects
            body_format2 = str(rt.get("body_format") or body_format).strip().lower() or body_format
            body_variants2 = rt.get("body_variants") or split_body_variants(body)
            reply_to2 = str(rt.get("reply_to") or reply_to)
            urls2 = rt.get("urls_list") or urls_list
            src2 = rt.get("src_list") or src_list

            # PMTA pressure-based adaptive speed control (global)
            pmta_pressure_applied: Dict[str, Any] = {}
            health_policy_applied: Dict[str, Any] = {}

            # Adaptive policy from accounting + SMTP responses.
            try:
                health_policy_applied = _accounting_health_policy(
                    workers=workers2,
                    delay=delay2,
                    chunk_sz=cs,
                    sleep_between=sleep2,
                )
                if health_policy_applied.get("ok"):
                    ap = health_policy_applied.get("applied") or {}
                    workers2 = int(ap.get("workers") or workers2)
                    cs = int(ap.get("chunk_size") or cs)
                    delay2 = float(ap.get("delay_s") if ap.get("delay_s") is not None else delay2)
                    sleep2 = float(ap.get("sleep_chunks") if ap.get("sleep_chunks") is not None else sleep2)

                    h_lvl = int(health_policy_applied.get("level") or 0)
                    if h_lvl != int(last_health_level):
                        last_health_level = h_lvl
                        with JOBS_LOCK:
                            msg = f"Adaptive health policy level {h_lvl}: {health_policy_applied.get('reason','')}"
                            job.log("WARN" if h_lvl >= 2 else "INFO", msg)
            except Exception:
                health_policy_applied = {}

            if PMTA_PRESSURE_CONTROL:
                try:
                    # Refresh PMTA live snapshot (rate-limited)
                    if (time.time() - float(last_pmta_pressure or 0.0)) >= float(PMTA_PRESSURE_POLL_S or 3.0):
                        live = pmta_live_panel(smtp_host=smtp_host)
                        last_pmta_pressure = time.time()
                        with JOBS_LOCK:
                            job.pmta_live = live
                            job.pmta_live_ts = now_iso()
                        pol = pmta_pressure_policy_from_live(live)
                        pmta_pressure_applied = pol if isinstance(pol, dict) else {}
                        with JOBS_LOCK:
                            job.pmta_pressure = pmta_pressure_applied
                            job.pmta_pressure_ts = now_iso()
                    else:
                        with JOBS_LOCK:
                            pmta_pressure_applied = dict(job.pmta_pressure or {})

                    # Apply recommended caps
                    if pmta_pressure_applied and pmta_pressure_applied.get("ok"):
                        lvl = int(pmta_pressure_applied.get("level") or 0)
                        if lvl > 0:
                            dmin = pmta_pressure_applied.get("delay_min")
                            wmax = pmta_pressure_applied.get("workers_max")
                            cmax = pmta_pressure_applied.get("chunk_size_max")
                            smin = pmta_pressure_applied.get("sleep_min")

                            if isinstance(dmin, (int, float)):
                                delay2 = max(float(delay2 or 0.0), float(dmin))
                            if isinstance(smin, (int, float)):
                                sleep2 = max(float(sleep2 or 0.0), float(smin))
                            if isinstance(wmax, (int, float)):
                                workers2 = max(1, min(int(workers2 or 1), int(wmax)))
                            if isinstance(cmax, (int, float)):
                                cs = max(1, min(int(cs or 1), int(cmax)))

                            pmta_pressure_applied = dict(pmta_pressure_applied)
                            pmta_pressure_applied["applied"] = {
                                "delay_s": float(delay2 or 0.0),
                                "sleep_chunks": float(sleep2 or 0.0),
                                "workers": int(workers2 or 1),
                                "chunk_size": int(cs or 1),
                            }

                            if lvl != int(last_pressure_level or 0):
                                last_pressure_level = lvl
                                with JOBS_LOCK:
                                    job.log("WARN" if lvl >= 2 else "INFO", f"PMTA pressure level {lvl}: {pmta_pressure_applied.get('reason','')}")

                except Exception:
                    pmta_pressure_applied = {}

            target_domain = _next_provider_domain()
            if not target_domain:
                wait_for = _next_ready_in()
                if wait_for > 0 and _remaining_total() > 0:
                    with JOBS_LOCK:
                        job.status = "running"
                        job.log("INFO", f"All active receiver domains are in scoped backoff. wait={int(wait_for)}s")
                    if not _sleep_checked(min(wait_for, 2.0)):
                        _stop_job("stop requested")
                        return
                    continue
                break

            bucket = provider_buckets.get(target_domain) or []
            chunk = bucket[:cs]
            provider_buckets[target_domain] = bucket[len(chunk):]
            if not chunk:
                break

            # Live chunk info for Jobs UI
            dom_counts = count_recipient_domains(chunk)

            # PMTA per-domain snapshot (rate-limited) for big recipient domains
            if PMTA_DOMAIN_STATS:
                try:
                    if (time.time() - float(last_pmta_domains or 0.0)) >= float(PMTA_DOMAINS_POLL_S or 4.0):
                        # Pick top domains globally (job plan), then map them to /domains output
                        with JOBS_LOCK:
                            plan_copy = dict(job.domain_plan or {})
                        top = sorted(plan_copy.items(), key=lambda x: int(x[1] or 0), reverse=True)[: max(0, int(PMTA_DOMAINS_TOP_N or 0))]
                        want = [d for d, _ in top if d]

                        over = pmta_domains_overview(smtp_host=smtp_host)
                        small = {
                            "ok": bool(over.get("ok")),
                            "reason": str(over.get("reason") or ""),
                            "url": str(over.get("url") or ""),
                            "domains": {},
                        }
                        if over.get("ok"):
                            m = (over.get("domains") if isinstance(over.get("domains"), dict) else {}) or {}
                            for d in want:
                                dv = m.get(d)
                                if isinstance(dv, dict):
                                    small["domains"][d] = {
                                        "queued": int(dv.get("queued") or 0),
                                        "deferred": int(dv.get("deferred") or 0),
                                        "active": (int(dv.get("active")) if dv.get("active") is not None else None),
                                    }

                        with JOBS_LOCK:
                            job.pmta_domains = small
                            job.pmta_domains_ts = now_iso()

                        last_pmta_domains = time.time()
                except Exception:
                    pass

            with JOBS_LOCK:
                job.current_chunk = chunk_idx
                job.current_chunk_domains = dom_counts
                job.current_chunk_info = {
                    "chunk": chunk_idx,
                    "size": len(chunk),
                    "target_domain": target_domain,
                    "chunk_size": cs,
                    "workers": workers2,
                    "delay_s": delay2,
                    "sleep_chunks": sleep2,
                    "pmta_pressure": pmta_pressure_applied,
                    "adaptive_health": health_policy_applied,
                    "attempt": 0,
                    "sender": "",
                    "subject": "",
                    "body_variant": "",
                    "body_format": body_format2,
                    "reply_to": reply_to2,
                }

            # keep chunks_total roughly correct
            remaining = max(0, _remaining_total())
            est_remaining = (remaining + cs - 1) // cs
            with JOBS_LOCK:
                job.chunks_total = max(job.chunks_total, job.chunks_done + est_remaining)

            # Per-chunk attempt loop.
            # Per-chunk AI rewrite chain (optional): rewrite from last accepted message,
            # then carry rewritten output forward as input for next chunk.
            chunk_subjects = list(subjects2 or subjects)
            chunk_body_variants = list(body_variants2 or split_body_variants(body))

            if ai_enabled:
                ai_in_subjects = list(ai_subject_chain or chunk_subjects)
                ai_in_body = ai_body_chain if ai_body_chain.strip() else (chunk_body_variants[0] if chunk_body_variants else body)
                try:
                    ai_new_subjects, ai_new_body, ai_backend = ai_rewrite_subjects_and_body(
                        token=ai_token,
                        subjects=ai_in_subjects,
                        body=ai_in_body,
                        body_format=body_format2,
                    )
                    ai_new_subjects = [str(x).strip() for x in (ai_new_subjects or []) if str(x).strip()]
                    if ai_new_subjects:
                        chunk_subjects = ai_new_subjects
                        ai_subject_chain = ai_new_subjects

                    if str(ai_new_body or "").strip():
                        ai_body_chain = str(ai_new_body)
                        chunk_body_variants = split_body_variants(ai_body_chain)

                    with JOBS_LOCK:
                        job.log(
                            "INFO",
                            f"Chunk {chunk_idx+1} [{target_domain}]: AI rewrite applied ({ai_backend}) subj={len(chunk_subjects)} body_variants={len(chunk_body_variants)}",
                        )
                except Exception as e:
                    with JOBS_LOCK:
                        job.log("WARN", f"Chunk {chunk_idx+1} [{target_domain}]: AI rewrite failed, using previous content ({e})")

            attempt = 0
            sender_cursor_base = int(provider_sender_cursor.get(target_domain, 0) or 0)
            deferred_wait_until = 0.0
            deferred_count = 0
            while True:
                # rotate per provider (domain), and shift again on each retry
                rot = sender_cursor_base + attempt

                fe = from_emails2[rot % len(from_emails2)]
                fn = from_names2[rot % len(from_names2)] if from_names2 else "Sender"
                sb = chunk_subjects[rot % len(chunk_subjects)]
                b_used = chunk_body_variants[rot % len(chunk_body_variants)] if chunk_body_variants else body
                sender_domain = _extract_domain_from_email(fe) or ""
                relation_key = (target_domain, sender_domain)
                now_ts = time.time()
                rel_wait_until = float(relation_backoff_until.get(relation_key, 0.0) or 0.0)

                if rel_wait_until > now_ts:
                    deferred_wait_until = max(deferred_wait_until, rel_wait_until)
                    deferred_count += 1
                    attempt += 1
                    if deferred_count < max(1, len(from_emails2)):
                        continue

                    provider_buckets[target_domain] = chunk + (provider_buckets.get(target_domain) or [])
                    provider_next_retry_ts[target_domain] = max(float(provider_next_retry_ts.get(target_domain, 0.0) or 0.0), deferred_wait_until)
                    with JOBS_LOCK:
                        job.current_chunk = -1
                        job.current_chunk_info = {}
                        job.current_chunk_domains = {}
                        job.push_chunk_state({
                            "chunk": chunk_idx,
                            "status": "deferred",
                            "size": len(chunk),
                            "sender": fe,
                            "subject": sb,
                            "attempt": attempt,
                            "next_retry_ts": deferred_wait_until,
                            "reason": "relation_backoff_active",
                            "receiver_domain": target_domain,
                            "sender_domain": sender_domain,
                        })
                        job.log("WARN", f"Chunk {chunk_idx+1} [{target_domain}]: deferred due active scoped backoff sender_domain={sender_domain} wait={int(max(0.0, deferred_wait_until - now_ts))}s")
                    break

                # Update PMTA live metrics for UI (rate-limited)
                if PMTA_QUEUE_BACKOFF:
                    try:
                        if (time.time() - float(last_pmta_live or 0.0)) >= float(PMTA_LIVE_POLL_S or 3.0):
                            live = pmta_live_panel(smtp_host=smtp_host)
                            last_pmta_live = time.time()
                            with JOBS_LOCK:
                                job.pmta_live = live
                                job.pmta_live_ts = now_iso()
                    except Exception:
                        pass

                sc, det = _spam_check(fe, sb, b_used, body_format2)
                _bl_listed, bl_detail = _blacklist_check(fe)

                # PMTA domain/queue adaptive backoff (best-effort)
                pmta_sig = {"enabled": False, "ok": True, "blocked": False, "slow": None, "reason": ""}
                pmta_reason = ""
                pmta_slow: Dict[str, Any] = {}

                if PMTA_QUEUE_BACKOFF:
                    try:
                        pmta_sig = pmta_chunk_policy(smtp_host=smtp_host, chunk_domain_counts=dom_counts)
                        if pmta_sig.get("blocked"):
                            pmta_reason = str(pmta_sig.get("reason") or "")
                        elif pmta_sig.get("slow"):
                            pmta_slow = pmta_sig.get("slow") or {}
                            # apply slowdown for this chunk attempt only
                            try:
                                delay2 = max(float(delay2 or 0.0), float(pmta_slow.get("delay_min") or 0.0))
                            except Exception:
                                pass
                            try:
                                wmax = int(pmta_slow.get("workers_max") or 0)
                                if wmax > 0:
                                    workers2 = max(1, min(int(workers2 or 1), wmax))
                            except Exception:
                                pass
                    except Exception:
                        pmta_sig = {"enabled": True, "ok": False, "blocked": False, "slow": None, "reason": "pmta policy error"}

                # DNSBL is visibility-only; do not pause chunks due to blacklist hits.
                blocked = backoff_enabled and (
                    (sc is not None and sc > job.spam_threshold)
                    or bool(_bl_listed)
                    or bool(pmta_reason)
                )

                with JOBS_LOCK:
                    job.current_chunk = chunk_idx
                    job.current_chunk_info.update({
                        "attempt": attempt,
                        "sender": fe,
                        "subject": sb,
                        "body_variant": (rot % max(1, len(chunk_body_variants))) if chunk_body_variants else 0,
                        "spam_score": sc,
                        "blacklist": bl_detail,
                        "pmta_reason": pmta_reason,
                        "pmta_slow": pmta_slow,
                        "target_domain": target_domain,
                    })

                if blocked:
                    attempt += 1
                    reason = []
                    if sc is not None and sc > job.spam_threshold:
                        reason.append(f"spam_score={sc:.2f}>{job.spam_threshold:.1f}")
                    if bl_detail:
                        reason.append(f"blacklist={bl_detail}")
                    if pmta_reason:
                        reason.append(f"pmta={pmta_reason}")
                    rtxt = " ".join(reason) or "blocked"

                    rel_attempt = int(relation_backoff_attempts.get(relation_key, 0) or 0) + 1
                    relation_backoff_attempts[relation_key] = rel_attempt

                    wait_s = min(backoff_max_s, backoff_base_s * (2 ** max(0, rel_attempt - 1)))
                    next_ts = time.time() + wait_s
                    relation_backoff_until[relation_key] = next_ts
                    deferred_wait_until = max(deferred_wait_until, next_ts)

                    entry = {
                        "chunk": chunk_idx,
                        "size": len(chunk),
                        "attempt": rel_attempt,
                        "next_retry_ts": next_ts,
                        "reason": rtxt,
                        "sender": fe,
                        "subject": sb,
                        "spam_score": sc,
                        "blacklist": bl_detail,
                        "receiver_domain": target_domain,
                        "sender_domain": sender_domain,
                        "scope": "receiver_sender_domain",
                    }

                    with JOBS_LOCK:
                        job.status = "running"
                        job.chunks_backoff += 1
                        job.push_backoff(entry)
                        job.push_chunk_state({**entry, "status": "backoff"})
                        job.log("WARN", f"Chunk {chunk_idx+1} [{target_domain}]: scoped BACKOFF receiver={target_domain} sender_domain={sender_domain} retry#{rel_attempt} wait={int(wait_s)}s ({rtxt})")

                    if rel_attempt > max_backoff_retries:
                        with JOBS_LOCK:
                            job.log("ERROR", f"Chunk {chunk_idx+1} [{target_domain}]: scoped relation exhausted retries sender_domain={sender_domain} ({rtxt})")

                    deferred_count += 1
                    if deferred_count >= max(1, len(from_emails2)):
                        provider_buckets[target_domain] = chunk + (provider_buckets.get(target_domain) or [])
                        provider_next_retry_ts[target_domain] = max(float(provider_next_retry_ts.get(target_domain, 0.0) or 0.0), deferred_wait_until)
                        with JOBS_LOCK:
                            job.current_chunk = -1
                            job.current_chunk_info = {}
                            job.current_chunk_domains = {}
                        break

                    continue

                # allowed -> send
                with JOBS_LOCK:
                    job.status = "running"
                    job.push_chunk_state({
                        "chunk": chunk_idx,
                        "status": "running",
                        "size": len(chunk),
                        "sender": fe,
                        "subject": sb,
                        "spam_score": sc,
                        "blacklist": bl_detail,
                        "attempt": attempt,
                        "next_retry_ts": 0,
                        "reason": "",
                        "receiver_domain": target_domain,
                    })
                    job.log("INFO", f"Chunk {chunk_idx+1} [{target_domain}]: sending size={len(chunk)} sender={fe} workers={workers2}")

                if not _wait_ready():
                    _stop_job("stop requested")
                    return

                _send_chunk(
                    chunk_idx=chunk_idx,
                    chunk_rcpts=chunk,
                    from_name=fn,
                    from_email=fe,
                    subject=sb,
                    body_used=b_used,
                    body_format2=body_format2,
                    reply_to2=reply_to2,
                    delay2=delay2,
                    workers2=workers2,
                    urls2=urls2,
                    src2=src2,
                )

                if _should_stop():
                    _stop_job("stop requested")
                    return

                with JOBS_LOCK:
                    job.chunks_done += 1
                    job.current_chunk = -1
                    job.current_chunk_info = {}
                    job.current_chunk_domains = {}
                    job.push_chunk_state({
                        "chunk": chunk_idx,
                        "status": "done" if attempt == 0 else "done_after_backoff",
                        "size": len(chunk),
                        "sender": fe,
                        "subject": sb,
                        "spam_score": sc,
                        "blacklist": bl_detail,
                        "attempt": attempt,
                        "next_retry_ts": 0,
                        "reason": "",
                        "receiver_domain": target_domain,
                    })
                if from_emails2:
                    provider_sender_cursor[target_domain] = (sender_cursor_base + 1) % max(1, len(from_emails2))
                break

            # next chunk
            chunk_idx += 1

            if sleep2 > 0 and _remaining_total() > 0:
                with JOBS_LOCK:
                    job.log("INFO", f"Sleeping {sleep2}s between chunks (round-robin providers)...")
                if not _sleep_checked(sleep2):
                    _stop_job("stop requested")
                    return

        with JOBS_LOCK:
            job.status = "done"
            job.current_chunk = -1
            job.log("INFO", "Job finished.")
            job.maybe_persist(force=True)

    except Exception as e:
        with JOBS_LOCK:
            job.status = "error"
            job.last_error = str(e)
            job.log("ERROR", f"Job error: {e}")
            job.maybe_persist(force=True)



# =========================
# App Config Schema + helpers
# =========================

APP_CONFIG_SCHEMA: List[dict] = [
    # Spam score
    {"key": "SPAMCHECK_BACKEND", "type": "str", "default": "spamd", "group": "Spam", "restart_required": False,
     "desc": "Spam scoring backend: spamd | spamc | spamassassin | module | off."},
    {"key": "SPAMD_HOST", "type": "str", "default": "127.0.0.1", "group": "Spam", "restart_required": False,
     "desc": "spamd (SpamAssassin daemon) host."},
    {"key": "SPAMD_PORT", "type": "int", "default": "783", "group": "Spam", "restart_required": False,
     "desc": "spamd TCP port (default 783)."},
    {"key": "SPAMD_TIMEOUT", "type": "float", "default": "5", "group": "Spam", "restart_required": False,
     "desc": "Timeout for spamd/spamc/spamassassin calls (seconds)."},

    # DNSBL/DBL
    {"key": "RBL_ZONES", "type": "str", "default": "zen.spamhaus.org,bl.spamcop.net,cbl.abuseat.org", "group": "DNSBL", "restart_required": False,
     "desc": "Comma-separated IP DNSBL zones (RBL). Empty disables IP blacklist checks."},
    {"key": "DBL_ZONES", "type": "str", "default": "dbl.spamhaus.org", "group": "DNSBL", "restart_required": False,
     "desc": "Comma-separated domain DBL zones. Empty disables domain blacklist checks."},
    {"key": "SEND_DNSBL", "type": "bool", "default": "true", "group": "DNSBL", "restart_required": False,
     "desc": "If true, continue sending even when SMTP host IP appears in DNSBL (logs listing as info only)."},

    # PMTA monitor
    {"key": "PMTA_MONITOR_TIMEOUT_S", "type": "float", "default": "3", "group": "PMTA Monitor", "restart_required": False,
     "desc": "Timeout for PMTA monitor HTTP calls (seconds)."},
    {"key": "PMTA_MONITOR_SCHEME", "type": "str", "default": "auto", "group": "PMTA Monitor", "restart_required": False,
     "desc": "PMTA monitor scheme: auto | https | http. PMTA 5.x often forces HTTPS on :8080."},
    {"key": "PMTA_MONITOR_BASE_URL", "type": "str", "default": "", "group": "PMTA Monitor", "restart_required": False,
     "desc": "Override PMTA monitor base URL (e.g. https://194.116.172.135:8080). Useful if SMTP host != monitor host."},

    {"key": "PMTA_MONITOR_API_KEY", "type": "str", "default": "", "group": "PMTA Monitor", "restart_required": False, "secret": True,
     "desc": "Optional PMTA monitor API key (sent as X-API-Key)."},
    {"key": "PMTA_HEALTH_REQUIRED", "type": "bool", "default": "1", "group": "PMTA Monitor", "restart_required": False,
     "desc": "If true: block starting jobs when PMTA monitor is unreachable. If false: warn-only."},

    # PMTA health busy thresholds
    {"key": "PMTA_MAX_SPOOL_RECIPIENTS", "type": "int", "default": "200000", "group": "PMTA Health", "restart_required": False,
     "desc": "Busy threshold: max spool recipients before blocking job start."},
    {"key": "PMTA_MAX_SPOOL_MESSAGES", "type": "int", "default": "50000", "group": "PMTA Health", "restart_required": False,
     "desc": "Busy threshold: max spool messages before blocking job start."},
    {"key": "PMTA_MAX_QUEUED_RECIPIENTS", "type": "int", "default": "250000", "group": "PMTA Health", "restart_required": False,
     "desc": "Busy threshold: max queued recipients before blocking job start."},
    {"key": "PMTA_MAX_QUEUED_MESSAGES", "type": "int", "default": "60000", "group": "PMTA Health", "restart_required": False,
     "desc": "Busy threshold: max queued messages before blocking job start."},

    # Sender backoff (preflight)
    {"key": "BACKOFF_MAX_RETRIES", "type": "int", "default": "3", "group": "Backoff", "restart_required": False,
     "desc": "Max backoff retries per chunk when spam/blacklist/PMTA policy blocks sending."},
    {"key": "BACKOFF_BASE_S", "type": "float", "default": "60", "group": "Backoff", "restart_required": False,
     "desc": "Base backoff wait in seconds (exponential)."},
    {"key": "BACKOFF_MAX_S", "type": "float", "default": "1800", "group": "Backoff", "restart_required": False,
     "desc": "Maximum backoff wait (seconds)."},
    {"key": "ENABLE_BACKOFF", "type": "bool", "default": "1", "group": "Backoff", "restart_required": False,
     "desc": "Default state for send-form backoff checkbox (env: ENABLE_BACKOFF)."},

    # PMTA live/diag
    {"key": "PMTA_DIAG_ON_ERROR", "type": "bool", "default": "1", "group": "PMTA Diag", "restart_required": False,
     "desc": "If enabled: capture PMTA snapshots when an SMTP send fails (helps classify failures)."},
    {"key": "PMTA_DIAG_RATE_S", "type": "float", "default": "1.0", "group": "PMTA Diag", "restart_required": False,
     "desc": "Rate-limit for PMTA diagnostics per domain (seconds)."},
    {"key": "PMTA_QUEUE_TOP_N", "type": "int", "default": "6", "group": "PMTA Live", "restart_required": False,
     "desc": "How many top queues to show in the PMTA Live Panel."},
    {"key": "PMTA_QUEUE_BACKOFF", "type": "bool", "default": "1", "group": "PMTA Backoff", "restart_required": False,
     "desc": "If enabled: use /domainDetail + /queueDetail to slow down or backoff based on PMTA errors/deferrals."},
    {"key": "PMTA_QUEUE_REQUIRED", "type": "bool", "default": "0", "group": "PMTA Backoff", "restart_required": False,
     "desc": "If true and PMTA detail endpoints are unreachable: block chunk (strict mode)."},
    {"key": "PMTA_LIVE_POLL_S", "type": "float", "default": "3", "group": "PMTA Live", "restart_required": False,
     "desc": "Polling interval for PMTA live panel (seconds)."},
    {"key": "PMTA_DOMAIN_CHECK_TOP_N", "type": "int", "default": "2", "group": "PMTA Backoff", "restart_required": False,
     "desc": "How many top recipient domains per chunk to inspect via domainDetail/queueDetail."},
    {"key": "PMTA_DETAIL_CACHE_TTL_S", "type": "float", "default": "3", "group": "PMTA Backoff", "restart_required": False,
     "desc": "Cache TTL for PMTA detail calls (seconds)."},

    # PMTA chunk slow/backoff thresholds
    {"key": "PMTA_DOMAIN_DEFERRALS_BACKOFF", "type": "int", "default": "80", "group": "PMTA Backoff", "restart_required": False,
     "desc": "If deferrals >= this value → chunk enters backoff."},
    {"key": "PMTA_DOMAIN_ERRORS_BACKOFF", "type": "int", "default": "6", "group": "PMTA Backoff", "restart_required": False,
     "desc": "If errors_count >= this value → chunk enters backoff."},
    {"key": "PMTA_DOMAIN_DEFERRALS_SLOW", "type": "int", "default": "25", "group": "PMTA Backoff", "restart_required": False,
     "desc": "If deferrals >= this value → slow down sending for that chunk."},
    {"key": "PMTA_DOMAIN_ERRORS_SLOW", "type": "int", "default": "3", "group": "PMTA Backoff", "restart_required": False,
     "desc": "If errors_count >= this value → slow down sending for that chunk."},
    {"key": "PMTA_SLOW_DELAY_S", "type": "float", "default": "0.35", "group": "PMTA Backoff", "restart_required": False,
     "desc": "Minimum delay per message when PMTA suggests slowdown."},
    {"key": "PMTA_SLOW_WORKERS_MAX", "type": "int", "default": "3", "group": "PMTA Backoff", "restart_required": False,
     "desc": "Maximum worker threads when PMTA suggests slowdown."},

    # PMTA pressure control
    {"key": "PMTA_PRESSURE_CONTROL", "type": "bool", "default": "1", "group": "PMTA Pressure", "restart_required": False,
     "desc": "If enabled: dynamically cap delay/workers/chunk/sleep based on PMTA backlog (queue/spool/deferrals)."},
    {"key": "PMTA_PRESSURE_POLL_S", "type": "float", "default": "3", "group": "PMTA Pressure", "restart_required": False,
     "desc": "Polling interval for pressure policy calculation."},
    {"key": "PMTA_DOMAIN_STATS", "type": "bool", "default": "1", "group": "PMTA Domains", "restart_required": False,
     "desc": "If enabled: fetch /domains overview and show queued/deferred/active for top domains."},
    {"key": "PMTA_DOMAINS_POLL_S", "type": "float", "default": "4", "group": "PMTA Domains", "restart_required": False,
     "desc": "Polling interval for /domains snapshot."},
    {"key": "PMTA_DOMAINS_TOP_N", "type": "int", "default": "6", "group": "PMTA Domains", "restart_required": False,
     "desc": "How many top domains to show in PMTA domain snapshot."},
    # OpenRouter (AI rewrite)
    {"key": "OPENROUTER_ENDPOINT", "type": "str", "default": "https://openrouter.ai/api/v1/chat/completions", "group": "AI", "restart_required": False,
     "desc": "OpenRouter API endpoint for AI rewrite."},
    {"key": "OPENROUTER_MODEL", "type": "str", "default": "arcee-ai/trinity-large-preview:free", "group": "AI", "restart_required": False,
     "desc": "OpenRouter model name used for AI rewrite."},
    {"key": "OPENROUTER_TIMEOUT_S", "type": "float", "default": "40", "group": "AI", "restart_required": False,
     "desc": "Timeout for OpenRouter HTTP calls (seconds)."},


    {"key": "PMTA_BRIDGE_PULL_TOKEN", "type": "str", "default": "", "group": "Accounting", "restart_required": False, "secret": True,
     "desc": "Bearer token sent by Shiva while pulling /api/v1/pull/latest from bridge."},

    # Accounting bridge pull mode (Shiva pull request -> bridge API response)
    {"key": "PMTA_BRIDGE_PULL_ENABLED", "type": "bool", "default": "1", "group": "Accounting", "restart_required": True,
     "desc": "Enable the only accounting flow: Shiva pulls accounting from bridge API."},
    {"key": "PMTA_BRIDGE_PULL_URL", "type": "str", "default": "", "group": "Accounting", "restart_required": True,
     "desc": "Full bridge endpoint for pull mode, e.g. http://194.116.172.135:8090/api/v1/pull/latest?kind=acct."},
    {"key": "PMTA_BRIDGE_PULL_S", "type": "float", "default": "5", "group": "Accounting", "restart_required": False,
     "desc": "Polling interval (seconds) for Shiva bridge pull thread."},
    {"key": "PMTA_BRIDGE_PULL_MAX_LINES", "type": "int", "default": "2000", "group": "Accounting", "restart_required": False,
     "desc": "max_lines query used when Shiva pulls from bridge endpoint."},
    {"key": "PMTA_BRIDGE_PULL_KIND", "type": "str", "default": "acct", "group": "Accounting", "restart_required": False,
     "desc": "Bridge kind requested by Shiva (acct|diag|log|pmtahttp|all)."},
    {"key": "PMTA_BRIDGE_PULL_ALL_FILES", "type": "bool", "default": "0", "group": "Accounting", "restart_required": False,
     "desc": "When enabled, Shiva asks bridge to return new lines from all matched files (not only latest)."},

    # App (restart-only)
    {"key": "DB_CLEAR_ON_START", "type": "bool", "default": "0", "group": "App", "restart_required": True,
     "desc": "If enabled: wipes SQLite tables on app start (danger). Requires restart."},
]

APP_CONFIG_INDEX: Dict[str, dict] = {it["key"]: it for it in APP_CONFIG_SCHEMA if isinstance(it, dict) and it.get("key")}


def _cfg_boolish(s: str) -> bool:
    v = (s or "").strip().lower()
    return v in {"1", "true", "yes", "on", "y"}


def _cfg_get_raw_and_source(key: str) -> Tuple[Optional[str], str, Optional[str], Optional[str]]:
    """Return (effective_raw, source, ui_raw, env_raw)."""
    k = (key or "").strip()
    ui = db_get_app_config(k)
    if ui is not None:
        return ui, "ui", ui, os.getenv(k)

    envv = os.getenv(k)
    if envv is not None:
        return envv, "env", ui, envv
    return None, "default", ui, envv


def cfg_get_str(key: str, default: str) -> str:
    raw, src, _ui, _envv = _cfg_get_raw_and_source(key)
    if raw is None:
        return str(default)
    return str(raw)


def cfg_get_int(key: str, default: int) -> int:
    raw, src, _ui, _envv = _cfg_get_raw_and_source(key)
    if raw is None:
        return int(default)
    try:
        return int(str(raw).strip())
    except Exception:
        return int(default)


def cfg_get_float(key: str, default: float) -> float:
    raw, src, _ui, _envv = _cfg_get_raw_and_source(key)
    if raw is None:
        return float(default)
    try:
        return float(str(raw).strip())
    except Exception:
        return float(default)


def cfg_get_bool(key: str, default: bool) -> bool:
    raw, src, _ui, _envv = _cfg_get_raw_and_source(key)
    if raw is None:
        return bool(default)
    return _cfg_boolish(str(raw))


def config_items() -> List[dict]:
    """Return schema + current effective values for the UI."""
    items: List[dict] = []
    for it in APP_CONFIG_SCHEMA:
        k = str(it.get("key") or "").strip()
        typ = str(it.get("type") or "str").strip().lower()
        d0 = it.get("default", "")
        raw, src, ui_raw, env_raw = _cfg_get_raw_and_source(k)

        # compute effective value string
        if raw is None:
            eff = str(d0)
            src2 = "default"
        else:
            eff = str(raw)
            src2 = src

        items.append({
            "key": k,
            "type": typ,
            "group": str(it.get("group") or "Other"),
            "desc": str(it.get("desc") or ""),
            "secret": bool(it.get("secret") or False),
            "restart_required": bool(it.get("restart_required") or False),
            "value": eff,
            "source": src2,
            "default_value": str(d0),
            "env_value": "" if env_raw is None else str(env_raw),
            "ui_value": "" if ui_raw is None else str(ui_raw),
        })
    return items


def reload_runtime_config() -> dict:
    """Apply UI-stored config overrides to runtime globals (best-effort).

    NOTE: Some keys are marked restart_required; they are stored but not applied live.
    """
    try:
        global SPAMCHECK_BACKEND, SPAMD_HOST, SPAMD_PORT, SPAMD_TIMEOUT
        global _RBL_ZONES_RAW, _DBL_ZONES_RAW, RBL_ZONES_LIST, DBL_ZONES_LIST, SEND_DNSBL
        global PMTA_MONITOR_TIMEOUT_S, PMTA_MONITOR_BASE_URL, PMTA_MONITOR_SCHEME, PMTA_MONITOR_API_KEY, PMTA_HEALTH_REQUIRED
        global PMTA_DIAG_ON_ERROR, PMTA_DIAG_RATE_S, PMTA_QUEUE_TOP_N
        global PMTA_QUEUE_BACKOFF, PMTA_QUEUE_REQUIRED
        global PMTA_LIVE_POLL_S, PMTA_DOMAIN_CHECK_TOP_N, PMTA_DETAIL_CACHE_TTL_S
        global PMTA_DOMAIN_DEFERRALS_BACKOFF, PMTA_DOMAIN_ERRORS_BACKOFF, PMTA_DOMAIN_DEFERRALS_SLOW, PMTA_DOMAIN_ERRORS_SLOW
        global PMTA_SLOW_DELAY_S, PMTA_SLOW_WORKERS_MAX
        global PMTA_PRESSURE_CONTROL, PMTA_PRESSURE_POLL_S
        global PMTA_DOMAIN_STATS, PMTA_DOMAINS_POLL_S, PMTA_DOMAINS_TOP_N
        global OPENROUTER_ENDPOINT, OPENROUTER_MODEL, OPENROUTER_TIMEOUT_S
        global PMTA_BRIDGE_PULL_ENABLED, PMTA_BRIDGE_PULL_URL, PMTA_BRIDGE_PULL_TOKEN, PMTA_BRIDGE_PULL_S, PMTA_BRIDGE_PULL_MAX_LINES
        global PMTA_BRIDGE_PULL_KIND, PMTA_BRIDGE_PULL_ALL_FILES

        # Spam
        SPAMCHECK_BACKEND = (cfg_get_str("SPAMCHECK_BACKEND", "spamd") or "spamd").strip().lower()
        SPAMD_HOST = (cfg_get_str("SPAMD_HOST", "127.0.0.1") or "127.0.0.1").strip()
        SPAMD_PORT = int(cfg_get_int("SPAMD_PORT", 783))
        SPAMD_TIMEOUT = float(cfg_get_float("SPAMD_TIMEOUT", 5.0))

        # DNSBL
        _RBL_ZONES_RAW = (cfg_get_str("RBL_ZONES", "zen.spamhaus.org,bl.spamcop.net,cbl.abuseat.org") or "").strip()
        _DBL_ZONES_RAW = (cfg_get_str("DBL_ZONES", "dbl.spamhaus.org") or "").strip()
        RBL_ZONES_LIST = _parse_zones(_RBL_ZONES_RAW)
        DBL_ZONES_LIST = _parse_zones(_DBL_ZONES_RAW)
        SEND_DNSBL = bool(cfg_get_bool("SEND_DNSBL", True))

        # PMTA monitor
        PMTA_MONITOR_TIMEOUT_S = float(cfg_get_float("PMTA_MONITOR_TIMEOUT_S", 3.0))
        PMTA_MONITOR_SCHEME = (cfg_get_str("PMTA_MONITOR_SCHEME", "auto") or "auto").strip().lower()
        if PMTA_MONITOR_SCHEME not in {"auto", "http", "https"}:
            PMTA_MONITOR_SCHEME = "auto"
        PMTA_MONITOR_BASE_URL = (cfg_get_str("PMTA_MONITOR_BASE_URL", "") or "").strip()
        PMTA_MONITOR_API_KEY = (cfg_get_str("PMTA_MONITOR_API_KEY", "") or "").strip()
        PMTA_HEALTH_REQUIRED = bool(cfg_get_bool("PMTA_HEALTH_REQUIRED", True))

        # PMTA diag/live/backoff knobs
        PMTA_DIAG_ON_ERROR = bool(cfg_get_bool("PMTA_DIAG_ON_ERROR", True))
        PMTA_DIAG_RATE_S = float(cfg_get_float("PMTA_DIAG_RATE_S", 1.0))
        PMTA_QUEUE_TOP_N = int(cfg_get_int("PMTA_QUEUE_TOP_N", 6))

        PMTA_QUEUE_BACKOFF = bool(cfg_get_bool("PMTA_QUEUE_BACKOFF", True))
        PMTA_QUEUE_REQUIRED = bool(cfg_get_bool("PMTA_QUEUE_REQUIRED", False))
        PMTA_LIVE_POLL_S = float(cfg_get_float("PMTA_LIVE_POLL_S", 3.0))
        PMTA_DOMAIN_CHECK_TOP_N = int(cfg_get_int("PMTA_DOMAIN_CHECK_TOP_N", 2))
        PMTA_DETAIL_CACHE_TTL_S = float(cfg_get_float("PMTA_DETAIL_CACHE_TTL_S", 3.0))

        PMTA_DOMAIN_DEFERRALS_BACKOFF = int(cfg_get_int("PMTA_DOMAIN_DEFERRALS_BACKOFF", 80))
        PMTA_DOMAIN_ERRORS_BACKOFF = int(cfg_get_int("PMTA_DOMAIN_ERRORS_BACKOFF", 6))
        PMTA_DOMAIN_DEFERRALS_SLOW = int(cfg_get_int("PMTA_DOMAIN_DEFERRALS_SLOW", 25))
        PMTA_DOMAIN_ERRORS_SLOW = int(cfg_get_int("PMTA_DOMAIN_ERRORS_SLOW", 3))
        PMTA_SLOW_DELAY_S = float(cfg_get_float("PMTA_SLOW_DELAY_S", 0.35))
        PMTA_SLOW_WORKERS_MAX = int(cfg_get_int("PMTA_SLOW_WORKERS_MAX", 3))

        PMTA_PRESSURE_CONTROL = bool(cfg_get_bool("PMTA_PRESSURE_CONTROL", True))
        PMTA_PRESSURE_POLL_S = float(cfg_get_float("PMTA_PRESSURE_POLL_S", 3.0))
        PMTA_DOMAIN_STATS = bool(cfg_get_bool("PMTA_DOMAIN_STATS", True))
        PMTA_DOMAINS_POLL_S = float(cfg_get_float("PMTA_DOMAINS_POLL_S", 4.0))
        PMTA_DOMAINS_TOP_N = int(cfg_get_int("PMTA_DOMAINS_TOP_N", 6))

        # AI
        OPENROUTER_ENDPOINT = (cfg_get_str("OPENROUTER_ENDPOINT", OPENROUTER_ENDPOINT) or OPENROUTER_ENDPOINT).strip()
        OPENROUTER_MODEL = (cfg_get_str("OPENROUTER_MODEL", OPENROUTER_MODEL) or OPENROUTER_MODEL).strip()
        OPENROUTER_TIMEOUT_S = float(cfg_get_float("OPENROUTER_TIMEOUT_S", OPENROUTER_TIMEOUT_S))

        # Bridge pull mode (Shiva -> Bridge)
        PMTA_BRIDGE_PULL_ENABLED = bool(cfg_get_bool("PMTA_BRIDGE_PULL_ENABLED", bool(PMTA_BRIDGE_PULL_ENABLED)))
        PMTA_BRIDGE_PULL_URL = (cfg_get_str("PMTA_BRIDGE_PULL_URL", PMTA_BRIDGE_PULL_URL) or "").strip()
        PMTA_BRIDGE_PULL_TOKEN = (cfg_get_str("PMTA_BRIDGE_PULL_TOKEN", PMTA_BRIDGE_PULL_TOKEN) or "").strip()
        PMTA_BRIDGE_PULL_S = float(cfg_get_float("PMTA_BRIDGE_PULL_S", float(PMTA_BRIDGE_PULL_S or 5.0)))
        PMTA_BRIDGE_PULL_MAX_LINES = int(cfg_get_int("PMTA_BRIDGE_PULL_MAX_LINES", int(PMTA_BRIDGE_PULL_MAX_LINES or 2000)))
        PMTA_BRIDGE_PULL_KIND = (cfg_get_str("PMTA_BRIDGE_PULL_KIND", PMTA_BRIDGE_PULL_KIND) or "acct").strip().lower()
        PMTA_BRIDGE_PULL_ALL_FILES = bool(cfg_get_bool("PMTA_BRIDGE_PULL_ALL_FILES", bool(PMTA_BRIDGE_PULL_ALL_FILES)))

        # If bridge pull gets enabled/configured from UI after startup, ensure poller thread is running.
        start_accounting_bridge_poller_if_needed()

        return {"ok": True, "ts": now_iso()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# Apply UI config overrides once at startup (best-effort)
try:
    reload_runtime_config()
except Exception:
    pass


# =========================
# Routes
# =========================
@app.get("/")
def home():
    return redirect(url_for("campaigns_page"))


@app.get("/campaigns")
def campaigns_page():
    bid, is_new = get_or_create_browser_id()
    campaigns = db_list_campaigns(bid)
    resp = make_response(render_template_string(PAGE_CAMPAIGNS, campaigns=campaigns))
    return attach_browser_cookie(resp, bid, is_new)


@app.get("/campaigns/new")
def campaigns_new():
    bid, is_new = get_or_create_browser_id()
    c = db_create_campaign(bid, "")
    resp = redirect(url_for("campaign_open", campaign_id=c["id"]))
    return attach_browser_cookie(resp, bid, is_new)


@app.post("/campaigns/wipe")
def campaigns_wipe():
    bid, is_new = get_or_create_browser_id()
    db_clear_all()
    resp = redirect(url_for("campaigns_page"))
    return attach_browser_cookie(resp, bid, is_new)


@app.get("/campaign/<campaign_id>")
def campaign_open(campaign_id: str):
    bid, is_new = get_or_create_browser_id()
    c = db_get_campaign(bid, (campaign_id or "").strip())
    if not c:
        abort(404)
    resp = make_response(render_template_string(
        PAGE_FORM,
        campaign_id=c["id"],
        campaign_name=c["name"],
        default_enable_backoff=cfg_get_bool("ENABLE_BACKOFF", True),
    ))
    return attach_browser_cookie(resp, bid, is_new)


@app.get("/campaign/<campaign_id>/config")
def campaign_config_page(campaign_id: str):
    bid, is_new = get_or_create_browser_id()
    c = db_get_campaign(bid, (campaign_id or "").strip())
    if not c:
        abort(404)
    resp = make_response(render_template_string(PAGE_CONFIG, campaign_id=c["id"], campaign_name=c["name"]))
    return attach_browser_cookie(resp, bid, is_new)




@app.post("/campaign/<campaign_id>/rename")
def campaign_rename(campaign_id: str):
    bid, is_new = get_or_create_browser_id()
    nm = (request.form.get("name") or "").strip()
    if nm:
        db_rename_campaign(bid, (campaign_id or "").strip(), nm)
    resp = redirect(url_for("campaigns_page"))
    return attach_browser_cookie(resp, bid, is_new)


@app.post("/campaign/<campaign_id>/delete")
def campaign_delete(campaign_id: str):
    bid, is_new = get_or_create_browser_id()
    db_delete_campaign(bid, (campaign_id or "").strip())
    resp = redirect(url_for("campaigns_page"))
    return attach_browser_cookie(resp, bid, is_new)


@app.get("/jobs")
def list_jobs():
    cid = (request.args.get("c") or "").strip()
    with JOBS_LOCK:
        jobs = [j for j in JOBS.values() if not getattr(j, 'deleted', False)]
        if cid:
            jobs = [j for j in jobs if (j.campaign_id or "") == cid]
        jobs.sort(key=lambda x: x.created_at, reverse=True)
    return render_template_string(PAGE_JOBS, jobs=jobs, campaign_id=cid)


@app.get("/domains")
def domains_page():
    return render_template_string(PAGE_DOMAINS)


@app.get("/job/<job_id>")
def job_page(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if (not job) or getattr(job, 'deleted', False):
            abort(404)
        cid = job.campaign_id
    return render_template_string(PAGE_JOB, job_id=job_id, campaign_id=cid)


@app.get("/api/job/<job_id>")
def job_api(job_id: str):
    try:
        recent_page = max(1, int(request.args.get("recent_page") or 1))
    except Exception:
        recent_page = 1
    try:
        requested_page_size = int(request.args.get("recent_page_size") or 100)
    except Exception:
        requested_page_size = 100
    recent_page_size = max(1, min(200, requested_page_size))

    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if (not job) or getattr(job, 'deleted', False):
            return jsonify({"error": "not found"}), 404

        total_recent = len(job.recent_results or [])
        recent_total_pages = max(1, math.ceil(total_recent / recent_page_size))
        recent_page = min(recent_page, recent_total_pages)
        end_idx = total_recent - ((recent_page - 1) * recent_page_size)
        start_idx = max(0, end_idx - recent_page_size)
        recent_page_rows = (job.recent_results or [])[start_idx:end_idx]
        recent_page_rows.reverse()  # newest first within current page

        return jsonify(
            {
                "id": job.id,
                "created_at": job.created_at,
                "campaign_id": job.campaign_id,
                "smtp_host": job.smtp_host,
                "pmta_live": job.pmta_live,
                "pmta_live_ts": job.pmta_live_ts,
                "pmta_domains": job.pmta_domains,
                "pmta_domains_ts": job.pmta_domains_ts,
                "pmta_diag": job.pmta_diag,
                "pmta_diag_ts": job.pmta_diag_ts,
                "pmta_pressure": job.pmta_pressure,
                "pmta_pressure_ts": job.pmta_pressure_ts,
                "pmta_diag": job.pmta_diag,
                "pmta_diag_ts": job.pmta_diag_ts,
                "started_at": job.started_at,
                "updated_at": job.updated_at,
                "status": job.status,
                "total": job.total,
                "sent": job.sent,
                "failed": job.failed,
                "skipped": job.skipped,
                "invalid": job.invalid,
                "delivered": job.delivered,
                "bounced": job.bounced,
                "deferred": job.deferred,
                "complained": job.complained,
                "outcome_series": (job.outcome_series or [])[-60:],
                "accounting_last_ts": job.accounting_last_ts,
                "accounting_error_counts": job.accounting_error_counts,
                "accounting_last_errors": (job.accounting_last_errors or [])[-20:],
                "spam_threshold": job.spam_threshold,
                "spam_score": job.spam_score,
                "spam_detail": job.spam_detail,
                "safe_list_total": job.safe_list_total,
                "safe_list_invalid": job.safe_list_invalid,
                "last_error": job.last_error,
                "chunks_total": job.chunks_total,
                "chunks_done": job.chunks_done,
                "chunks_backoff": job.chunks_backoff,
                "chunks_abandoned": job.chunks_abandoned,
                "paused": job.paused,
                "stop_requested": job.stop_requested,
                "stop_reason": job.stop_reason,
                "speed_epm": job.speed_epm(),
                "eta_s": job.eta_seconds(),
                "current_chunk_info": job.current_chunk_info,
                "current_chunk_domains": job.current_chunk_domains,
                "error_counts": job.error_counts,
                "current_chunk": job.current_chunk,
                "chunk_states": job.chunk_states[-120:],
                "backoff_items": job.backoff_items[-120:],
                "domain_plan": job.domain_plan,
                "domain_sent": job.domain_sent,
                "domain_failed": job.domain_failed,
                "pmta_domains": job.pmta_domains,
                "pmta_domains_ts": job.pmta_domains_ts,
                "logs": [l.__dict__ for l in job.logs[-200:]],
                "recent_results": recent_page_rows,
                "recent_page": recent_page,
                "recent_page_size": recent_page_size,
                "recent_total": total_recent,
                "recent_total_pages": recent_total_pages,
            }
        )


@app.post("/api/job/<job_id>/control")
def api_job_control(job_id: str):
    """Pause/Resume/Stop a running job (used by Jobs UI)."""
    payload = request.get_json(silent=True) or request.form or {}
    action = str(payload.get("action") or "").strip().lower()
    reason = str(payload.get("reason") or "").strip()[:200]

    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"ok": False, "error": "not found"}), 404

        if action == "pause":
            job.paused = True
            if job.status not in {"backoff", "error", "done", "stopped"}:
                job.status = "paused"
            job.log("WARN", "Paused by user")
            return jsonify({"ok": True, "status": job.status})

        if action in {"resume", "unpause"}:
            job.paused = False
            if job.status == "paused":
                job.status = "running"
            job.log("INFO", "Resumed by user")
            return jsonify({"ok": True, "status": job.status})

        if action == "stop":
            job.stop_requested = True
            job.stop_reason = reason or job.stop_reason or "stopped by user"
            job.log("WARN", f"Stop requested: {job.stop_reason}")
            return jsonify({"ok": True, "status": job.status, "stop_requested": True})

    return jsonify({"ok": False, "error": "invalid action"}), 400


@app.get("/api/job/<job_id>/extract/shiva-sent")
def api_job_extract_shiva_sent(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if (not job) or getattr(job, 'deleted', False):
            return jsonify({"error": "not found"}), 404
        rows = list(job.recent_results or [])

    out: List[str] = []
    seen: Set[str] = set()
    for rr in rows:
        if not bool(rr.get("ok")):
            continue
        email = str(rr.get("email") or "").strip().lower()
        if not EMAIL_RE.fullmatch(email) or email in seen:
            continue
        seen.add(email)
        out.append(email)

    body = ("\n".join(out) + ("\n" if out else "")).encode("utf-8")
    resp = make_response(body)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="{job_id}-shiva-sent.txt"'
    return resp


@app.get("/api/job/<job_id>/extract/pmta-delivered")
def api_job_extract_pmta_delivered(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if (not job) or getattr(job, 'deleted', False):
            return jsonify({"error": "not found"}), 404

    out = db_list_outcome_rcpts(job_id, "delivered")
    body = ("\n".join(out) + ("\n" if out else "")).encode("utf-8")
    resp = make_response(body)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="{job_id}-pmta-delivered.txt"'
    return resp


@app.post("/api/job/<job_id>/delete")
def api_job_delete(job_id: str):
    """Delete a job from history.

    - If job is running/backoff/paused, we request stop.
    - Removes from in-memory JOBS and from SQLite jobs table.
    """
    jid = (job_id or "").strip()
    if not jid:
        return jsonify({"ok": False, "error": "missing job id"}), 400

    with JOBS_LOCK:
        job = JOBS.get(jid)
        if job:
            # request stop if active
            if job.status in {"queued", "running", "backoff", "paused"}:
                job.stop_requested = True
                job.paused = False
                job.stop_reason = job.stop_reason or "deleted by user"
                job.status = "stopped"
                job.log("WARN", "Job deleted by user")
            job.deleted = True
            try:
                del JOBS[jid]
            except Exception:
                pass

    # remove from DB
    try:
        db_delete_job(jid)
    except Exception:
        pass

    return jsonify({"ok": True})


@app.get("/api/form")
def api_form_get():
    # Legacy endpoint (kept). Prefer campaign endpoints.
    bid, is_new = get_or_create_browser_id()
    data = db_get_form(bid)
    resp = jsonify({"ok": True, "data": data})
    return attach_browser_cookie(resp, bid, is_new)


@app.post("/api/form")
def api_form_save():
    # Legacy endpoint (kept). Prefer campaign endpoints.
    bid, is_new = get_or_create_browser_id()
    payload = request.get_json(silent=True) or {}
    data = payload.get("data") if isinstance(payload, dict) else {}
    if not isinstance(data, dict):
        data = {}
    db_save_form(bid, data)
    resp = jsonify({"ok": True})
    return attach_browser_cookie(resp, bid, is_new)


@app.post("/api/form/clear")
def api_form_clear():
    # Legacy endpoint (kept). Prefer campaign endpoints.
    bid, is_new = get_or_create_browser_id()
    payload = request.get_json(silent=True) or {}
    scope = str(payload.get("scope") or "mine").strip().lower()
    if scope == "all":
        db_clear_all()
    else:
        db_clear_form(bid)
    resp = jsonify({"ok": True, "scope": scope})
    return attach_browser_cookie(resp, bid, is_new)


# -------------------------
# Campaign APIs (used by the form UI)
# -------------------------
@app.get("/api/campaign/<campaign_id>/form")
def api_campaign_form_get(campaign_id: str):
    bid, is_new = get_or_create_browser_id()
    cid = (campaign_id or "").strip()
    c = db_get_campaign(bid, cid)
    if not c:
        resp = jsonify({"ok": False, "error": "campaign not found"})
        return attach_browser_cookie(resp, bid, is_new), 404

    data = db_get_campaign_form(bid, cid)
    resp = jsonify({"ok": True, "campaign": {"id": c["id"], "name": c["name"]}, "data": data})
    return attach_browser_cookie(resp, bid, is_new)


@app.post("/api/campaign/<campaign_id>/form")
def api_campaign_form_save(campaign_id: str):
    bid, is_new = get_or_create_browser_id()
    cid = (campaign_id or "").strip()
    payload = request.get_json(silent=True) or {}
    data = payload.get("data") if isinstance(payload, dict) else {}
    if not isinstance(data, dict):
        data = {}

    ok = db_save_campaign_form(bid, cid, data)
    if not ok:
        resp = jsonify({"ok": False, "error": "campaign not found"})
        return attach_browser_cookie(resp, bid, is_new), 404

    resp = jsonify({"ok": True})
    return attach_browser_cookie(resp, bid, is_new)


@app.post("/api/campaign/<campaign_id>/clear")
def api_campaign_form_clear(campaign_id: str):
    bid, is_new = get_or_create_browser_id()
    cid = (campaign_id or "").strip()
    ok = db_clear_campaign_form(bid, cid)
    if not ok:
        resp = jsonify({"ok": False, "error": "campaign not found"})
        return attach_browser_cookie(resp, bid, is_new), 404
    resp = jsonify({"ok": True})
    return attach_browser_cookie(resp, bid, is_new)


@app.get("/api/campaign/<campaign_id>/domains_stats")
def api_campaign_domains_stats(campaign_id: str):
    """Compute domains stats for this campaign (reads recipients from SQLite).

    Shows planned distribution: how many emails will be sent to each *recipient domain*.
    """
    bid, is_new = get_or_create_browser_id()
    cid = (campaign_id or "").strip()
    c = db_get_campaign(bid, cid)
    if not c:
        resp = jsonify({"ok": False, "error": "campaign not found"})
        return attach_browser_cookie(resp, bid, is_new), 404

    form = db_get_campaign_form(bid, cid)
    rec_text = str((form or {}).get("recipients") or "")
    safe_text = str((form or {}).get("maillist_safe") or "")

    def compute(text: str) -> dict:
        emails = parse_recipients(text)
        valid_syntax, invalid_syntax = filter_valid_emails(emails)
        valid_mx, invalid_mx, filter_report = pre_send_recipient_filter(valid_syntax, smtp_probe=True)

        invalid_all = list(invalid_syntax) + list(invalid_mx)

        # Count domains (recipient domains)
        counts: Dict[str, int] = {}
        for e in valid_mx:
            d = _extract_domain_from_email(e)
            if not d:
                continue
            counts[d] = counts.get(d, 0) + 1

        domains_sorted = sorted(counts.items(), key=lambda x: x[1], reverse=True)

        # Limit expensive checks to top N domains
        MAX_CHECKS = 200
        out_items: List[dict] = []

        for idx, (dom, cnt) in enumerate(domains_sorted):
            route = filter_report.get("domains", {}).get(dom) or domain_mail_route(dom)
            mx_status = route.get("status", "unknown")
            mx_hosts = route.get("mx_hosts", [])

            mail_ips: List[str] = []
            any_listed = False

            if idx < MAX_CHECKS:
                mail_ips = resolve_sender_domain_ips(dom)
                dbl = check_domain_dnsbl(dom)
                if dbl:
                    any_listed = True
                for ip in mail_ips:
                    if check_ip_dnsbl(ip):
                        any_listed = True
                        break

            out_items.append(
                {
                    "domain": dom,
                    "count": cnt,
                    "mx_status": mx_status,
                    "mx_hosts": mx_hosts,
                    "mail_ips": mail_ips,
                    "any_listed": any_listed,
                }
            )

        return {
            "total_emails": len(emails),
            "invalid_emails": len(invalid_all),
            "unique_domains": len(counts),
            "domains": out_items,
            "filter": filter_report,
        }

    resp = jsonify({"ok": True, "campaign": {"id": c["id"], "name": c["name"]}, "recipients": compute(rec_text), "safe": compute(safe_text)})
    return attach_browser_cookie(resp, bid, is_new)


@app.get("/api/campaign/<campaign_id>/active_job")
def api_campaign_active_job(campaign_id: str):
    """Return the latest active job for this campaign (queued/running/backoff/paused).

    Used by the campaign Domains card to show LIVE per-domain progress.
    """
    bid, is_new = get_or_create_browser_id()
    cid = (campaign_id or "").strip()
    c = db_get_campaign(bid, cid)
    if not c:
        resp = jsonify({"ok": False, "error": "campaign not found"})
        return attach_browser_cookie(resp, bid, is_new), 404

    with JOBS_LOCK:
        active = [
            j for j in JOBS.values()
            if (not getattr(j, 'deleted', False))
            and (j.campaign_id or "") == cid
            and (j.status in {"queued", "running", "backoff", "paused"})
        ]
        active.sort(key=lambda x: x.created_at, reverse=True)
        job = active[0] if active else None

    if not job:
        resp = jsonify({"ok": False, "error": "no active job"})
        return attach_browser_cookie(resp, bid, is_new)

    resp = jsonify(
        {
            "ok": True,
            "job": {
                "id": job.id,
                "created_at": job.created_at,
                "status": job.status,
                "total": job.total,
                "sent": job.sent,
                "failed": job.failed,
                "skipped": job.skipped,
                "invalid": job.invalid,
                "chunks_total": job.chunks_total,
                "chunks_done": job.chunks_done,
                "current_chunk": job.current_chunk,
                "domain_plan": job.domain_plan,
                "domain_sent": job.domain_sent,
                "domain_failed": job.domain_failed,
            },
        }
    )
    return attach_browser_cookie(resp, bid, is_new)


@app.get("/api/campaign/<campaign_id>/latest_job")
def api_campaign_latest_job(campaign_id: str):
    """Return the latest job for this campaign (any status).

    Used by the Campaign page to confirm starting a new job.
    """
    bid, is_new = get_or_create_browser_id()
    cid = (campaign_id or "").strip()
    c = db_get_campaign(bid, cid)
    if not c:
        resp = jsonify({"ok": False, "error": "campaign not found"})
        return attach_browser_cookie(resp, bid, is_new), 404

    with JOBS_LOCK:
        items = [
            j for j in JOBS.values()
            if (not getattr(j, 'deleted', False)) and (j.campaign_id or "") == cid
        ]
        items.sort(key=lambda x: x.created_at, reverse=True)
        job = items[0] if items else None

    if not job:
        resp = jsonify({"ok": False, "error": "no jobs"})
        return attach_browser_cookie(resp, bid, is_new), 404

    resp = jsonify(
        {
            "ok": True,
            "job": {
                "id": job.id,
                "created_at": job.created_at,
                "status": job.status,
                "total": job.total,
                "sent": job.sent,
                "failed": job.failed,
                "skipped": job.skipped,
                "invalid": job.invalid,
            },
        }
    )
    return attach_browser_cookie(resp, bid, is_new)


@app.get("/api/jobs_digest")
def api_jobs_digest():
    """Small jobs digest used by Jobs page auto-refresh (new send detection)."""
    cid = (request.args.get("c") or "").strip()
    with JOBS_LOCK:
        items = [j for j in JOBS.values() if not getattr(j, 'deleted', False)]
        if cid:
            items = [j for j in items if (j.campaign_id or "") == cid]
        items.sort(key=lambda x: x.created_at, reverse=True)
        payload = [
            {
                "id": j.id,
                "campaign_id": j.campaign_id,
                "created_at": j.created_at,
                "status": j.status,
            }
            for j in items
        ]
    return jsonify({"ok": True, "jobs": payload})


# -------------------------
# App Config APIs
# -------------------------
@app.get("/api/config")
def api_config_get():
    items = config_items()
    saved = 0
    try:
        saved = len(db_list_app_config() or {})
    except Exception:
        saved = 0
    return jsonify({"ok": True, "items": items, "saved_overrides": saved})


@app.get("/api/version")
def api_version():
    # Quick sanity check endpoint (helps verify you are running the latest file)
    return jsonify({
        "ok": True,
        "version": APP_VERSION,
        "schema_keys": [str(it.get("key") or "") for it in (APP_CONFIG_SCHEMA or [])],
    })


def _cfg_validate_and_canon(key: str, value: Any) -> Tuple[bool, str, str]:
    """Return (ok, canon_value_str, error)."""
    meta = APP_CONFIG_INDEX.get(key)
    if not meta:
        return False, "", "unknown key"

    typ = str(meta.get("type") or "str").strip().lower()
    v = "" if value is None else str(value)

    if typ == "bool":
        vv = v.strip().lower()
        if vv in {"1", "true", "yes", "on", "y"}:
            return True, "1", ""
        if vv in {"0", "false", "no", "off", "n"}:
            return True, "0", ""
        return False, "", "invalid bool (use 1/0, true/false, yes/no)"

    if typ == "int":
        try:
            return True, str(int(v.strip() or "0")), ""
        except Exception:
            return False, "", "invalid int"

    if typ == "float":
        try:
            return True, str(float(v.strip() or "0")), ""
        except Exception:
            return False, "", "invalid float"

    # str
    if len(v) > 20000:
        v = v[:20000]
    return True, v, ""


@app.post("/api/config/set")
def api_config_set():
    data = request.get_json(silent=True) or {}

    # bulk
    if isinstance(data, dict) and isinstance(data.get("items"), dict):
        items = data.get("items") or {}
        saved = 0
        errors: Dict[str, str] = {}
        for k, v in items.items():
            key = str(k or "").strip()
            ok, canon, err = _cfg_validate_and_canon(key, v)
            if not ok:
                errors[key] = err
                continue
            ok_save, save_err = db_set_app_config(key, canon)
            if ok_save:
                saved += 1
            else:
                errors[key] = save_err or "failed to save"
        try:
            reload_runtime_config()
        except Exception:
            pass
        return jsonify({"ok": (len(errors) == 0), "saved": saved, "errors": errors})

    key = str(data.get("key") or "").strip()
    val = data.get("value")
    ok, canon, err = _cfg_validate_and_canon(key, val)
    if not ok:
        return jsonify({"ok": False, "error": err}), 400

    ok_save, save_err = db_set_app_config(key, canon)
    if not ok_save:
        return jsonify({"ok": False, "error": (save_err or "failed to save")}), 500

    try:
        reload_runtime_config()
    except Exception:
        pass

    return jsonify({"ok": True, "key": key, "value": canon})


@app.post("/api/config/reset")
def api_config_reset():
    data = request.get_json(silent=True) or {}
    key = str(data.get("key") or "").strip()
    if not key:
        return jsonify({"ok": False, "error": "missing key"}), 400

    db_delete_app_config(key)
    try:
        reload_runtime_config()
    except Exception:
        pass

    return jsonify({"ok": True, "key": key})


@app.get("/api/pmta_probe")
def api_pmta_probe():
    """Debug endpoint: probe PMTA Web Monitor endpoints.

    Usage:
      /api/pmta_probe?host=194.116.172.135
      /api/pmta_probe?smtp_host=mail.example.com
    """
    host = (request.args.get("host") or request.args.get("smtp_host") or "").strip()
    if not host:
        return jsonify({"ok": False, "error": "missing host (use ?host=...)"}), 400
    return jsonify(pmta_probe_endpoints(smtp_host=host))




@app.post("/api/smtp_test")
def api_smtp_test():
    """AJAX endpoint used by the UI's 'Test SMTP' button."""
    data = request.get_json(silent=True) or request.form or {}

    def g(k: str, default: str = "") -> str:
        try:
            return str(data.get(k, default) or "").strip()
        except Exception:
            return default

    smtp_host = g("smtp_host")
    smtp_port_raw = g("smtp_port", "2525")
    smtp_security = g("smtp_security", "none")
    smtp_timeout_raw = g("smtp_timeout", "25")
    smtp_user = g("smtp_user")
    smtp_pass = g("smtp_pass")

    if not smtp_host:
        return jsonify({"ok": False, "error": "smtp_host is required"}), 400

    try:
        smtp_port = int(smtp_port_raw)
        if not (1 <= smtp_port <= 65535):
            raise ValueError("port out of range")
    except Exception:
        return jsonify({"ok": False, "error": "invalid smtp_port"}), 400

    try:
        smtp_timeout = int(smtp_timeout_raw)
        if not (3 <= smtp_timeout <= 180):
            raise ValueError("timeout out of range")
    except Exception:
        return jsonify({"ok": False, "error": "invalid smtp_timeout"}), 400

    if smtp_security not in {"starttls", "ssl", "none"}:
        return jsonify({"ok": False, "error": "invalid smtp_security"}), 400

    res = smtp_test_connection(
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_security=smtp_security,
        smtp_timeout=smtp_timeout,
        smtp_user=smtp_user,
        smtp_pass=smtp_pass,
    )

    if res.get("ok"):
        return jsonify(
            {
                "ok": True,
                "detail": res.get("detail", "OK"),
                "time_ms": res.get("time_ms", 0),
                "steps": res.get("steps", []),
            }
        )

    return (
        jsonify(
            {
                "ok": False,
                "error": res.get("error", "unknown error"),
                "time_ms": res.get("time_ms", 0),
                "steps": res.get("steps", []),
            }
        ),
        400,
    )


@app.post("/api/ai_rewrite")
def api_ai_rewrite():
    """Rewrite subject lines + body via OpenRouter.

    This endpoint is interactive: it returns rewritten text and does NOT send.
    """
    data = request.get_json(silent=True) or {}

    token = str(data.get("token") or "").strip()
    subjects = data.get("subjects") or []
    body = str(data.get("body") or "")
    body_format = str(data.get("body_format") or "text").strip().lower()

    if not token:
        return jsonify({"ok": False, "error": "Missing token"}), 400

    if not isinstance(subjects, list):
        subjects = [str(subjects)]

    subjects = [str(x).strip() for x in subjects if str(x).strip()]

    if not subjects:
        return jsonify({"ok": False, "error": "Missing subjects"}), 400
    if not body.strip():
        return jsonify({"ok": False, "error": "Missing body"}), 400

    try:
        new_subjects, new_body, backend = ai_rewrite_subjects_and_body(
            token=token,
            subjects=subjects,
            body=body,
            body_format=body_format,
        )
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    return jsonify({"ok": True, "subjects": new_subjects, "body": new_body, "backend": backend})


@app.post("/api/domains_stats")
def api_domains_stats():
    data = request.get_json(silent=True) or {}

    rec_text = str(data.get("recipients") or "")
    safe_text = str(data.get("maillist_safe") or "")

    def compute(text: str) -> dict:
        emails = parse_recipients(text)
        valid_syntax, invalid_syntax = filter_valid_emails(emails)
        valid_mx, invalid_mx, meta = filter_emails_by_mx(valid_syntax)

        invalid_all = list(invalid_syntax) + list(invalid_mx)

        # Count domains
        counts: Dict[str, int] = {}
        for e in valid_mx:
            d = _extract_domain_from_email(e)
            if not d:
                continue
            counts[d] = counts.get(d, 0) + 1

        # Sort by count desc
        domains_sorted = sorted(counts.items(), key=lambda x: x[1], reverse=True)

        # Limit expensive checks to top N domains
        MAX_CHECKS = 200
        out_items: List[dict] = []

        for idx, (dom, cnt) in enumerate(domains_sorted):
            route = meta.get("domains", {}).get(dom) or domain_mail_route(dom)
            mx_status = route.get("status", "unknown")
            mx_hosts = route.get("mx_hosts", [])

            mail_ips: List[str] = []
            any_listed = False

            if idx < MAX_CHECKS:
                mail_ips = resolve_sender_domain_ips(dom)
                dbl = check_domain_dnsbl(dom)
                if dbl:
                    any_listed = True
                # IP DNSBL
                for ip in mail_ips:
                    if check_ip_dnsbl(ip):
                        any_listed = True
                        break
            else:
                # skip heavy checks
                mail_ips = []
                any_listed = False

            out_items.append(
                {
                    "domain": dom,
                    "count": cnt,
                    "mx_status": mx_status,
                    "mx_hosts": mx_hosts,
                    "mail_ips": mail_ips,
                    "any_listed": any_listed,
                }
            )

        return {
            "total_emails": len(emails),
            "invalid_emails": len(invalid_all),
            "unique_domains": len(counts),
            "domains": out_items,
        }

    return jsonify({"ok": True, "recipients": compute(rec_text), "safe": compute(safe_text)})


@app.post("/api/preflight")
def api_preflight():
    """Return spam score + DNSBL status for sender domain and SMTP host IP(s)."""
    data = request.get_json(silent=True) or request.form or {}

    def g(k: str, default: str = "") -> str:
        try:
            return str(data.get(k, default) or "")
        except Exception:
            return default

    smtp_host = g("smtp_host").strip()
    from_email_raw = g("from_email")
    subject_raw = g("subject")
    body = g("body").strip()
    body_format = g("body_format", "text").strip().lower()

    try:
        spam_threshold = float(g("spam_limit", "4").strip() or "4")
    except Exception:
        spam_threshold = 4.0
    spam_threshold = max(1.0, min(10.0, spam_threshold))

    # First values (same logic as /start)
    from_emails = parse_multiline(from_email_raw, dedupe_lower=True)
    valid_sender_emails, _invalid_sender_emails = filter_valid_emails(from_emails)
    subjects = parse_multiline(subject_raw, dedupe_lower=False)

    from_email = valid_sender_emails[0] if valid_sender_emails else ""
    subject = subjects[0] if subjects else ""

    if not from_email or not subject or not body:
        return (
            jsonify({"ok": False, "error": "Preflight needs Sender Email, Subject and Body."}),
            400,
        )

    spam_score, spam_detail = compute_spam_score(
        subject=subject,
        body=body,
        body_format=body_format,
        from_email=from_email,
    )

    # Reputation checks
    ips = _resolve_ipv4(smtp_host) if smtp_host else []
    ip_listings = {ip: check_ip_dnsbl(ip) for ip in ips}

    domain = _extract_domain_from_email(from_email)
    domain_listings = check_domain_dnsbl(domain) if domain else []

    # NEW: Check ALL sender domains (from the textarea list)
    sender_domains: List[str] = []
    _seen_dom: Set[str] = set()
    for em in valid_sender_emails:
        d = _extract_domain_from_email(em)
        if not d:
            continue
        if d in _seen_dom:
            continue
        _seen_dom.add(d)
        sender_domains.append(d)

    sender_domain_ips = {d: resolve_sender_domain_ips(d) for d in sender_domains}
    sender_domain_ip_listings = {
        d: {ip: check_ip_dnsbl(ip) for ip in ips}
        for d, ips in sender_domain_ips.items()
    }
    sender_domain_dbl_listings = {d: check_domain_dnsbl(d) for d in sender_domains}

    # NEW: Spam score per sender domain (build email using the domain)
    domain_to_sender_email: Dict[str, str] = {}
    for em in valid_sender_emails:
        d = _extract_domain_from_email(em)
        if d and d not in domain_to_sender_email:
            domain_to_sender_email[d] = em

    sender_domain_spam_scores: Dict[str, Optional[float]] = {}
    sender_domain_spam_backends: Dict[str, str] = {}

    for d in sender_domains:
        fe = domain_to_sender_email.get(d) or f"support@{d}"
        s2, det2 = compute_spam_score(subject=subject, body=body, body_format=body_format, from_email=fe)
        sender_domain_spam_scores[d] = s2
        b2 = ""
        if det2 and det2.startswith("backend="):
            b2 = det2.splitlines()[0].replace("backend=", "").strip()
        sender_domain_spam_backends[d] = b2

    # Try to extract backend name from spam_detail header line
    backend = ""
    if spam_detail and spam_detail.startswith("backend="):
        backend = spam_detail.splitlines()[0].replace("backend=", "").strip()

    return jsonify(
        {
            "ok": True,
            "spam_threshold": spam_threshold,
            "spam_score": spam_score,
            "spam_backend": backend,
            "spam_detail": (spam_detail[:800] if spam_detail else ""),
            "smtp_host": smtp_host,
            "ips": ips,
            "ip_listings": ip_listings,
            "sender_email": from_email,
            "sender_domain": domain,
            "domain_listings": domain_listings,
            "sender_domains": sender_domains,
            "sender_domain_ips": sender_domain_ips,
            "sender_domain_ip_listings": sender_domain_ip_listings,
            "sender_domain_dbl_listings": sender_domain_dbl_listings,
            "sender_domain_spam_scores": sender_domain_spam_scores,
            "sender_domain_spam_backends": sender_domain_spam_backends,
            "rbl_zones": RBL_ZONES_LIST,
            "dbl_zones": DBL_ZONES_LIST,
        }
    )


@app.get("/api/accounting/bridge/status")
def api_accounting_bridge_status():
    """Expose latest bridge polling diagnostics for browser console debugging."""
    with _BRIDGE_DEBUG_LOCK:
        state = dict(_BRIDGE_DEBUG_STATE)
    state["pull_enabled"] = bool(PMTA_BRIDGE_PULL_ENABLED)
    state["pull_interval_s"] = float(PMTA_BRIDGE_PULL_S or 0)
    state["pull_max_lines"] = int(PMTA_BRIDGE_PULL_MAX_LINES or 0)
    state["pull_kind"] = (PMTA_BRIDGE_PULL_KIND or "").strip()
    state["pull_all_files"] = bool(PMTA_BRIDGE_PULL_ALL_FILES)
    state["pull_url"] = (PMTA_BRIDGE_PULL_URL or "").strip()
    state["pull_url_configured"] = bool(state["pull_url"])
    if state["pull_url"]:
        state["pull_url_masked"] = state["pull_url"].split("?", 1)[0]
    else:
        state["pull_url_masked"] = ""
    return jsonify({"ok": True, "bridge": state})


@app.post("/api/accounting/bridge/pull")
def api_accounting_bridge_pull_once():
    """Manual pull from bridge endpoint (same processing path as periodic poller)."""
    if not PMTA_BRIDGE_PULL_URL:
        return jsonify({"ok": False, "error": "bridge pull URL is not configured"}), 400
    return jsonify(_poll_accounting_bridge_once())


@app.post("/start")
def start():
    # Required permission checkbox
    if request.form.get("permission_ok") != "on":
        return "Permission confirmation required.", 400

    # Campaign context (required)
    campaign_id = (request.form.get("campaign_id") or "").strip()
    bid, is_new = get_or_create_browser_id()
    if not campaign_id:
        return "Missing campaign_id. Please open a campaign first.", 400
    if not db_get_campaign(bid, campaign_id):
        return "Invalid campaign. Please open a valid campaign.", 400

    # Hard guard: prevent duplicate /start while a previous start request is still being processed.
    # This fixes duplicated jobs when the user navigates away/back and clicks Start again quickly.
    if not start_guard_acquire(campaign_id):
        return "A send request is already being processed for this campaign. Please wait until the job is created.", 429
    g._start_guard_campaign = campaign_id

    # If there is already an ACTIVE job for this campaign, require explicit confirmation.
    force_new = (request.form.get("force_new_job") or "").strip().lower() in {"1", "true", "yes", "on"}
    if not force_new:
        with JOBS_LOCK:
            active = [
                j for j in JOBS.values()
                if (not getattr(j, "deleted", False))
                and (j.campaign_id or "") == campaign_id
                and (j.status in {"queued", "running", "backoff", "paused"})
            ]
            active.sort(key=lambda x: x.created_at, reverse=True)
            if active:
                aj = active[0]
                return (
                    f"Active job already in progress for this campaign: {aj.id} (status={aj.status}). "
                    f"If you want another job, confirm and try again.",
                    409,
                )

    smtp_host = (request.form.get("smtp_host") or "").strip()
    smtp_port_raw = (request.form.get("smtp_port") or "2525").strip()
    try:
        smtp_port = int(smtp_port_raw)
        if not (1 <= smtp_port <= 65535):
            raise ValueError("port out of range")
    except Exception:
        return "Invalid SMTP Port.", 400
    smtp_security = (request.form.get("smtp_security") or "none").strip()
    smtp_timeout_raw = (request.form.get("smtp_timeout") or "25").strip()
    try:
        smtp_timeout = int(smtp_timeout_raw)
        if not (3 <= smtp_timeout <= 180):
            raise ValueError("timeout out of range")
    except Exception:
        return "Invalid SMTP Timeout.", 400
    smtp_user = (request.form.get("smtp_user") or "").strip()
    smtp_pass = (request.form.get("smtp_pass") or "").strip()

    # Optional: PowerMTA health check (Web Monitor / HTTP Monitoring API)
    # Runs BEFORE creating the job/thread (fast fail when PMTA is down/busy).
    pmta_hc = pmta_health_check(smtp_host=smtp_host)
    if pmta_hc.get("enabled"):
        if (not pmta_hc.get("ok")) and pmta_hc.get("required"):
            return (
                f"PowerMTA health-check failed (monitor unreachable). "
                f"Reason: {pmta_hc.get('reason','unknown')}. "
                f"URL: {pmta_hc.get('status_url','')}",
                503,
            )
        if pmta_hc.get("busy"):
            return (
                f"PowerMTA is busy/overloaded. Please wait and try again. "
                f"Reason: {pmta_hc.get('reason','busy')}. "
                f"URL: {pmta_hc.get('status_url','')}",
                503,
            )

    # Sender / Subject can be multiple lines (one value per line)
    from_names = parse_multiline(request.form.get("from_name") or "", dedupe_lower=False)
    from_emails_raw = parse_multiline(request.form.get("from_email") or "", dedupe_lower=True)
    valid_sender_emails, invalid_sender_emails = filter_valid_emails(from_emails_raw)
    subjects = parse_multiline(request.form.get("subject") or "", dedupe_lower=False)

    # AI rewrite controls
    use_ai = (request.form.get("use_ai") == "on")
    enable_backoff = (request.form.get("enable_backoff") == "on")
    ai_token = (request.form.get("ai_token") or "").strip()

    reply_to = (request.form.get("reply_to") or "").strip()

    # For now we use the FIRST value; you can rotate/select later.
    from_name = from_names[0] if from_names else ""
    from_email = valid_sender_emails[0] if valid_sender_emails else ""
    subject = subjects[0] if subjects else ""
    body_format = (request.form.get("body_format") or "text").strip()
    body = (request.form.get("body") or "").strip()

    # Optional per-email placeholders
    urls_list = parse_multiline(request.form.get("urls_list") or "", dedupe_lower=False)
    src_list = parse_multiline(request.form.get("src_list") or "", dedupe_lower=False)

    delay_s = float(request.form.get("delay_s") or "0")
    max_rcpt = int(request.form.get("max_rcpt") or "300")

    # Threaded chunking controls
    try:
        chunk_size = int(request.form.get("chunk_size") or "50")
    except Exception:
        chunk_size = 50
    chunk_size = max(1, min(50000, chunk_size))

    try:
        thread_workers = int(request.form.get("thread_workers") or "5")
    except Exception:
        thread_workers = 5
    thread_workers = max(1, min(200, thread_workers))

    try:
        sleep_chunks = float(request.form.get("sleep_chunks") or "0")
    except Exception:
        sleep_chunks = 0.0
    sleep_chunks = max(0.0, min(120.0, sleep_chunks))

    # Spam score limit (slider)
    try:
        spam_threshold = float(request.form.get("score_range") or "4")
    except Exception:
        spam_threshold = 4.0
    spam_threshold = max(1.0, min(10.0, spam_threshold))

    if use_ai and not ai_token:
        return "AI token is required when 'Use AI rewrite' is enabled.", 400

    # --- Better validation (more helpful than "Missing required fields")
    errors: List[str] = []
    if not smtp_host:
        errors.append("SMTP Host is required")

    if not from_names:
        errors.append("Sender Name is required (textarea, one per line)")

    if not from_emails_raw:
        errors.append("Sender Email is required (textarea, one per line)")
    elif not valid_sender_emails:
        sample = ", ".join(invalid_sender_emails[:5])
        errors.append(f"No valid Sender Email found. Invalid examples: {sample}")

    if not subjects:
        errors.append("Subject is required (textarea, one per line)")

    if not body:
        errors.append("Body is required")

    if errors:
        return "Validation errors:\n- " + "\n- ".join(errors), 400

    # Collect recipients from textarea
    recipients_text = request.form.get("recipients") or ""
    recipients = parse_recipients(recipients_text)

    # Also from file (txt/csv)
    f = request.files.get("recipients_file")
    if f and f.filename:
        try:
            content = f.read().decode("utf-8", errors="ignore")
            # For CSV we still extract anything that looks like an email by splitting.
            recipients += parse_recipients(content)
        except Exception:
            pass

    recipients = parse_recipients("\n".join(recipients))  # dedupe again
    valid, invalid = filter_valid_emails(recipients)
    syntax_valid = list(valid)

    # Pre-send recipient filter (syntax/domain + optional SMTP probe)
    valid, mx_invalid, recipient_filter = pre_send_recipient_filter(valid, smtp_probe=True)
    if mx_invalid:
        invalid.extend(mx_invalid)

    # Safety fallback: if DNS/probe temporarily rejects everything, do not hard-block
    # a send that already passed syntax validation. This avoids false negatives after
    # transient resolver/provider issues and lets runtime delivery decide.
    if syntax_valid and not valid:
        valid = syntax_valid
        recipient_filter = {**recipient_filter, "degraded_fallback": True, "degraded_reason": "all_filtered_by_route_checks"}

    # Safe list (optional whitelist)
    safe_text = request.form.get("maillist_safe") or ""
    safe_raw = parse_recipients(safe_text)
    safe_valid, safe_invalid = filter_valid_emails(safe_raw)

    # Apply the same pre-send filter for safe list
    safe_valid, safe_mx_invalid, safe_filter = pre_send_recipient_filter(safe_valid, smtp_probe=True)
    if safe_mx_invalid:
        safe_invalid.extend(safe_mx_invalid)

    safe_skipped = 0
    if safe_valid:
        safe_set = {e.lower() for e in safe_valid}
        filtered = [r for r in valid if r.lower() in safe_set]
        safe_skipped = len(valid) - len(filtered)
        valid = filtered

    if safe_valid and len(valid) == 0:
        return "Safe maillist is set, but none of the recipients are in it.", 400

    if len(valid) == 0:
        sample = ", ".join(invalid[:8])
        return f"No valid recipients found. Invalid count={len(invalid)}. Examples: {sample}", 400

    if len(valid) > max_rcpt:
        return f"Too many recipients ({len(valid)}). Max allowed is {max_rcpt}.", 400

    # Compute spam score BEFORE sending (check ALL sender domains)
    domain_to_sender: Dict[str, str] = {}
    for em in valid_sender_emails:
        d = _extract_domain_from_email(em)
        if d and d not in domain_to_sender:
            domain_to_sender[d] = em

    worst_domain = ""
    worst_score: Optional[float] = None
    worst_detail = ""

    for d, em in domain_to_sender.items():
        sc, det = compute_spam_score(subject=subject, body=body, body_format=body_format, from_email=em)
        if sc is None:
            continue
        if worst_score is None or sc > worst_score:
            worst_score = sc
            worst_domain = d
            worst_detail = det

    spam_score = worst_score
    spam_detail = worst_detail

    # If user has multiple variants (subjects or body variants), don't hard-block the whole job here.
    # Per-chunk preflight + backoff will handle it.
    body_variants = split_body_variants(body)
    multi_variant = (len(subjects) > 1) or (len(body_variants) > 1)

    if (not multi_variant) and (spam_score is not None) and (spam_score > spam_threshold):
        return (
            f"Blocked: Spam score {spam_score} is higher than limit {spam_threshold}. "
            f"Worst sender domain: {worst_domain}. Please improve the subject/body before sending (run Preflight for details).",
            400,
        )

    if multi_variant and (spam_score is not None) and (spam_score > spam_threshold):
        # Allow start, but log later (job) that initial variant is risky.
        pass

    job_id = uuid.uuid4().hex[:12]
    job = SendJob(
        id=job_id,
        created_at=now_iso(),
        updated_at=now_iso(),
        campaign_id=campaign_id,
        smtp_host=smtp_host,
        total=len(valid),
        invalid=len(invalid),
        skipped=safe_skipped,
        spam_threshold=spam_threshold,
        spam_score=spam_score,
        spam_detail=spam_detail,
        safe_list_total=len(safe_valid),
        safe_list_invalid=len(safe_invalid),
    )
    job.domain_plan = count_recipient_domains(valid)
    job.domain_sent = {}
    job.domain_failed = {}
    # MX stats note
    job.log(
        "INFO",
        "Recipient filter applied: "
        f"checks={'+'.join(recipient_filter.get('checks') or ['syntax','mx_or_a'])} "
        f"kept={recipient_filter.get('kept', len(valid))} dropped={recipient_filter.get('dropped', len(mx_invalid))} "
        f"smtp_probe={recipient_filter.get('smtp_probe_used', 0)}/{recipient_filter.get('smtp_probe_limit', 0)}; "
        f"safe_kept={safe_filter.get('kept', len(safe_valid))} safe_dropped={safe_filter.get('dropped', len(safe_mx_invalid))}",
    )

    # PMTA monitor snapshot (if enabled)
    try:
        if isinstance(locals().get('pmta_hc'), dict) and pmta_hc.get('enabled'):
            job.log(
                "INFO",
                "PMTA monitor: "
                f"ok={pmta_hc.get('ok')} busy={pmta_hc.get('busy')} reason={pmta_hc.get('reason')} "
                f"status_url={pmta_hc.get('status_url')} "
                f"spool_rcpt={pmta_hc.get('spool_recipients')} spool_msg={pmta_hc.get('spool_messages')} "
                f"queued_rcpt={pmta_hc.get('queued_recipients')} queued_msg={pmta_hc.get('queued_messages')}"
            )
    except Exception:
        pass
    job.log("INFO", f"Accepted {len(valid)} valid recipients, {len(invalid)} invalid recipients filtered.")
    if safe_valid:
        job.log("INFO", f"Safe maillist ON: safe_total={len(safe_valid)} safe_invalid={len(safe_invalid)} skipped_by_safe={safe_skipped}.")
    else:
        job.log("INFO", f"Safe maillist OFF: safe_invalid={len(safe_invalid)}.")

    if spam_score is None:
        job.log("WARN", f"Spam scoring unavailable: {spam_detail}")
    else:
        job.log("INFO", f"Spam score BEFORE send: score={spam_score} limit={spam_threshold}")
        if spam_detail:
            job.log("INFO", f"Spam detail (truncated): {spam_detail[:600]}")
    job.log(
        "INFO",
        f"Sender inputs: names={len(from_names)} emails_valid={len(valid_sender_emails)} emails_invalid={len(invalid_sender_emails)} subjects={len(subjects)}. "
        f"Sending mode: provider-aware round-robin chunks (one recipient-domain chunk -> one sender email/IP rotation).",
    )
    job.log(
        "INFO",
        f"Chunk controls: chunk_size={chunk_size} workers={thread_workers} sleep_between_chunks={sleep_chunks}s delay_between_messages={delay_s}s",
    )
    job.log("INFO", f"Backoff protection: {'ON' if enable_backoff else 'OFF'} (covers spam/blacklist/PMTA policy checks; SEND_DNSBL={'ON' if SEND_DNSBL else 'OFF'}).")

    with JOBS_LOCK:
        JOBS[job_id] = job

    # Persist job immediately (so it appears in Jobs even after refresh)
    job.maybe_persist(force=True)

    t = threading.Thread(
        target=smtp_send_job,
        daemon=True,
        args=(
            job_id,
            smtp_host,
            smtp_port,
            smtp_security,
            smtp_timeout,
            smtp_user,
            smtp_pass,
            from_names,
            valid_sender_emails,
            subjects,
            reply_to,
            body_format,
            body,
            valid,
            delay_s,
            urls_list,
            src_list,
            chunk_size,
            thread_workers,
            sleep_chunks,
            enable_backoff,
            use_ai,
            ai_token,
        ),
    )
    t.start()

    return redirect(url_for("job_page", job_id=job_id))


if __name__ == "__main__":
    # For local use. In production, use a real WSGI server (gunicorn/waitress).
    app.run(
        host=(os.getenv("SHIVA_HOST", "0.0.0.0") or "0.0.0.0").strip(),
        port=int((os.getenv("SHIVA_PORT", "5001") or "5001").strip()),
        debug=True,
    )
