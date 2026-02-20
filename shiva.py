# app_v2_sender.py (enhanced)
# Notes:
# - Adds: Campaign Edit + Delete
# - Adds: Per-campaign SEED (test list) so sending works without env vars (still seed-only by default)
# - Fixes: queued recipients not in seed list would stall the campaign (now marked as 'skipped')
#
# IMPORTANT: Use ONLY permission-based/opt-in recipients.

import os, re, hmac, json, hashlib, base64, time, threading
from datetime import datetime
from typing import List, Tuple, Optional

from flask import Flask, request, jsonify, redirect, abort, render_template_string
from flask_sqlalchemy import SQLAlchemy
from markupsafe import Markup, escape

import smtplib
import ssl as sslmod
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from email.utils import format_datetime

from sqlalchemy import text as sql_text

# ----------------------------
# App / DB
# ----------------------------
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DB_URL", "sqlite:///mailer.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-please")

# Allow background threads to access SQLite safely (dev/testing).
# For production, prefer Postgres/MySQL.
if str(app.config["SQLALCHEMY_DATABASE_URI"]).startswith("sqlite:"):
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"connect_args": {"check_same_thread": False}}

db = SQLAlchemy(app)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


# ----------------------------
# Models
# ----------------------------
class Suppression(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=False)
    reason = db.Column(db.String(64), nullable=False)
    meta = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.String(32), default=now_iso)


class Recipient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=False)
    isp = db.Column(db.String(32), nullable=False, default="other")
    status = db.Column(db.String(16), nullable=False, default="active")  # active/suppressed
    created_at = db.Column(db.String(32), default=now_iso)


class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)

    # SMTP relay settings (typically your PMTA submission host)
    smtp_host = db.Column(db.String(255), nullable=False)
    smtp_port = db.Column(db.Integer, nullable=False, default=2525)
    smtp_mode = db.Column(db.String(16), nullable=False, default="starttls")  # plain/starttls/ssl
    smtp_user = db.Column(db.String(255), nullable=True)
    smtp_pass = db.Column(db.String(255), nullable=True)

    # Campaign content
    from_profiles = db.Column(db.Text, nullable=False, default="")  # lines
    subjects = db.Column(db.Text, nullable=False, default="")       # lines
    letter = db.Column(db.Text, nullable=False, default="")         # html/text

    # Controls / config
    base_url = db.Column(db.String(255), nullable=False, default="http://127.0.0.1:5000")
    isp_limits_json = db.Column(db.Text, nullable=False, default="{}")
    pool_size = db.Column(db.Integer, nullable=False, default=10)
    max_inflight = db.Column(db.Integer, nullable=False, default=100)

    # Per-campaign seed list for TEST mode (works even if env SEED_LIST is empty)
    # This column is added via a small migration helper at startup.
    seed_list = db.Column(db.Text, nullable=False, default="")

    # Campaign-level runtime config that behaves like editable env config
    env_parameters_json = db.Column(db.Text, nullable=False, default="{}")
    env_variables_json = db.Column(db.Text, nullable=False, default="{}")

    # QA / safety
    qa_score = db.Column(db.Float, nullable=True)
    status = db.Column(db.String(16), nullable=False, default="draft")  # draft/paused/running/stopped

    # Metrics snapshot (updated here during submission; bounces/complaints come from log ingestion later)
    metrics_json = db.Column(
        db.Text,
        nullable=False,
        default='{"sent":0,"hard_bounces":0,"complaints":0,"failed":0,"updated_at":null}',
    )

    created_at = db.Column(db.String(32), default=now_iso)


class CampaignRecipient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey("campaign.id"), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey("recipient.id"), nullable=False)
    state = db.Column(db.String(16), nullable=False, default="queued")  # queued/sending/sent/failed/suppressed/skipped
    created_at = db.Column(db.String(32), default=now_iso)


# ----------------------------
# Lightweight DB migration (SQLite-friendly)
# ----------------------------

def _sqlite_has_column(table: str, column: str) -> bool:
    rows = db.session.execute(sql_text(f"PRAGMA table_info({table});")).fetchall()
    cols = {r[1] for r in rows}  # (cid, name, type, notnull, dflt_value, pk)
    return column in cols


def ensure_schema():
    """Adds missing columns for SQLite without requiring Alembic.

    This is intentionally minimal for dev/testing.
    """
    try:
        if db.engine.dialect.name == "sqlite":
            # seed_list
            if not _sqlite_has_column("campaign", "seed_list"):
                db.session.execute(sql_text("ALTER TABLE campaign ADD COLUMN seed_list TEXT DEFAULT ''"))
                db.session.commit()
            if not _sqlite_has_column("campaign", "env_parameters_json"):
                db.session.execute(sql_text("ALTER TABLE campaign ADD COLUMN env_parameters_json TEXT DEFAULT '{}'"))
                db.session.commit()
            if not _sqlite_has_column("campaign", "env_variables_json"):
                db.session.execute(sql_text("ALTER TABLE campaign ADD COLUMN env_variables_json TEXT DEFAULT '{}'"))
                db.session.commit()
        else:
            # For other DBs, try a best-effort IF NOT EXISTS.
            try:
                db.session.execute(sql_text("ALTER TABLE campaign ADD COLUMN IF NOT EXISTS seed_list TEXT"))
                db.session.execute(sql_text("ALTER TABLE campaign ADD COLUMN IF NOT EXISTS env_parameters_json TEXT"))
                db.session.execute(sql_text("ALTER TABLE campaign ADD COLUMN IF NOT EXISTS env_variables_json TEXT"))
                db.session.commit()
            except Exception:
                db.session.rollback()
    except Exception:
        db.session.rollback()


# ----------------------------
# ISP classification
# ----------------------------
ISP_MAP = {
    "gmail.com": "gmail",
    "googlemail.com": "gmail",
    "outlook.com": "microsoft",
    "hotmail.com": "microsoft",
    "live.com": "microsoft",
    "msn.com": "microsoft",
    "yahoo.com": "yahoo",
    "ymail.com": "yahoo",
    "aol.com": "yahoo",
}


def classify_isp(email: str) -> str:
    domain = email.split("@")["-1"].lower().strip() if "@" in email else ""
    return ISP_MAP.get(domain, "other")


# ----------------------------
# Safe deterministic tokens
# ----------------------------
def _h(data: str) -> bytes:
    return hashlib.sha256(data.encode("utf-8")).digest()


def message_id_for(campaign_id: int, email: str) -> str:
    raw = _h(f"mid|{campaign_id}|{email}")
    return base64.urlsafe_b64encode(raw[:12]).decode().rstrip("=")


def id_num_for(campaign_id: int, email: str) -> str:
    raw = _h(f"num|{campaign_id}|{email}")
    n = int.from_bytes(raw[:4], "big") % 1_000_000
    return f"{n:06d}"


def id_mix_for(campaign_id: int, email: str) -> str:
    raw = base64.urlsafe_b64encode(_h(f"mix|{campaign_id}|{email}")[:9]).decode().rstrip("=")
    return raw[:12]


def tracking_code_for(campaign_id: int, email: str) -> str:
    raw = base64.b32encode(_h(f"trk|{campaign_id}|{email}")[:10]).decode().rstrip("=")
    return raw[:16].lower()


# ----------------------------
# Unsubscribe token
# ----------------------------
def make_unsub_token(email: str) -> str:
    key = app.config["SECRET_KEY"].encode()
    sig = hmac.new(key, email.encode(), hashlib.sha256).hexdigest()
    return f"{email}.{sig}"


def verify_unsub_token(token: str) -> Optional[str]:
    try:
        email, sig = token.rsplit(".", 1)
        expected = make_unsub_token(email).rsplit(".", 1)[1]
        return email if hmac.compare_digest(sig, expected) else None
    except Exception:
        return None


@app.get("/u/<token>")
def unsubscribe(token):
    email = verify_unsub_token(token)
    if not email:
        abort(404)

    if not Suppression.query.filter_by(email=email).first():
        db.session.add(Suppression(email=email, reason="unsubscribe"))

    r = Recipient.query.filter_by(email=email).first()
    if r:
        r.status = "suppressed"
    db.session.commit()
    return "Unsubscribed successfully ✅"


# ----------------------------
# Parsing helpers
# ----------------------------
def parse_lines(txt: str) -> List[str]:
    return [l.strip() for l in (txt or "").replace("\r\n", "\n").split("\n") if l.strip()]


def parse_from_profiles(txt: str) -> List[Tuple[str, str]]:
    """Accept lines like:
    - Name <email@domain.com>
    - email@domain.com | Name
    - email@domain.com
    """
    out = []
    for line in parse_lines(txt):
        if "<" in line and ">" in line:
            name = line.split("<", 1)[0].strip()
            email = line.split("<", 1)[1].split(">", 1)[0].strip()
        elif "|" in line:
            email, name = [x.strip() for x in line.split("|", 1)]
        else:
            email, name = line.strip(), ""
        email = email.lower()
        if EMAIL_RE.match(email):
            out.append((name, email))
    return out


def sanitize_email_list(txt: str) -> List[str]:
    emails = []
    seen = set()
    for line in parse_lines(txt):
        parts = re.split(r"[,\s;]+", line.strip())
        for p in parts:
            p = p.strip().lower()
            if EMAIL_RE.match(p) and p not in seen:
                seen.add(p)
                emails.append(p)
                break
    return emails


# ----------------------------
# Variant selection (balanced, deterministic)
# ----------------------------
def pick_variant(items: List[str], campaign_id: int, email: str) -> str:
    if not items:
        return ""
    raw = _h(f"pick|{campaign_id}|{email}")
    idx = int.from_bytes(raw[:4], "big") % len(items)
    return items[idx]


def pick_from_profile(profiles: List[Tuple[str, str]], campaign_id: int, email: str) -> Tuple[str, str]:
    if not profiles:
        return ("", "")
    raw = _h(f"from|{campaign_id}|{email}")
    idx = int.from_bytes(raw[:4], "big") % len(profiles)
    return profiles[idx]


# ----------------------------
# Placeholder rendering
# ----------------------------
PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")


def render_placeholders(text: str, ctx: dict) -> str:
    def repl(m):
        k = m.group(1)
        return str(ctx.get(k, m.group(0)))

    return PLACEHOLDER_RE.sub(repl, text or "")


# ----------------------------
# Kill switch rules
# ----------------------------
KILL_RULES = {"min_sample": 500, "max_hard_bounce_rate": 0.05, "max_complaints_rate": 0.001}


def should_kill(metrics: dict) -> bool:
    sent = int(metrics.get("sent", 0))
    if sent < KILL_RULES["min_sample"]:
        return False
    hb = float(metrics.get("hard_bounces", 0)) / max(sent, 1)
    cp = float(metrics.get("complaints", 0)) / max(sent, 1)
    return hb >= KILL_RULES["max_hard_bounce_rate"] or cp >= KILL_RULES["max_complaints_rate"]


# ----------------------------
# Content QA scoring stub
# ----------------------------
def content_qa_score(subject: str, letter: str) -> float:
    # Placeholder: integrate your real QA logic here.
    return 85.0


# ----------------------------
# SMTP connection test
# ----------------------------
def smtp_test(host: str, port: int, mode: str, user: str = "", pw: str = "", timeout: int = 15) -> Tuple[bool, str]:
    try:
        mode = (mode or "").lower().strip()
        if mode == "ssl":
            ctx = sslmod.create_default_context()
            srv = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
        else:
            srv = smtplib.SMTP(host, port, timeout=timeout)
        srv.ehlo()
        if mode == "starttls":
            ctx = sslmod.create_default_context()
            srv.starttls(context=ctx)
            srv.ehlo()
        if user:
            srv.login(user, pw)
        srv.quit()
        return True, "OK"
    except Exception as e:
        return False, str(e)


# ----------------------------
# Sending (compliance-first)
# ----------------------------
# SAFETY DEFAULT:
# Bulk sending is OFF by default to prevent accidental misuse.
# - You can test sending via per-campaign Seed list (UI) OR env SEED_LIST.
# - To enable bulk: set ALLOW_BULK_SEND=1 (ONLY for opt-in / permission-based recipients).
ALLOW_BULK_SEND = str(os.getenv("ALLOW_BULK_SEND", "0")).strip().lower() in ("1", "true", "yes")
ENV_SEED_LIST = {e.strip().lower() for e in str(os.getenv("SEED_LIST", "")).split(",") if e.strip()}
MAX_SEND_PER_RUN = int(os.getenv("MAX_SEND_PER_RUN", "0") or 0)  # 0 = unlimited

DEFAULT_ENV_PARAMETERS = {
    "allow_bulk_send": False,
    "max_send_per_run": 0,
    "seed_mode_enabled": True,
    "sending_enabled": True,
}
DEFAULT_ENV_VARIABLES = {"SEED_LIST": ""}

_SENDER_LOCK = threading.Lock()
_SENDER = {}  # cid -> {thread, stop_event}


def _campaign_seed_set(c: Campaign) -> set:
    # Campaign UI seed list (newline/comma/space)
    campaign_seeds = set(sanitize_email_list(c.seed_list or ""))
    env_vars = _safe_json_load(c.env_variables_json or "{}", DEFAULT_ENV_VARIABLES)
    env_seed_raw = str(env_vars.get("SEED_LIST", "") or "")
    env_seed = {e.strip().lower() for e in env_seed_raw.split(",") if e.strip()}
    return set(ENV_SEED_LIST) | campaign_seeds | env_seed


def _campaign_env_parameters(c: Campaign) -> dict:
    cfg = _safe_json_load(c.env_parameters_json or "{}", DEFAULT_ENV_PARAMETERS)
    out = dict(DEFAULT_ENV_PARAMETERS)
    out.update({k: cfg.get(k, v) for k, v in DEFAULT_ENV_PARAMETERS.items()})
    out["allow_bulk_send"] = bool(out.get("allow_bulk_send", False))
    out["seed_mode_enabled"] = bool(out.get("seed_mode_enabled", True))
    out["sending_enabled"] = bool(out.get("sending_enabled", True))
    out["max_send_per_run"] = max(int(out.get("max_send_per_run", 0) or 0), 0)
    return out


class TokenBucket:
    def __init__(self, rate_per_min: int, burst: int):
        rate_per_min = max(int(rate_per_min or 0), 0)
        burst = max(int(burst or 0), 1)
        self.rate_per_sec = rate_per_min / 60.0
        self.capacity = burst
        self.tokens = float(burst)
        self.last = time.monotonic()

    def _refill(self):
        now = time.monotonic()
        dt = max(0.0, now - self.last)
        self.last = now
        self.tokens = min(self.capacity, self.tokens + dt * self.rate_per_sec)

    def take(self, n: float = 1.0) -> bool:
        self._refill()
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False


def _safe_json_load(s: str, fallback: dict) -> dict:
    try:
        x = json.loads(s or "{}")
        return x if isinstance(x, dict) else dict(fallback)
    except Exception:
        return dict(fallback)


def _get_isp_limits(c: Campaign) -> dict:
    defaults = {
        "gmail": {"rate_per_min": 120, "burst": 30, "max_inflight": 50},
        "microsoft": {"rate_per_min": 80, "burst": 20, "max_inflight": 40},
        "yahoo": {"rate_per_min": 60, "burst": 15, "max_inflight": 30},
        "other": {"rate_per_min": 100, "burst": 25, "max_inflight": 40},
    }
    cfg = _safe_json_load(c.isp_limits_json or "{}", defaults)
    for k, v in defaults.items():
        if k not in cfg or not isinstance(cfg.get(k), dict):
            cfg[k] = v
        for kk in ("rate_per_min", "burst", "max_inflight"):
            cfg[k][kk] = int(cfg[k].get(kk, v[kk]) or v[kk])
    return cfg


def _build_email_message(c: Campaign, to_email: str) -> EmailMessage:
    subjects = parse_lines(c.subjects)
    from_profiles = parse_from_profiles(c.from_profiles)

    subj = pick_variant(subjects, c.id, to_email)
    name, from_email = pick_from_profile(from_profiles, c.id, to_email)
    from_fmt = f"{name} <{from_email}>" if name else (from_email or "")

    unsub = f"{c.base_url.rstrip('/')}/u/{make_unsub_token(to_email)}"

    ctx = {
        "email": to_email,
        "message_id": message_id_for(c.id, to_email),
        "tracking_code": tracking_code_for(c.id, to_email),
        "id_num": id_num_for(c.id, to_email),
        "id_mix": id_mix_for(c.id, to_email),
        "unsubscribe_url": unsub,
    }

    subj_r = render_placeholders(subj, ctx)
    body_r = render_placeholders(c.letter, ctx)

    html = body_r or ""
    if "<" not in html:
        html = escape(html).replace("\n", "<br/>")

    text = re.sub(r"<br\\s*/?>", "\n", html, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)

    msg = EmailMessage()
    msg["From"] = from_fmt
    msg["To"] = to_email
    msg["Subject"] = subj_r
    msg["Date"] = format_datetime(datetime.utcnow())

    domain = "localhost"
    if from_email and "@" in from_email:
        domain = from_email.split("@", 1)[1].strip().lower() or domain
    msg["Message-ID"] = f"<{ctx['message_id']}@{domain}>"

    # Compliance: unsubscribe headers
    msg["List-Unsubscribe"] = f"<{unsub}>"
    msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"

    # Optional tracking headers
    msg["X-Campaign-ID"] = str(c.id)
    msg["X-Tracking-Code"] = ctx["tracking_code"]

    msg.set_content(text or "(HTML email)")
    msg.add_alternative(html, subtype="html")
    return msg


def _smtp_send_message(c: Campaign, msg: EmailMessage, timeout: int = 20) -> Tuple[bool, str]:
    try:
        mode = (c.smtp_mode or "starttls").lower().strip()
        host = (c.smtp_host or "").strip()
        port = int(c.smtp_port or 2525)

        if mode == "ssl":
            ctx = sslmod.create_default_context()
            srv = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
        else:
            srv = smtplib.SMTP(host, port, timeout=timeout)

        srv.ehlo()
        if mode == "starttls":
            ctx = sslmod.create_default_context()
            srv.starttls(context=ctx)
            srv.ehlo()

        if c.smtp_user:
            srv.login(c.smtp_user, c.smtp_pass or "")

        srv.send_message(msg)
        srv.quit()
        return True, "OK"
    except Exception as e:
        return False, str(e)


def _campaign_counts(cid: int) -> dict:
    total = CampaignRecipient.query.filter_by(campaign_id=cid).count()
    queued = CampaignRecipient.query.filter_by(campaign_id=cid, state="queued").count()
    sending = CampaignRecipient.query.filter_by(campaign_id=cid, state="sending").count()
    sent = CampaignRecipient.query.filter_by(campaign_id=cid, state="sent").count()
    failed = CampaignRecipient.query.filter_by(campaign_id=cid, state="failed").count()
    suppressed = CampaignRecipient.query.filter_by(campaign_id=cid, state="suppressed").count()
    skipped = CampaignRecipient.query.filter_by(campaign_id=cid, state="skipped").count()
    pct = (sent / max(total, 1)) * 100.0
    return {
        "total": total,
        "queued": queued,
        "sending": sending,
        "sent": sent,
        "failed": failed,
        "suppressed": suppressed,
        "skipped": skipped,
        "pct": pct,
    }


def _update_metrics(c: Campaign, patch: dict):
    m = _safe_json_load(
        c.metrics_json or "{}",
        {"sent": 0, "hard_bounces": 0, "complaints": 0, "failed": 0, "updated_at": None},
    )
    for k, v in (patch or {}).items():
        m[k] = v
    m["updated_at"] = now_iso()
    c.metrics_json = json.dumps(m)


def _sender_loop(cid: int, stop_event: threading.Event):
    with app.app_context():
        c = Campaign.query.get(cid)
        if not c:
            return

        limits_cfg = _get_isp_limits(c)
        buckets = {k: TokenBucket(v.get("rate_per_min"), v.get("burst")) for k, v in limits_cfg.items()}

        pool_size = max(int(c.pool_size or 1), 1)
        executor = ThreadPoolExecutor(max_workers=pool_size)
        inflight = {}  # future -> (cr_id, to_email, isp)
        sent_this_run = 0

        try:
            while not stop_event.is_set():
                c = Campaign.query.get(cid)
                if not c:
                    break

                if c.status in ("draft", "paused"):
                    time.sleep(0.8)
                    continue
                if c.status == "stopped":
                    break
                if c.status != "running":
                    time.sleep(0.8)
                    continue

                # Kill-switch check (depends on bounces/complaints being populated elsewhere)
                m = _safe_json_load(c.metrics_json or "{}", {"sent": 0, "hard_bounces": 0, "complaints": 0})
                if should_kill(m):
                    c.status = "paused"
                    _update_metrics(c, {"last_error": "Kill-switch triggered (bounce/complaint thresholds)."})
                    db.session.commit()
                    time.sleep(1.0)
                    continue

                # Collect finished futures
                done = [f for f in list(inflight.keys()) if f.done()]
                for f in done:
                    cr_id, to_email, isp = inflight.pop(f)
                    ok, err = False, "Unknown"
                    try:
                        ok, err = f.result(timeout=0)
                    except Exception as e:
                        ok, err = False, str(e)

                    cr = CampaignRecipient.query.get(cr_id)
                    if cr:
                        cr.state = "sent" if ok else "failed"

                    mm = _safe_json_load(
                        c.metrics_json or "{}",
                        {"sent": 0, "hard_bounces": 0, "complaints": 0, "failed": 0},
                    )
                    if ok:
                        mm["sent"] = int(mm.get("sent", 0)) + 1
                        sent_this_run += 1
                    else:
                        mm["failed"] = int(mm.get("failed", 0)) + 1
                        mm["last_error"] = (err or "")[:500]
                    mm["updated_at"] = now_iso()
                    c.metrics_json = json.dumps(mm)
                    db.session.commit()

                env_params = _campaign_env_parameters(c)

                if not env_params["sending_enabled"]:
                    c.status = "paused"
                    _update_metrics(c, {"last_error": "Sending disabled from campaign config."})
                    db.session.commit()
                    time.sleep(0.8)
                    continue

                max_send_per_run = env_params["max_send_per_run"] or MAX_SEND_PER_RUN
                if max_send_per_run > 0 and sent_this_run >= max_send_per_run:
                    c.status = "paused"
                    _update_metrics(c, {"last_error": f"Paused after MAX_SEND_PER_RUN={max_send_per_run}."})
                    db.session.commit()
                    time.sleep(0.8)
                    continue

                global_cap = max(int(c.max_inflight or 1), 1)
                if len(inflight) >= min(global_cap, pool_size * 4):
                    time.sleep(0.15)
                    continue

                # Fetch next queued recipients
                q = (
                    db.session.query(CampaignRecipient.id, Recipient.email, Recipient.isp, Recipient.status)
                    .join(Recipient, Recipient.id == CampaignRecipient.recipient_id)
                    .filter(CampaignRecipient.campaign_id == cid)
                    .filter(CampaignRecipient.state == "queued")
                    .order_by(CampaignRecipient.id.asc())
                    .limit(50)
                    .all()
                )

                if not q:
                    if not inflight:
                        c.status = "stopped"
                        _update_metrics(c, {"finished_at": now_iso()})
                        db.session.commit()
                        break
                    time.sleep(0.2)
                    continue

                # Safety config (campaign/env aware)
                allowed_seed = _campaign_seed_set(c)
                seed_mode_enabled = bool(env_params["seed_mode_enabled"])

                scheduled_any = False
                for (cr_id, to_email, isp, r_status) in q:
                    if stop_event.is_set() or c.status != "running":
                        break

                    to_email = (to_email or "").strip().lower()
                    isp = (isp or "other").strip().lower()
                    if isp not in buckets:
                        isp = "other"

                    if seed_mode_enabled:
                        if not allowed_seed:
                            # No seed configured -> pause and explain
                            c.status = "paused"
                            _update_metrics(c, {"last_error": "Seed mode: add test emails in Seed list / environment variables to start."})
                            db.session.commit()
                            break
                        if to_email not in allowed_seed:
                            # Avoid stalling: mark as skipped
                            cr = CampaignRecipient.query.get(cr_id)
                            if cr and cr.state == "queued":
                                cr.state = "skipped"
                                db.session.commit()
                            continue

                    # Re-check suppression/status
                    if r_status != "active" or Suppression.query.filter_by(email=to_email).first():
                        cr = CampaignRecipient.query.get(cr_id)
                        if cr:
                            cr.state = "suppressed"
                            db.session.commit()
                        continue

                    # Per-ISP throttle
                    if not buckets[isp].take(1.0):
                        continue

                    # Per-ISP inflight cap
                    per_cap = int(limits_cfg.get(isp, {}).get("max_inflight", 20) or 20)
                    inflight_isp = sum(1 for (_, _, i) in inflight.values() if i == isp)
                    if inflight_isp >= max(per_cap, 1):
                        continue

                    # Mark sending and submit
                    cr = CampaignRecipient.query.get(cr_id)
                    if not cr or cr.state != "queued":
                        continue
                    cr.state = "sending"
                    db.session.commit()

                    def _task(to_addr: str, campaign_id: int = cid):
                        # Thread-safe: do not reuse the main thread DB session.
                        with app.app_context():
                            cc = Campaign.query.get(campaign_id)
                            if not cc:
                                return False, "Campaign not found"
                            msg = _build_email_message(cc, to_addr)
                            return _smtp_send_message(cc, msg)

                    fut = executor.submit(_task, to_email)
                    inflight[fut] = (cr_id, to_email, isp)
                    scheduled_any = True

                    if len(inflight) >= min(global_cap, pool_size * 4):
                        break

                if not scheduled_any:
                    time.sleep(0.25)

        finally:
            executor.shutdown(wait=False)
            with _SENDER_LOCK:
                cur = _SENDER.get(cid)
                if cur and cur.get("stop") is stop_event:
                    _SENDER.pop(cid, None)


def _ensure_sender(cid: int):
    with _SENDER_LOCK:
        cur = _SENDER.get(cid)
        if cur and cur.get("thread") and cur["thread"].is_alive():
            return
        stop = threading.Event()
        t = threading.Thread(target=_sender_loop, args=(cid, stop), daemon=True)
        _SENDER[cid] = {"thread": t, "stop": stop}
        t.start()


def _stop_sender(cid: int):
    with _SENDER_LOCK:
        cur = _SENDER.get(cid)
        if cur:
            cur["stop"].set()


# ----------------------------
# UI
# ----------------------------
BASE_HTML = r"""
<!doctype html>
<html lang="en" dir="ltr">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Mailer Builder</title>
  <style>
    :root{
      --bg:#0b1220;--panel:#111a2e;--panel2:#0e1730;--b:#243252;--b2:#2a3a63;
      --txt:#e7eefc;--mut:#b7c6e8;--ok:#62ffb1;--bad:#ff6b6b;--warn:#ffd166;
      --btn:#2b7cff;--btn2:#233055;--danger:#ff3b52;
      --shadow: 0 14px 40px rgba(0,0,0,.35);
      --r:14px;
    }
    *{box-sizing:border-box}
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto; background:var(--bg); color:var(--txt); margin:0}
    .wrap{max-width:1120px; margin:24px auto; padding:0 16px}
    .card{background:var(--panel); border:1px solid var(--b); border-radius:var(--r); padding:16px; margin-bottom:14px; box-shadow:var(--shadow)}
    .soft{background:rgba(255,255,255,.03)}
    .row{display:grid; grid-template-columns:1fr 1fr; gap:12px}
    @media (max-width:920px){.row{grid-template-columns:1fr}}
    label{display:block; font-size:13px; color:var(--mut); margin:10px 0 6px}
    input,select,textarea{width:100%; background:var(--panel2); color:var(--txt); border:1px solid var(--b2); border-radius:12px; padding:10px}
    textarea{min-height:120px; resize:vertical}

    .topbar{display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:14px}
    h2,h3,h4{margin:0}
    .muted{color:var(--mut); font-size:13px; line-height:1.45}
    .small{font-size:12px; color:var(--mut)}
    .actions{display:flex; gap:10px; flex-wrap:wrap; align-items:center}

    .btn{background:var(--btn); color:white; border:none; padding:10px 14px; border-radius:12px; cursor:pointer; font-weight:600}
    .btn2{background:var(--btn2); color:white; border:1px solid var(--b2); padding:10px 14px; border-radius:12px; cursor:pointer; font-weight:600}
    .btnDanger{background:var(--danger); color:white; border:none; padding:10px 14px; border-radius:12px; cursor:pointer; font-weight:700}
    .btn:disabled,.btn2:disabled,.btnDanger:disabled{opacity:.45; cursor:not-allowed}

    code{background:var(--panel2); border:1px solid var(--b2); padding:2px 6px; border-radius:10px}
    a{color:#9ec5ff; text-decoration:none}

    .pill{display:inline-flex; align-items:center; gap:8px; padding:6px 10px; border-radius:999px; border:1px solid var(--b2); background:var(--panel2); font-size:12px; color:var(--txt)}
    .dot::before{content:""; width:8px; height:8px; border-radius:50%; background:#8aa3d6; display:inline-block}
    .dot.green::before{background:var(--ok)}
    .dot.red::before{background:var(--bad)}
    .dot.yellow::before{background:var(--warn)}

    .bar{height:10px; border-radius:999px; border:1px solid var(--b2); background:rgba(255,255,255,.03); overflow:hidden}
    .bar > div{height:100%; width:0%; background:linear-gradient(90deg, rgba(98,255,177,.9), rgba(43,124,255,.9)); border-radius:999px}

    .divider{height:1px; background:rgba(255,255,255,.06); margin:14px 0}
    .sectionTitle{display:flex; align-items:flex-start; justify-content:space-between; gap:10px; margin-bottom:8px; flex-wrap:wrap}
    .hint{padding:10px 12px; border-radius:12px; background:rgba(255,255,255,.03); border:1px dashed rgba(255,255,255,.15); color:var(--mut); font-size:13px}

    /* Toast */
    .toast{position:fixed; right:18px; bottom:18px; background:#0e1730; border:1px solid var(--b2); color:var(--txt);
      padding:12px 14px; border-radius:14px; min-width:240px; box-shadow:var(--shadow); display:none; z-index:9999}
    .toast.show{display:block; animation:pop .18s ease-out}
    .toast .t{font-weight:700; margin-bottom:4px}
    .toast.success{border-color:rgba(98,255,177,.35)}
    .toast.error{border-color:rgba(255,107,107,.35)}
    .switchRow{display:flex; align-items:center; justify-content:space-between; gap:12px; margin-top:10px; flex-wrap:wrap}
    .switchWrap{display:inline-flex; align-items:center; gap:10px}
    .switch{position:relative; width:54px; height:30px; display:inline-block}
    .switch input{opacity:0; width:0; height:0}
    .slider{position:absolute; inset:0; background:var(--btn2); border:1px solid var(--b2); border-radius:999px; cursor:pointer; transition:.18s}
    .slider:before{content:""; position:absolute; width:24px; height:24px; left:2px; top:2px; border-radius:50%; background:#fff; transition:.18s}
    .switch input:checked + .slider{background:rgba(98,255,177,.2); border-color:rgba(98,255,177,.6)}
    .switch input:checked + .slider:before{transform:translateX(24px); background:var(--ok)}
    @keyframes pop{from{transform:translateY(10px); opacity:.4} to{transform:translateY(0); opacity:1}}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div>
        <h2>Mailer Builder (Flask)</h2>
        <div class="muted">Campaign hygiene • suppression • unsubscribe • variants • QA • kill-switch • sender + progress</div>
      </div>
      <div class="actions">
        <a class="btn2" href="/">Campaigns</a>
        <a class="btn" href="/campaign/new">+ New campaign</a>
      </div>
    </div>

    {{content}}
  </div>

  <div id="toast" class="toast"><div class="t" id="toast_t"></div><div class="small" id="toast_m"></div></div>

<script>
async function postJSON(url, data){
  const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data)});
  return await r.json();
}

function showToast(msg, kind='success', title=''){
  const t = document.getElementById('toast');
  const tt = document.getElementById('toast_t');
  const tm = document.getElementById('toast_m');
  t.className = 'toast ' + (kind||'');
  tt.textContent = title || (kind==='error' ? 'Error' : 'OK');
  tm.textContent = msg || '';
  t.classList.add('show');
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(()=>t.classList.remove('show'), 2600);
}

function confirmExport(){
  return confirm('Export this campaign data?');
}

function confirmDelete(){
  return confirm('Delete this campaign? This will remove its recipients states.');
}

async function deleteCampaign(campaignId){
  if(!confirmDelete()) return;
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = `/api/campaign/${campaignId}/delete`;
  document.body.appendChild(form);
  form.submit();
}

async function testSMTP(){
  const host = document.getElementById('smtp_host').value;
  const port = parseInt(document.getElementById('smtp_port').value || '0', 10);
  const mode = document.getElementById('smtp_mode').value;
  const user = document.getElementById('smtp_user').value;
  const pw   = document.getElementById('smtp_pass').value;
  const out = document.getElementById('smtp_result');
  out.textContent = 'Testing...';
  const res = await postJSON('/api/test_smtp', {host, port, mode, user, pw});
  if(res.ok){ out.innerHTML = '<span style="color:var(--ok)">✅ Connected</span>'; showToast('SMTP connection OK'); }
  else{ out.innerHTML = '<span style="color:var(--bad)">❌ Failed:</span> <span class="small">'+(res.error||'')+'</span>'; showToast(res.error||'SMTP failed', 'error'); }
}

async function preview(campaignId){
  const sample = (document.getElementById('preview_email').value||'').trim().toLowerCase();
  const res = await postJSON(`/api/campaign/${campaignId}/preview`, {email: sample});
  const out = document.getElementById('preview_out');
  if(!res.ok){ out.innerHTML = '<span style="color:var(--bad)">'+res.error+'</span>'; showToast(res.error||'Preview failed','error'); return; }

  const iframe = document.createElement('iframe');
  iframe.setAttribute('sandbox','');
  iframe.style.width = '100%';
  iframe.style.height = '240px';
  iframe.style.border = '1px solid var(--b2)';
  iframe.style.borderRadius = '12px';
  iframe.style.background = 'white';
  iframe.srcdoc = res.letter_html || '';

  out.innerHTML = `
    <div class="card soft">
      <div class="small">From</div><div><code>${res.from}</code></div>
      <div class="small" style="margin-top:8px">Subject</div><div><code>${res.subject}</code></div>
      <div class="small" style="margin-top:10px">Tokens</div>
      <div class="small"><code>{{message_id}}</code> = ${res.tokens.message_id} &nbsp; <code>{{tracking_code}}</code> = ${res.tokens.tracking_code} &nbsp; <code>{{id_num}}</code> = ${res.tokens.id_num} &nbsp; <code>{{id_mix}}</code> = ${res.tokens.id_mix}</div>
      <div class="small" style="margin-top:10px">Rendered</div>
      <div id="pv_iframe"></div>
    </div>`;
  document.getElementById('pv_iframe').appendChild(iframe);
  showToast('Preview generated');
}

function bindImportCounter(){
  const ta = document.getElementById('mail_list');
  const out = document.getElementById('import_count');
  if(!ta || !out) return;
  const count = (txt)=>{
    const s = (txt||'').trim();
    if(!s) return 0;
    const parts = s.split(/\n|,|;|\s+/g).map(x=>x.trim()).filter(Boolean);
    return new Set(parts).size;
  };
  const render = ()=> out.textContent = String(count(ta.value));
  ta.addEventListener('input', render);
  render();
}

async function sendAction(campaignId, action){
  const res = await postJSON(`/api/campaign/${campaignId}/send/${action}`, {});
  if(res.ok){ showToast(res.message || 'Done'); }
  else{ showToast(res.error || 'Action failed','error'); }
  await pollSendStatus(campaignId);
}

async function toggleSeedMode(campaignId, enabled){
  const res = await postJSON(`/api/campaign/${campaignId}/seed-mode`, {enabled});
  if(!res.ok){
    showToast(res.error || 'Could not update seed mode', 'error');
    await pollSendStatus(campaignId);
    return;
  }
  showToast(enabled ? 'SEED mode enabled' : 'SEED mode disabled');
  await pollSendStatus(campaignId);
}

async function pollSendStatus(campaignId){
  try{
    const r = await fetch(`/api/campaign/${campaignId}/send/status`);
    const s = await r.json();

    const elStatus = document.getElementById('send_status');
    const elHint = document.getElementById('send_hint');
    const elCounts = document.getElementById('send_counts');
    const elPct = document.getElementById('send_pct');
    const bar = document.getElementById('send_bar');
    const seedToggle = document.getElementById('seed_mode_toggle');
    const seedToggleLabel = document.getElementById('seed_mode_label');

    const btnStart = document.getElementById('btn_send_start');
    const btnPause = document.getElementById('btn_send_pause');
    const btnStop  = document.getElementById('btn_send_stop');

    if(elStatus) elStatus.textContent = s.status || 'draft';

    const hint = !s.sending_enabled
      ? 'Sending is disabled from campaign config.'
      : (s.seed_mode_enabled
        ? 'SEED Mode Active: messages are sent only to Seed list / config SEED_LIST.'
        : 'SEED Mode Disabled: messages are sent to the imported Mail list recipients.');

    if(elHint) elHint.textContent = hint;

    if(elCounts) elCounts.textContent = `Total ${s.total} • Queued ${s.queued} • Sending ${s.sending} • Sent ${s.sent} • Failed ${s.failed} • Suppressed ${s.suppressed} • Skipped ${s.skipped}`;
    if(elPct) elPct.textContent = `${(s.pct||0).toFixed(1)}%`;
    if(bar) bar.style.width = `${Math.max(0, Math.min(100, s.pct||0))}%`;

    if(btnStart) btnStart.disabled = (s.status === 'running') || (s.total === 0);
    if(btnPause) btnPause.disabled = (s.status !== 'running');
    if(btnStop)  btnStop.disabled  = (s.status === 'stopped' || s.status === 'draft');
    if(seedToggle){
      seedToggle.checked = !!s.seed_mode_enabled;
      seedToggle.disabled = !s.sending_enabled;
    }
    if(seedToggleLabel){
      seedToggleLabel.textContent = s.seed_mode_enabled ? 'SEED Mode: Enable' : 'SEED Mode: Disable';
    }

    return s;
  }catch(e){
    return null;
  }
}

function startSendPolling(campaignId){
  if(!campaignId) return;
  pollSendStatus(campaignId);
  clearInterval(window.__sendPoll);
  window.__sendPoll = setInterval(()=>pollSendStatus(campaignId), 2000);
}

window.addEventListener('DOMContentLoaded', bindImportCounter);
</script>
</body>
</html>
"""


# ----------------------------
# Pages
# ----------------------------
@app.get("/")
def campaigns():
    items = Campaign.query.order_by(Campaign.id.desc()).all()
    rows = []
    for c in items:
        counts = _campaign_counts(c.id)

        qa = c.qa_score
        qa_txt = f"{qa:.0f}/100" if qa is not None else "Not run"
        qa_w = max(0.0, min(100.0, float(qa))) if qa is not None else 0.0

        rows.append(
            f"""
            <div class="card">
              <div class="sectionTitle">
                <div>
                  <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap">
                    <b>#{c.id} — {escape(c.name)}</b>
                    <span class="pill dot {'green' if c.status=='running' else ('yellow' if c.status=='paused' else ('red' if c.status=='stopped' else ''))}">{escape(c.status)}</span>
                    <span class="pill">QA: <b>{qa_txt}</b></span>
                    <span class="pill">Sent: <b>{counts['sent']}</b>/<b>{counts['total']}</b></span>
                  </div>
                  <div class="small" style="margin-top:6px">SMTP: <code>{escape(c.smtp_host)}:{c.smtp_port}</code> ({escape(c.smtp_mode)}) • Created: {escape(c.created_at)}</div>
                  <div style="margin-top:10px">
                    <div class="small" style="display:flex;justify-content:space-between"><span>QA</span><span>{qa_txt}</span></div>
                    <div class="bar"><div style="width:{qa_w:.1f}%"></div></div>
                    <div class="small" style="display:flex;justify-content:space-between;margin-top:8px"><span>Send progress</span><span>{counts['pct']:.1f}%</span></div>
                    <div class="bar"><div style="width:{counts['pct']:.1f}%"></div></div>
                  </div>
                </div>
                <div class="actions">
                  <a class="btn2" href="/campaign/{c.id}">Open</a>
                  <a class="btn2" href="/campaign/{c.id}/edit">Edit</a>
                  <button class="btnDanger" type="button" onclick="deleteCampaign({c.id})">Delete</button>
                  <a class="btn2" href="/api/campaign/{c.id}/export" onclick="return confirmExport()">Export</a>
                </div>
              </div>
            </div>
            """
        )

    content = "\n".join(rows) if rows else '<div class="card muted">No campaigns yet. Click "New campaign".</div>'
    return render_template_string(BASE_HTML, content=Markup(content))


@app.get("/campaign/new")
def new_campaign():
    default_limits = {
        "gmail": {"rate_per_min": 120, "burst": 30, "max_inflight": 50},
        "microsoft": {"rate_per_min": 80, "burst": 20, "max_inflight": 40},
        "yahoo": {"rate_per_min": 60, "burst": 15, "max_inflight": 30},
        "other": {"rate_per_min": 100, "burst": 25, "max_inflight": 40},
    }

    default_env_parameters = json.dumps(DEFAULT_ENV_PARAMETERS, ensure_ascii=False, indent=2)
    default_env_variables = json.dumps(DEFAULT_ENV_VARIABLES, ensure_ascii=False, indent=2)

    content = f"""
    <form class="card" method="post" action="/api/campaign/create">
      <div class="sectionTitle">
        <div>
          <h3>Create campaign</h3>
          <div class="muted">Set SMTP relay + content variants. You can test SMTP before saving.</div>
        </div>
      </div>

      <div class="row">
        <div>
          <label>Campaign name</label>
          <input name="name" placeholder="Example: March Promo" required />
        </div>
        <div>
          <label>Base URL (for unsubscribe)</label>
          <input name="base_url" value="http://127.0.0.1:5000" required />
        </div>
      </div>

      <div class="card soft" style="margin-top:12px">
        <div class="sectionTitle">
          <div>
            <h4>Server connect (SMTP relay)</h4>
            <div class="muted">Typical: your PowerMTA submission host (e.g. port 2525). Supports: plain / STARTTLS / SSL.</div>
          </div>
          <div class="pill">Tip: use <code>Test</code> first</div>
        </div>

        <div class="row">
          <div>
            <label>SMTP host</label>
            <input id="smtp_host" name="smtp_host" placeholder="Example: 194.116.x.x or mail.yourdomain.com" required />
          </div>
          <div>
            <label>SMTP port</label>
            <input id="smtp_port" name="smtp_port" value="2525" required />
          </div>
        </div>

        <div class="row">
          <div>
            <label>Mode</label>
            <select id="smtp_mode" name="smtp_mode">
              <option value="plain">PLAIN (no TLS)</option>
              <option value="starttls" selected>STARTTLS</option>
              <option value="ssl">SSL (SMTPS)</option>
            </select>
          </div>
          <div>
            <label>Connection pool size</label>
            <input name="pool_size" value="10" />
          </div>
        </div>

        <div class="row">
          <div>
            <label>SMTP username (optional)</label>
            <input id="smtp_user" name="smtp_user" placeholder="user" />
          </div>
          <div>
            <label>SMTP password (optional)</label>
            <input id="smtp_pass" name="smtp_pass" placeholder="pass" />
          </div>
        </div>

        <div class="actions" style="margin-top:10px">
          <button type="button" class="btn2" onclick="testSMTP()">Test connection</button>
          <div id="smtp_result" class="small"></div>
        </div>
      </div>

      <div class="row">
        <div>
          <label>From profiles (one per line)</label>
          <textarea name="from_profiles" placeholder="Name <sender@domain.com>\nsender@domain.com | Name\nsender@domain.com"></textarea>
          <div class="small">From is chosen deterministically per recipient (balanced).</div>
        </div>
        <div>
          <label>Subjects (one per line)</label>
          <textarea name="subjects" placeholder="Subject A\nSubject B\nSubject C"></textarea>
          <div class="small">Subject selection is deterministic per recipient (A/B style).</div>
        </div>
      </div>

      <label>Letter (HTML/Text)</label>
      <textarea name="letter" placeholder="Hello {{email}}\nYour code: {{tracking_code}}\nUnsub: {{unsubscribe_url}}"></textarea>

      <div class="card soft" style="margin-top:12px">
        <div class="sectionTitle">
          <div>
            <h4>Seed list (test emails)</h4>
            <div class="muted">When bulk is OFF, sending works ONLY for these emails. Put your own test inboxes here.</div>
          </div>
          <span class="pill">Seed-only</span>
        </div>
        <label>Seed list</label>
        <textarea name="seed_list" placeholder="you@gmail.com\nyou@yahoo.com"></textarea>
      </div>

      <div class="card soft" style="margin-top:12px">
        <div class="sectionTitle">
          <div>
            <h4>Campaign config (Environment)</h4>
            <div class="muted">Edit runtime parameters and variables per campaign without changing server-level env.</div>
          </div>
          <span class="pill">Config</span>
        </div>
        <div class="row">
          <div>
            <label>Environment Parameters (JSON)</label>
            <textarea name="env_parameters_json">{default_env_parameters}</textarea>
            <div class="small">Keys: allow_bulk_send, max_send_per_run, seed_mode_enabled, sending_enabled.</div>
          </div>
          <div>
            <label>Environment Variables (JSON)</label>
            <textarea name="env_variables_json">{default_env_variables}</textarea>
            <div class="small">Supported now: SEED_LIST (comma separated).</div>
          </div>
        </div>
      </div>


      <label>ISP limits JSON</label>
      <textarea name="isp_limits_json">{json.dumps(default_limits, ensure_ascii=False, indent=2)}</textarea>

      <label>Max inflight</label>
      <input name="max_inflight" value="100" />

      <div class="actions" style="margin-top:12px">
        <button class="btn" type="submit">Create</button>
        <a class="btn2" href="/">Cancel</a>
      </div>
    </form>
    """

    return render_template_string(BASE_HTML, content=Markup(content))


@app.get("/campaign/<int:cid>/edit")
def campaign_edit(cid):
    c = Campaign.query.get_or_404(cid)

    default_limits = _safe_json_load(c.isp_limits_json or "{}", {})
    env_params = _campaign_env_parameters(c)
    env_vars = _safe_json_load(c.env_variables_json or "{}", DEFAULT_ENV_VARIABLES)

    content = f"""
    <form class="card" method="post" action="/api/campaign/{c.id}/update">
      <div class="sectionTitle">
        <div>
          <h3>Edit campaign #{c.id}</h3>
          <div class="muted">Update SMTP + content. Save changes then go back to Open.</div>
        </div>
        <div class="actions">
          <a class="btn2" href="/campaign/{c.id}">Open</a>
          <button class="btnDanger" type="button" onclick="deleteCampaign({c.id})">Delete</button>
        </div>
      </div>

      <div class="row">
        <div>
          <label>Campaign name</label>
          <input name="name" value="{escape(c.name)}" required />
        </div>
        <div>
          <label>Base URL (for unsubscribe)</label>
          <input name="base_url" value="{escape(c.base_url)}" required />
        </div>
      </div>

      <div class="card soft" style="margin-top:12px">
        <div class="sectionTitle">
          <div>
            <h4>Server connect (SMTP relay)</h4>
            <div class="muted">Typical: your PowerMTA submission host (e.g. port 2525). Supports: plain / STARTTLS / SSL.</div>
          </div>
          <div class="pill">Tip: use <code>Test</code> first</div>
        </div>

        <div class="row">
          <div>
            <label>SMTP host</label>
            <input id="smtp_host" name="smtp_host" value="{escape(c.smtp_host)}" required />
          </div>
          <div>
            <label>SMTP port</label>
            <input id="smtp_port" name="smtp_port" value="{c.smtp_port}" required />
          </div>
        </div>

        <div class="row">
          <div>
            <label>Mode</label>
            <select id="smtp_mode" name="smtp_mode">
              <option value="plain" {'selected' if c.smtp_mode=='plain' else ''}>PLAIN (no TLS)</option>
              <option value="starttls" {'selected' if c.smtp_mode=='starttls' else ''}>STARTTLS</option>
              <option value="ssl" {'selected' if c.smtp_mode=='ssl' else ''}>SSL (SMTPS)</option>
            </select>
          </div>
          <div>
            <label>Connection pool size</label>
            <input name="pool_size" value="{c.pool_size}" />
          </div>
        </div>

        <div class="row">
          <div>
            <label>SMTP username (optional)</label>
            <input id="smtp_user" name="smtp_user" value="{escape(c.smtp_user or '')}" />
          </div>
          <div>
            <label>SMTP password (optional)</label>
            <input id="smtp_pass" name="smtp_pass" value="{escape(c.smtp_pass or '')}" />
          </div>
        </div>

        <div class="actions" style="margin-top:10px">
          <button type="button" class="btn2" onclick="testSMTP()">Test connection</button>
          <div id="smtp_result" class="small"></div>
        </div>
      </div>

      <div class="row">
        <div>
          <label>From profiles (one per line)</label>
          <textarea name="from_profiles">{escape(c.from_profiles or '')}</textarea>
          <div class="small">From is chosen deterministically per recipient (balanced).</div>
        </div>
        <div>
          <label>Subjects (one per line)</label>
          <textarea name="subjects">{escape(c.subjects or '')}</textarea>
          <div class="small">Subject selection is deterministic per recipient (A/B style).</div>
        </div>
      </div>

      <label>Letter (HTML/Text)</label>
      <textarea name="letter">{escape(c.letter or '')}</textarea>

      <div class="card soft" style="margin-top:12px">
        <div class="sectionTitle">
          <div>
            <h4>Seed list (test emails)</h4>
            <div class="muted">When bulk is OFF, sending works ONLY for these emails (and env SEED_LIST). Add your test inboxes.</div>
          </div>
          <span class="pill">Seed-only</span>
        </div>
        <label>Seed list</label>
        <textarea name="seed_list">{escape(c.seed_list or '')}</textarea>
      </div>

      <div class="card soft" style="margin-top:12px">
        <div class="sectionTitle">
          <div>
            <h4>Campaign config (Environment)</h4>
            <div class="muted">Control seed mode, bulk mode, and sending behavior from campaign config.</div>
          </div>
          <span class="pill">Config</span>
        </div>
        <div class="row">
          <div>
            <label>Environment Parameters (JSON)</label>
            <textarea name="env_parameters_json">{escape(json.dumps(env_params, ensure_ascii=False, indent=2))}</textarea>
          </div>
          <div>
            <label>Environment Variables (JSON)</label>
            <textarea name="env_variables_json">{escape(json.dumps(env_vars, ensure_ascii=False, indent=2))}</textarea>
          </div>
        </div>
      </div>

      <label>ISP limits JSON</label>
      <textarea name="isp_limits_json">{escape(json.dumps(default_limits, ensure_ascii=False, indent=2))}</textarea>

      <label>Max inflight</label>
      <input name="max_inflight" value="{c.max_inflight}" />

      <div class="actions" style="margin-top:12px">
        <button class="btn" type="submit">Save changes</button>
        <a class="btn2" href="/campaign/{c.id}">Back</a>
      </div>
    </form>
    """

    return render_template_string(BASE_HTML, content=Markup(content))


@app.get("/campaign/<int:cid>")
def campaign_view(cid):
    c = Campaign.query.get_or_404(cid)

    m = _safe_json_load(c.metrics_json or "{}", {})
    qa = c.qa_score
    qa_txt = f"{qa:.0f}/100" if qa is not None else "Not run"
    qa_w = max(0.0, min(100.0, float(qa))) if qa is not None else 0.0

    counts = _campaign_counts(cid)
    pct = counts["pct"]

    health_bad = should_kill(m)

    seed_set = _campaign_seed_set(c)
    seed_hint = f"Seed configured: {len(seed_set)}" if seed_set else "Seed is empty (add in Edit)"

    content = f"""
    <div class="card">
      <div class="sectionTitle">
        <div>
          <h3>#{c.id} — {escape(c.name)}</h3>
          <div class="small" style="margin-top:6px">SMTP: <code>{escape(c.smtp_host)}:{c.smtp_port}</code> ({escape(c.smtp_mode)})</div>
          <div class="actions" style="margin-top:10px">
            <span class="pill dot {'red' if health_bad else 'green'}">{'Kill-switch risk' if health_bad else 'Healthy'}</span>
            <span class="pill">Status: <b>{escape(c.status)}</b></span>
            <span class="pill">QA: <b>{qa_txt}</b></span>
            <span class="pill">{seed_hint}</span>
          </div>
        </div>
        <div class="actions">
          <a class="btn2" href="/campaign/{c.id}/edit">Edit</a>
          <button class="btnDanger" type="button" onclick="deleteCampaign({c.id})">Delete</button>
          <a class="btn2" href="/api/campaign/{c.id}/export" onclick="return confirmExport()">Export</a>
        </div>
      </div>

      <div style="margin-top:12px">
        <div class="small" style="display:flex;justify-content:space-between"><span>QA score</span><span><b>{qa_txt}</b></span></div>
        <div class="bar"><div style="width:{qa_w:.1f}%"></div></div>
      </div>

      <div style="margin-top:12px">
        <div class="small" style="display:flex;justify-content:space-between"><span>Send progress</span><span><b id="send_pct">{pct:.1f}%</b></span></div>
        <div class="bar"><div id="send_bar" style="width:{pct:.1f}%"></div></div>
        <div class="small" style="margin-top:8px" id="send_counts">Total {counts['total']} • Queued {counts['queued']} • Sending {counts['sending']} • Sent {counts['sent']} • Failed {counts['failed']} • Suppressed {counts['suppressed']} • Skipped {counts['skipped']}</div>
        <div class="small" style="margin-top:6px" id="send_hint"></div>
      </div>

      <div class="divider"></div>

      <div class="card soft">
        <div class="sectionTitle">
          <div>
            <h4>Sending</h4>
            <div class="muted">Progress is based on recipient states. Default mode is seed-only unless bulk is enabled.</div>
          </div>
          <span class="pill">Live: <b id="send_status">{escape(c.status)}</b></span>
        </div>

        <div class="actions">
          <button id="btn_send_start" class="btn" type="button" onclick="sendAction({c.id}, 'start')">Start</button>
          <button id="btn_send_pause" class="btn2" type="button" onclick="sendAction({c.id}, 'pause')">Pause</button>
          <button id="btn_send_stop" class="btnDanger" type="button" onclick="sendAction({c.id}, 'stop')">Stop</button>
        </div>

        <div class="switchRow">
          <div class="small">Switch SEED mode from frontend.</div>
          <div class="switchWrap">
            <span class="pill" id="seed_mode_label">SEED Mode: --</span>
            <label class="switch">
              <input id="seed_mode_toggle" type="checkbox" onchange="toggleSeedMode({c.id}, this.checked)">
              <span class="slider"></span>
            </label>
          </div>
        </div>

        <div class="hint" style="margin-top:10px">
          <b>SEED Mode Enable:</b> sends only to <code>Seed list</code> / <code>SEED_LIST</code>.
          <b>SEED Mode Disable:</b> sends to imported <code>Mail list</code> recipients.
        </div>
      </div>

      <div class="divider"></div>

      <div class="row">
        <div class="card soft">
          <h4>Import mailing list</h4>
          <div class="muted">Paste emails (one per line or CSV). Dedupe + suppression applied.</div>
          <form method="post" action="/api/campaign/{c.id}/import">
            <label>Mail list</label>
            <textarea id="mail_list" name="mail_list" placeholder="a@gmail.com\nb@yahoo.com"></textarea>
            <div class="actions" style="margin-top:10px">
              <button class="btn" type="submit">Import</button>
              <span class="pill">Detected: <b id="import_count">0</b></span>
            </div>
          </form>
        </div>

        <div class="card soft">
          <h4>Content QA</h4>
          <div class="muted">Hook for a real compliance/quality scanner. Currently placeholder.</div>
          <form method="post" action="/api/campaign/{c.id}/qa" class="actions" style="margin-top:10px">
            <button class="btn2" type="submit">Run QA</button>
            <span class="pill">QA: <b>{qa_txt}</b></span>
          </form>

          <div class="divider"></div>

          <h4>Preview</h4>
          <div class="muted">Render From/Subject/Letter + tokens for a sample recipient.</div>
          <label>Sample email</label>
          <input id="preview_email" placeholder="someone@gmail.com" />
          <div class="actions" style="margin-top:10px">
            <button class="btn2" type="button" onclick="preview({c.id})">Generate preview</button>
          </div>
          <div id="preview_out" style="margin-top:10px"></div>
        </div>
      </div>
    </div>

    <script>
      startSendPolling({c.id});
    </script>
    """

    return render_template_string(BASE_HTML, content=Markup(content))


# ----------------------------
# API
# ----------------------------
@app.post("/api/test_smtp")
def api_test_smtp():
    data = request.json or {}
    ok, msg = smtp_test(
        host=str(data.get("host", "")).strip(),
        port=int(data.get("port", 0) or 0),
        mode=str(data.get("mode", "starttls")).strip(),
        user=str(data.get("user", "")).strip(),
        pw=str(data.get("pw", "")).strip(),
    )
    return jsonify({"ok": ok, "error": None if ok else msg})


@app.post("/api/campaign/create")
def api_campaign_create():
    form = request.form
    name = (form.get("name") or "").strip()
    base_url = (form.get("base_url") or "").strip()
    smtp_host = (form.get("smtp_host") or "").strip()
    smtp_port = int(form.get("smtp_port") or 2525)
    smtp_mode = (form.get("smtp_mode") or "starttls").strip().lower()
    smtp_user = (form.get("smtp_user") or "").strip()
    smtp_pass = (form.get("smtp_pass") or "").strip()
    from_profiles = form.get("from_profiles") or ""
    subjects = form.get("subjects") or ""
    letter = form.get("letter") or ""
    seed_list = form.get("seed_list") or ""
    isp_limits_json = form.get("isp_limits_json") or "{}"
    env_parameters_json = form.get("env_parameters_json") or "{}"
    env_variables_json = form.get("env_variables_json") or "{}"
    pool_size = int(form.get("pool_size") or 10)
    max_inflight = int(form.get("max_inflight") or 100)

    if not name or not smtp_host or smtp_port <= 0:
        return "Invalid input", 400
    if smtp_mode not in ("plain", "starttls", "ssl"):
        smtp_mode = "starttls"
    try:
        json.loads(isp_limits_json)
    except Exception:
        isp_limits_json = "{}"
    try:
        json.loads(env_parameters_json)
    except Exception:
        env_parameters_json = json.dumps(DEFAULT_ENV_PARAMETERS)
    try:
        json.loads(env_variables_json)
    except Exception:
        env_variables_json = json.dumps(DEFAULT_ENV_VARIABLES)

    c = Campaign(
        name=name,
        base_url=base_url,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_mode=smtp_mode,
        smtp_user=smtp_user or None,
        smtp_pass=smtp_pass or None,
        from_profiles=from_profiles,
        subjects=subjects,
        letter=letter,
        seed_list=seed_list,
        isp_limits_json=isp_limits_json,
        env_parameters_json=env_parameters_json,
        env_variables_json=env_variables_json,
        pool_size=pool_size,
        max_inflight=max_inflight,
        status="draft",
    )
    db.session.add(c)
    db.session.commit()
    return redirect(f"/campaign/{c.id}")


@app.post("/api/campaign/<int:cid>/update")
def api_campaign_update(cid):
    c = Campaign.query.get_or_404(cid)
    form = request.form

    name = (form.get("name") or "").strip()
    base_url = (form.get("base_url") or "").strip()
    smtp_host = (form.get("smtp_host") or "").strip()
    smtp_port = int(form.get("smtp_port") or 2525)
    smtp_mode = (form.get("smtp_mode") or "starttls").strip().lower()
    smtp_user = (form.get("smtp_user") or "").strip()
    smtp_pass = (form.get("smtp_pass") or "").strip()
    from_profiles = form.get("from_profiles") or ""
    subjects = form.get("subjects") or ""
    letter = form.get("letter") or ""
    seed_list = form.get("seed_list") or ""
    isp_limits_json = form.get("isp_limits_json") or "{}"
    env_parameters_json = form.get("env_parameters_json") or "{}"
    env_variables_json = form.get("env_variables_json") or "{}"
    pool_size = int(form.get("pool_size") or 10)
    max_inflight = int(form.get("max_inflight") or 100)

    if not name or not smtp_host or smtp_port <= 0:
        return "Invalid input", 400
    if smtp_mode not in ("plain", "starttls", "ssl"):
        smtp_mode = "starttls"
    try:
        json.loads(isp_limits_json)
    except Exception:
        isp_limits_json = c.isp_limits_json or "{}"
    try:
        json.loads(env_parameters_json)
    except Exception:
        env_parameters_json = c.env_parameters_json or json.dumps(DEFAULT_ENV_PARAMETERS)
    try:
        json.loads(env_variables_json)
    except Exception:
        env_variables_json = c.env_variables_json or json.dumps(DEFAULT_ENV_VARIABLES)

    c.name = name
    c.base_url = base_url
    c.smtp_host = smtp_host
    c.smtp_port = smtp_port
    c.smtp_mode = smtp_mode
    c.smtp_user = smtp_user or None
    c.smtp_pass = smtp_pass or None
    c.from_profiles = from_profiles
    c.subjects = subjects
    c.letter = letter
    c.seed_list = seed_list
    c.isp_limits_json = isp_limits_json
    c.env_parameters_json = env_parameters_json
    c.env_variables_json = env_variables_json
    c.pool_size = pool_size
    c.max_inflight = max_inflight

    db.session.commit()
    return redirect(f"/campaign/{cid}")


@app.post("/api/campaign/<int:cid>/delete")
def api_campaign_delete(cid):
    c = Campaign.query.get_or_404(cid)

    # Stop sender thread if running
    _stop_sender(cid)

    # Delete campaign recipients states
    CampaignRecipient.query.filter_by(campaign_id=cid).delete(synchronize_session=False)

    # Delete campaign itself
    db.session.delete(c)
    db.session.commit()
    return redirect("/")


@app.post("/api/campaign/<int:cid>/import")
def api_campaign_import(cid):
    Campaign.query.get_or_404(cid)
    mail_list = request.form.get("mail_list") or ""
    emails = sanitize_email_list(mail_list)

    for e in emails:
        if Suppression.query.filter_by(email=e).first():
            continue

        r = Recipient.query.filter_by(email=e).first()
        if not r:
            r = Recipient(email=e, isp=classify_isp(e), status="active")
            db.session.add(r)
            db.session.flush()

        if r.status != "active":
            continue

        exists = CampaignRecipient.query.filter_by(campaign_id=cid, recipient_id=r.id).first()
        if not exists:
            db.session.add(CampaignRecipient(campaign_id=cid, recipient_id=r.id, state="queued"))

    db.session.commit()
    return redirect(f"/campaign/{cid}")


@app.post("/api/campaign/<int:cid>/qa")
def api_campaign_qa(cid):
    c = Campaign.query.get_or_404(cid)
    subjects = parse_lines(c.subjects)
    subject = subjects[0] if subjects else ""
    c.qa_score = float(content_qa_score(subject, c.letter))
    db.session.commit()
    return redirect(f"/campaign/{cid}")


@app.post("/api/campaign/<int:cid>/preview")
def api_campaign_preview(cid):
    c = Campaign.query.get_or_404(cid)
    data = request.json or {}
    email = (data.get("email") or "").strip().lower()
    if not EMAIL_RE.match(email):
        return jsonify({"ok": False, "error": "Enter a valid email for preview."})

    subjects = parse_lines(c.subjects)
    from_profiles = parse_from_profiles(c.from_profiles)

    subj = pick_variant(subjects, c.id, email)
    name, from_email = pick_from_profile(from_profiles, c.id, email)
    from_fmt = f"{name} <{from_email}>" if name else (from_email or "")

    unsub = f"{c.base_url.rstrip('/')}/u/{make_unsub_token(email)}"
    ctx = {
        "email": email,
        "message_id": message_id_for(c.id, email),
        "tracking_code": tracking_code_for(c.id, email),
        "id_num": id_num_for(c.id, email),
        "id_mix": id_mix_for(c.id, email),
        "unsubscribe_url": unsub,
    }
    subj_r = render_placeholders(subj, ctx)
    letter_r = render_placeholders(c.letter, ctx)
    letter_html = (letter_r or "").replace("\n", "<br/>")

    return jsonify(
        {
            "ok": True,
            "from": from_fmt,
            "subject": subj_r,
            "tokens": {k: ctx[k] for k in ["message_id", "tracking_code", "id_num", "id_mix"]},
            "letter_html": letter_html,
        }
    )


@app.post("/api/campaign/<int:cid>/send/start")
def api_send_start(cid):
    c = Campaign.query.get_or_404(cid)

    env_params = _campaign_env_parameters(c)
    seed_mode_enabled = bool(env_params["seed_mode_enabled"])

    if not env_params["sending_enabled"]:
        return jsonify({"ok": False, "error": "Sending is disabled in campaign Environment Parameters."})

    if seed_mode_enabled:
        allowed = _campaign_seed_set(c)
        if not allowed:
            return jsonify({"ok": False, "error": "Seed mode: add test emails in Edit → Seed list or Environment Variables.SEED_LIST."})

    c.status = "running"
    _update_metrics(c, {"started_at": now_iso()})
    db.session.commit()

    _ensure_sender(cid)
    return jsonify({"ok": True, "message": "Sender started."})


@app.post("/api/campaign/<int:cid>/send/pause")
def api_send_pause(cid):
    c = Campaign.query.get_or_404(cid)
    c.status = "paused"
    _update_metrics(c, {"paused_at": now_iso()})
    db.session.commit()
    return jsonify({"ok": True, "message": "Paused."})


@app.post("/api/campaign/<int:cid>/send/stop")
def api_send_stop(cid):
    c = Campaign.query.get_or_404(cid)
    c.status = "stopped"
    _update_metrics(c, {"stopped_at": now_iso()})
    db.session.commit()
    _stop_sender(cid)
    return jsonify({"ok": True, "message": "Stopped."})


@app.get("/api/campaign/<int:cid>/send/status")
def api_send_status(cid):
    c = Campaign.query.get_or_404(cid)
    counts = _campaign_counts(cid)
    env_params = _campaign_env_parameters(c)
    counts.update({
        "ok": True,
        "status": c.status,
        "bulk_enabled": bool(ALLOW_BULK_SEND or env_params["allow_bulk_send"]),
        "seed_mode_enabled": bool(env_params["seed_mode_enabled"]),
        "sending_enabled": bool(env_params["sending_enabled"]),
        "seed_count": len(_campaign_seed_set(c)),
    })
    return jsonify(counts)


@app.post("/api/campaign/<int:cid>/seed-mode")
def api_seed_mode(cid):
    c = Campaign.query.get_or_404(cid)
    data = request.json or {}
    enabled = bool(data.get("enabled", False))
    env_params = _campaign_env_parameters(c)
    env_params["seed_mode_enabled"] = enabled
    c.env_parameters_json = json.dumps(env_params)
    db.session.commit()
    return jsonify({"ok": True, "seed_mode_enabled": enabled})


@app.get("/api/campaign/<int:cid>/export")
def api_campaign_export(cid):
    c = Campaign.query.get_or_404(cid)
    recs = (
        db.session.query(Recipient.email, Recipient.isp, CampaignRecipient.state)
        .join(CampaignRecipient, CampaignRecipient.recipient_id == Recipient.id)
        .filter(CampaignRecipient.campaign_id == cid)
        .all()
    )
    payload = {
        "campaign": {
            "id": c.id,
            "name": c.name,
            "status": c.status,
            "base_url": c.base_url,
            "smtp": {
                "host": c.smtp_host,
                "port": c.smtp_port,
                "mode": c.smtp_mode,
                "user": c.smtp_user,
            },
            "pool_size": c.pool_size,
            "max_inflight": c.max_inflight,
            "isp_limits": _safe_json_load(c.isp_limits_json or "{}", {}),
            "from_profiles": parse_lines(c.from_profiles),
            "subjects": parse_lines(c.subjects),
            "seed_list": sanitize_email_list(c.seed_list or ""),
            "env_parameters": _campaign_env_parameters(c),
            "env_variables": _safe_json_load(c.env_variables_json or "{}", DEFAULT_ENV_VARIABLES),
            "placeholders": ["email", "message_id", "tracking_code", "id_num", "id_mix", "unsubscribe_url"],
            "qa_score": c.qa_score,
            "created_at": c.created_at,
            "metrics": _safe_json_load(c.metrics_json or "{}", {}),
        },
        "recipients": [{"email": e, "isp": isp, "state": st} for (e, isp, st) in recs],
    }
    return jsonify(payload)


# ----------------------------
# Run
# ----------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        ensure_schema()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5001")), debug=True)
