#!/usr/bin/env python3
import os
import fnmatch
import json
import csv
import re
import base64
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any, Optional

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# ----------------------------
# Config (ENV)
# ----------------------------
PMTA_LOG_DIR = Path(os.getenv("PMTA_LOG_DIR", "/var/log/pmta")).resolve()
# Static bridge token (kept in code by request to avoid env export dependency).
API_TOKEN = "mxft0zDIEHkdoTHF94jhxtKe1hdXSjVW5hHskfmuFXEdwzHtt9foI7ZZCz303Jyx"
ALLOW_NO_AUTH = os.getenv("ALLOW_NO_AUTH", "0") == "1"
DEBUG_ALLOW_QUERY_TOKEN = os.getenv("DEBUG_ALLOW_QUERY_TOKEN", "0") == "1"
DEFAULT_PUSH_MAX_LINES = int(os.getenv("DEFAULT_PUSH_MAX_LINES", "5000"))
DEFAULT_PULL_LIMIT = int(os.getenv("DEFAULT_PULL_LIMIT", "500"))
MAX_PULL_LIMIT = int(os.getenv("MAX_PULL_LIMIT", "2000"))
RECENT_PULL_MAX_FILES = int(os.getenv("RECENT_PULL_MAX_FILES", "32"))
RECENT_PULL_MAX_AGE_HOURS = int(os.getenv("RECENT_PULL_MAX_AGE_HOURS", "48"))

# CORS (for browser access)
# Examples:
#   CORS_ORIGINS="https://yourdomain.com,https://admin.yourdomain.com"
#   CORS_ORIGINS="*"
CORS_ORIGINS_RAW = os.getenv("CORS_ORIGINS", "*").strip()
CORS_ORIGINS = (
    ["*"] if CORS_ORIGINS_RAW == "*" else [o.strip() for o in CORS_ORIGINS_RAW.split(",") if o.strip()]
)

# ----------------------------
# App
# ----------------------------
app = FastAPI(title="PMTA Accounting/Logs API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

ALLOWED_KINDS = {
    "acct": ["acct-*.csv"],
    "diag": ["diag-*.csv"],
    "log": ["log", "log.*", "pmtahttp.log", "pmtahttp.log.*"],
    "pmtahttp": ["pmtahttp.log", "pmtahttp.log.*"],
    "all": ["acct-*.csv", "diag-*.csv", "log", "log.*", "pmtahttp.log", "pmtahttp.log.*"],
}

_TAIL_STATE_LOCK = threading.Lock()
_TAIL_STATE: Dict[str, int] = {}
_CSV_HEADER_STATE_LOCK = threading.Lock()
_CSV_HEADER_STATE: Dict[str, List[str]] = {}
_BRIDGE_STATUS_LOCK = threading.Lock()
_BRIDGE_STATUS: Dict[str, Any] = {
    "last_processed_file": "",
    "last_cursor": "",
    "parsed": 0,
    "skipped": 0,
    "unknown_outcome": 0,
    "last_error": "",
}


def _status_update(**kwargs: Any) -> None:
    with _BRIDGE_STATUS_LOCK:
        _BRIDGE_STATUS.update(kwargs)


def _error_payload(error: str, detail: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "ok": False,
        "error": str(error or "request_failed"),
        "detail": detail or {},
    }


@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail or "HTTP error")}
    error = str(detail.get("error") or "http_error")
    return JSONResponse(status_code=exc.status_code, content=_error_payload(error=error, detail=detail))


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(_: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=400,
        content=_error_payload(
            error="invalid_parameters",
            detail={"message": "Invalid request parameters", "issues": exc.errors()},
        ),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(_: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content=_error_payload(error="internal_error", detail={"message": str(exc)}),
    )

ACCOUNTING_HEADER_CANDIDATES = [
    "x-job-id",
    "x-campaign-id",
    "job-id",
    "campaign-id",
    "job_id",
    "campaign_id",
    "msgid",
    "message-id",
    "message_id",
]

_PMTA_MESSAGE_ID_RE = re.compile(
    r"^<[^.<>@\s]+[.]([^.<>@\s]+)[.]([^.<>@\s]+)[.]c\d+[.]w\d+@[^>]+>$",
    re.IGNORECASE,
)

_JOBID_RE_1 = re.compile(r"[.][a-f0-9]{8,64}[.]([a-f0-9]{12})[.]([a-f0-9]{8,64}|none)[.]c[0-9]+[.]w[0-9]+@local", re.IGNORECASE)
_JOBID_RE_2 = re.compile(r"[.][a-f0-9]{8,64}[.]([a-f0-9]{12})[.]c[0-9]+[.]w[0-9]+@local", re.IGNORECASE)


def _extract_job_id_from_text(text: str) -> str:
    t = str(text or "").strip().lower()
    if not t:
        return ""
    m = _JOBID_RE_1.search(t)
    if m:
        return str(m.group(1) or "").strip().lower()
    m = _JOBID_RE_2.search(t)
    if m:
        return str(m.group(1) or "").strip().lower()
    return ""


def _parse_ids_from_message_id(value: Any) -> Tuple[str, str]:
    msgid = str(value or "").strip()
    if not msgid:
        return "", ""
    m = _PMTA_MESSAGE_ID_RE.match(msgid)
    if not m:
        return "", ""
    return str(m.group(1) or "").strip().lower(), str(m.group(2) or "").strip().lower()


def _normalize_job_id(value: Any) -> str:
    """Normalize job id to the canonical 12-hex format used by Shiva/PMTA message IDs."""
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if re.fullmatch(r"[a-f0-9]{12}", raw):
        return raw

    from_text = _extract_job_id_from_text(raw)
    if from_text:
        return from_text

    m = re.search(r"\b([a-f0-9]{12})\b", raw)
    if m:
        return str(m.group(1) or "").strip().lower()
    return raw


def _normalize_outcome_type(v: Any) -> str:
    s = str(v or "").strip().lower()
    if not s:
        return ""
    if s in {"d", "delivered", "delivery", "success", "accepted", "ok", "sent"}:
        return "delivered"
    if s in {"b", "bounce", "bounced", "hardbounce", "softbounce", "failed", "failure", "reject", "rejected", "error"}:
        return "bounced"
    if s in {"t", "defer", "deferred", "deferral", "transient"}:
        return "deferred"
    if s in {"c", "complaint", "complained", "fbl"}:
        return "complained"
    if any(x in s for x in ("success", "2.0.0", "relayed", "delivered", "accepted", "250 ")):
        return "delivered"
    if any(x in s for x in ("bounce", "bounced", "failed", "failure", "reject", "5.", " 550", " 551", " 552", " 553", " 554")):
        return "bounced"
    if any(x in s for x in ("defer", "deferred", "transient", "4.", " 421", " 450", " 451", " 452")):
        return "deferred"
    if any(x in s for x in ("complaint", "fbl", "abuse")):
        return "complained"
    return ""


def _event_value(ev: Dict[str, Any], *names: str) -> str:
    aliases = {str(n or "").strip().lower().replace("_", "-") for n in names if str(n or "").strip()}
    if not aliases:
        return ""
    for k, v in (ev or {}).items():
        kk = str(k or "").strip().lower().replace("_", "-")
        vv = str(v or "").strip()
        if kk in aliases and vv:
            return vv
    for k, v in (ev or {}).items():
        kk = str(k or "").strip().lower().replace("_", "-")
        vv = str(v or "").strip()
        if vv and any(a in kk for a in aliases):
            return vv
    return ""


def _event_job_id(ev: Dict[str, Any]) -> str:
    jid = _event_value(ev, "header_x-job-id", "x-job-id")
    jid = _normalize_job_id(jid)
    if jid:
        return jid
    msgid = _event_value(ev, "header_message-id", "message-id", "message_id", "msgid", "messageid")
    jid, _ = _parse_ids_from_message_id(msgid)
    jid = _normalize_job_id(jid)
    if jid:
        return jid

    # PMTA columns can exist but are often empty in acct files; keep as last fallback only.
    jid = _normalize_job_id(_event_value(ev, "job-id", "job_id", "jobid", "envid", "env-id"))
    if jid:
        return jid
    return ""


def _event_campaign_id(ev: Dict[str, Any]) -> str:
    campaign_id = _event_value(ev, "header_x-campaign-id", "x-campaign-id")
    campaign_id = str(campaign_id or "").strip().lower()
    if campaign_id:
        return campaign_id
    msgid = _event_value(ev, "header_message-id", "message-id", "message_id", "msgid", "messageid")
    _, campaign_id = _parse_ids_from_message_id(msgid)
    return campaign_id


def _event_explicit_job_id(ev: Dict[str, Any]) -> str:
    """Return only explicit job-id fields from accounting rows (no message-id inference)."""
    jid = _event_value(ev, "header_x-job-id", "x-job-id", "job-id", "job_id", "jobid")
    return _normalize_job_id(jid)


def _walk_accounting_events(patterns: List[str]):
    files = _find_matching_files(patterns)
    for fp in files:
        with fp.open("r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                s = (line or "").strip()
                if not s:
                    continue
                ev = _parse_accounting_line(s, source_file=fp.name, line_no_or_offset=line_no)
                if ev:
                    yield ev


def require_token(request: Request):
    """
    Supported auth methods:
      - Header: Authorization: Bearer <token>
      - Header: x-api-token: <token>

    Query param token auth is disabled by default and only allowed when
    DEBUG_ALLOW_QUERY_TOKEN=1 is explicitly set.
    """
    if ALLOW_NO_AUTH:
        return

    if not API_TOKEN:
        raise HTTPException(
            status_code=500,
            detail={"error": "server_misconfig", "message": "API_TOKEN is not set"},
        )

    auth = request.headers.get("authorization", "")
    token = ""
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
    else:
        token = request.headers.get("x-api-token", "").strip()

    if not token and DEBUG_ALLOW_QUERY_TOKEN:
        token = request.query_params.get("token", "").strip() or request.query_params.get("api_token", "").strip()

    if token != API_TOKEN:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "unauthorized",
                "message": "Missing or invalid API token",
                "auth_methods": ["Authorization: Bearer <token>", "x-api-token: <token>"],
                "allow_no_auth": ALLOW_NO_AUTH,
                "debug_query_token_enabled": DEBUG_ALLOW_QUERY_TOKEN,
            },
        )


def _file_matches(name: str, patterns: List[str]) -> bool:
    return any(fnmatch.fnmatch(name, pat) for pat in patterns)


def list_dir_files(patterns: List[str]) -> List[Dict[str, Any]]:
    if not PMTA_LOG_DIR.is_dir():
        raise HTTPException(status_code=500, detail=f"Directory not found: {PMTA_LOG_DIR}")

    items = []
    for p in PMTA_LOG_DIR.iterdir():
        try:
            if p.is_symlink():
                continue
            if not p.is_file():
                continue

            name = p.name
            if not _file_matches(name, patterns):
                continue

            st = p.stat()
            mtime = st.st_mtime

            items.append(
                {
                    "name": name,
                    "size_bytes": int(st.st_size),
                    "mtime_epoch": int(mtime),
                    "mtime_utc": datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat(),
                    "mtime_local": datetime.fromtimestamp(mtime).astimezone().isoformat(),
                }
            )
        except FileNotFoundError:
            # file rotated/deleted between iterdir and stat
            continue

    return items


def _find_matching_files(patterns: List[str]) -> List[Path]:
    candidates: List[Tuple[float, Path]] = []
    for p in PMTA_LOG_DIR.iterdir():
        if not p.is_file() or p.is_symlink():
            continue
        if not _file_matches(p.name, patterns):
            continue
        try:
            candidates.append((p.stat().st_mtime, p))
        except FileNotFoundError:
            continue

    if not candidates:
        raise HTTPException(status_code=404, detail="No accounting/log files matched")

    candidates.sort(key=lambda x: x[0], reverse=True)
    return [p for _, p in candidates]


def _find_latest_file(patterns: List[str]) -> Path:
    candidates: List[Tuple[float, Path]] = []
    for p in PMTA_LOG_DIR.iterdir():
        if not p.is_file() or p.is_symlink():
            continue
        if not _file_matches(p.name, patterns):
            continue
        try:
            candidates.append((p.stat().st_mtime, p))
        except FileNotFoundError:
            continue

    if not candidates:
        raise HTTPException(status_code=404, detail="No accounting/log files matched")

    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def _read_new_lines(path: Path, max_lines: int) -> Dict[str, Any]:
    """Read newly appended lines from latest file with per-file byte offset state."""
    safe_max = max(1, int(max_lines or 1))

    key = str(path.resolve())
    with _TAIL_STATE_LOCK:
        start_off = int(_TAIL_STATE.get(key, 0) or 0)

    size = path.stat().st_size
    if start_off > size:
        start_off = 0

    lines: List[str] = []
    next_off = start_off
    has_more = False

    with path.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(start_off)
        while len(lines) < safe_max:
            line = f.readline()
            if not line:
                break
            next_off = f.tell()
            s = line.strip()
            if not s:
                continue
            lines.append(s)

        if f.readline():
            has_more = True

    with _TAIL_STATE_LOCK:
        _TAIL_STATE[key] = next_off

    return {
        "file": path.name,
        "from_offset": start_off,
        "to_offset": next_off,
        "count": len(lines),
        "has_more": has_more,
        "lines": lines,
    }


def _parse_accounting_line(
    line: str,
    *,
    source_file: str = "",
    line_no_or_offset: Any = "",
) -> Optional[Dict[str, Any]]:
    """Parse accounting line into dict (best-effort).

    Supports JSON lines and CSV files with/without header rows.
    """
    s = (line or "").strip()
    if not s:
        return None

    if s.startswith("{") and s.endswith("}"):
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                obj.setdefault("source_file", source_file)
                obj.setdefault("line_no_or_offset", line_no_or_offset)
                return obj
        except Exception:
            return None

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

    if fields and any(x.lower() in {"type", "event", "rcpt", "recipient", "msgid", "message-id", "message_id"} for x in fields):
        with _CSV_HEADER_STATE_LOCK:
            _CSV_HEADER_STATE[source_file or ""] = [x.strip().lower() for x in fields]
        return None

    ev: Dict[str, Any] = {"raw": s, "source_file": source_file, "line_no_or_offset": line_no_or_offset}
    with _CSV_HEADER_STATE_LOCK:
        hdr = _CSV_HEADER_STATE.get(source_file or "") or []

    if hdr and len(hdr) == len(fields):
        for k, v in zip(hdr, fields):
            if k:
                ev[k] = v
        return ev

    if fields:
        ev["type"] = fields[0]
    if len(fields) >= 9:
        ev["mailfrom"] = fields[3]
        ev["rcpt"] = fields[4]
        ev["status"] = fields[6]
        ev["dsnStatus"] = fields[7]
        ev["dsnDiag"] = fields[8]
    return ev


def _normalized_outcome(ev: Dict[str, Any]) -> str:
    typ = str(_event_value(ev, "type") or "").strip().lower()
    dsn_action = str(_event_value(ev, "dsnAction", "dsn_action") or "").strip().lower()
    dsn_status = str(_event_value(ev, "dsnStatus", "dsn_status") or "").strip().lower()
    dsn_diag = str(_event_value(ev, "dsnDiag", "dsn_diag") or "").strip().lower()

    if any(x in dsn_diag for x in ("complaint", "fbl", "feedback loop", "abuse")):
        return "complained"
    if typ == "d" or dsn_action == "relayed" or dsn_status.startswith("2"):
        return "delivered"
    if typ == "t" or dsn_action == "delayed" or dsn_status.startswith("4"):
        return "deferred"
    if typ == "b" or dsn_action == "failed" or dsn_status.startswith("5"):
        return "bounced"
    return "unknown"


def _structured_event(ev: Dict[str, Any]) -> Dict[str, Any]:
    message_id = _event_value(ev, "header_message-id", "message-id", "message_id", "msgid", "messageid")
    return {
        "type": str(_event_value(ev, "type") or "").strip().lower(),
        "outcome": _normalized_outcome(ev),
        "time_logged": _event_value(ev, "timeLogged", "timelogged", "time_logged", "time"),
        "orig": _event_value(ev, "orig", "mailfrom", "from"),
        "rcpt": _event_value(ev, "rcpt", "recipient", "email", "to", "rcpt_to"),
        "job_id": _event_job_id(ev),
        "campaign_id": _event_campaign_id(ev),
        "message_id": message_id,
        "dsn_action": _event_value(ev, "dsnAction", "dsn_action"),
        "dsn_status": _event_value(ev, "dsnStatus", "dsn_status"),
        "dsn_diag": _event_value(ev, "dsnDiag", "dsn_diag"),
        "vmta": _event_value(ev, "vmta"),
        "dlv_source_ip": _event_value(ev, "dlvSourceIp", "dlv_source_ip"),
        "dlv_dest_ip": _event_value(ev, "dlvDestinationIp", "dlv_dest_ip", "dlvDestinationIP"),
        "bounce_cat": _event_value(ev, "bounceCat", "bounce_cat"),
        "source_file": str(ev.get("source_file") or ""),
        "line_no_or_offset": ev.get("line_no_or_offset", ""),
    }


def _event_header_value(ev: Dict[str, Any]) -> Tuple[str, str]:
    normalized = {}
    for k, v in (ev or {}).items():
        kk = str(k or "").strip().lower()
        vv = str(v or "").strip()
        if kk and vv:
            normalized[kk] = vv
            normalized[kk.replace("_", "-")] = vv

    for key in ACCOUNTING_HEADER_CANDIDATES:
        v = normalized.get(key)
        if v:
            return key.replace("_", "-"), v

    return "unknown", ""


def _group_accounting_events(lines: List[str], *, source_file: str) -> Dict[str, Any]:
    events: List[Dict[str, Any]] = []
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for line in lines:
        ev = _parse_accounting_line(line, source_file=source_file)
        if not ev:
            continue
        events.append(ev)

        header_key, header_value = _event_header_value(ev)
        grp_key = (header_key, header_value)
        if grp_key not in groups:
            groups[grp_key] = {
                "header_key": header_key,
                "header_value": header_value,
                "count": 0,
                "emails": [],
                "events": [],
            }

        recipient = str(
            ev.get("rcpt")
            or ev.get("recipient")
            or ev.get("email")
            or ev.get("to")
            or ""
        ).strip()
        if recipient and recipient not in groups[grp_key]["emails"]:
            groups[grp_key]["emails"].append(recipient)

        groups[grp_key]["events"].append(ev)
        groups[grp_key]["count"] = int(groups[grp_key]["count"] or 0) + 1

    batches = sorted(
        groups.values(),
        key=lambda g: (g.get("header_key") != "unknown", int(g.get("count") or 0)),
        reverse=True,
    )

    return {
        "events": events,
        "batches": batches,
    }


def _merge_batches(batches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for batch in batches:
        key = (str(batch.get("header_key") or "unknown"), str(batch.get("header_value") or ""))
        if key not in merged:
            merged[key] = {
                "header_key": key[0],
                "header_value": key[1],
                "count": 0,
                "emails": [],
                "events": [],
            }
        dst = merged[key]
        dst["count"] = int(dst.get("count") or 0) + int(batch.get("count") or 0)
        for email in batch.get("emails") or []:
            if email and email not in dst["emails"]:
                dst["emails"].append(email)
        dst["events"].extend(batch.get("events") or [])

    return sorted(
        merged.values(),
        key=lambda g: (g.get("header_key") != "unknown", int(g.get("count") or 0)),
        reverse=True,
    )


def _normalize_match_value(v: Any) -> str:
    s = str(v or "").strip().lower()
    if not s:
        return ""
    if s.startswith("<") and s.endswith(">"):
        s = s[1:-1].strip()
    return s


def _event_matches_filter(ev: Dict[str, Any], filters: Dict[str, str]) -> bool:
    if not filters:
        return True

    normalized = {}
    for k, v in (ev or {}).items():
        kk = str(k or "").strip().lower().replace("_", "-")
        vv = _normalize_match_value(v)
        if kk and vv:
            normalized[kk] = vv

    job_id = _normalize_match_value(filters.get("job_id"))
    campaign_id = _normalize_match_value(filters.get("campaign_id"))
    message_id = _normalize_match_value(filters.get("message_id"))

    def _values_for(*needles: str) -> List[str]:
        vals: List[str] = []
        seen: set = set()
        for k, v in normalized.items():
            kk = str(k or "")
            vv = _normalize_match_value(v)
            if not vv:
                continue
            if kk in needles or any(n in kk for n in needles):
                if vv not in seen:
                    seen.add(vv)
                    vals.append(vv)
        return vals

    if job_id:
        vals = _values_for("x-job-id", "job-id", "jobid")
        normalized_vals = {_normalize_job_id(v) for v in vals if v}
        derived_jid = _event_job_id(ev)
        if derived_jid:
            normalized_vals.add(derived_jid)
        if job_id not in normalized_vals:
            return False

    if campaign_id:
        vals = _values_for("x-campaign-id", "campaign-id", "cid")
        if campaign_id not in vals:
            return False

    if message_id:
        vals = _values_for("message-id", "msgid", "messageid", "header-message-id")
        if message_id not in vals:
            return False

    return True




def _build_batches_from_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_key: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for ev in events or []:
        header_key, header_value = _event_header_value(ev)
        key = (header_key, header_value)
        if key not in by_key:
            by_key[key] = {
                "header_key": header_key,
                "header_value": header_value,
                "count": 0,
                "emails": [],
                "events": [],
            }
        dst = by_key[key]
        dst["count"] = int(dst.get("count") or 0) + 1
        recipient = str(ev.get("rcpt") or ev.get("recipient") or ev.get("email") or ev.get("to") or "").strip()
        if recipient and recipient not in dst["emails"]:
            dst["emails"].append(recipient)
        dst["events"].append(ev)

    return _merge_batches(list(by_key.values()))

def _request_filters(request: Request) -> Dict[str, str]:
    q = request.query_params
    return {
        "job_id": (
            request.headers.get("x-job-id", "").strip()
            or q.get("job_id", "").strip()
            or q.get("x_job_id", "").strip()
        ),
        "campaign_id": (
            request.headers.get("x-campaign-id", "").strip()
            or q.get("campaign_id", "").strip()
            or q.get("x_campaign_id", "").strip()
        ),
        "message_id": (
            request.headers.get("message-id", "").strip()
            or request.headers.get("x-message-id", "").strip()
            or q.get("message_id", "").strip()
            or q.get("msgid", "").strip()
        ),
    }


def _encode_cursor(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _decode_cursor(cursor: str) -> Dict[str, Any]:
    try:
        data = base64.urlsafe_b64decode(str(cursor or "").encode("ascii"))
        decoded = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail={"error": "invalid_cursor", "message": str(exc)})

    if not isinstance(decoded, dict):
        raise HTTPException(status_code=400, detail={"error": "invalid_cursor", "message": "Cursor must decode to object"})
    return decoded


def _recent_matching_files(patterns: List[str]) -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc).timestamp()
    min_mtime = now - max(1, RECENT_PULL_MAX_AGE_HOURS) * 3600
    files: List[Dict[str, Any]] = []
    for p in PMTA_LOG_DIR.iterdir():
        if not p.is_file() or p.is_symlink() or not _file_matches(p.name, patterns):
            continue
        try:
            st = p.stat()
        except FileNotFoundError:
            continue
        if st.st_mtime < min_mtime:
            continue
        files.append(
            {
                "path": str(p.resolve()),
                "name": p.name,
                "inode": int(st.st_ino),
                "size": int(st.st_size),
                "mtime": float(st.st_mtime),
            }
        )

    if not files:
        raise HTTPException(status_code=404, detail="No accounting/log files matched")

    files.sort(key=lambda x: (x["mtime"], x["name"]))
    return files[-max(1, RECENT_PULL_MAX_FILES):]


def _read_from_cursor(files: List[Dict[str, Any]], cursor_payload: Optional[Dict[str, Any]], limit: int) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    parsed = 0
    skipped = 0
    unknown_outcome = 0

    start_idx = 0
    start_off = 0
    if cursor_payload:
        cursor_path = str(cursor_payload.get("path") or "")
        cursor_inode = int(cursor_payload.get("inode") or 0)
        cursor_offset = max(0, int(cursor_payload.get("offset") or 0))
        cursor_mtime = float(cursor_payload.get("mtime") or 0)

        match_idx = None
        for idx, f in enumerate(files):
            if int(f["inode"]) == cursor_inode and str(f["path"]) == cursor_path:
                match_idx = idx
                break

        if match_idx is not None:
            current = files[match_idx]
            start_idx = match_idx
            start_off = cursor_offset if int(current["size"]) >= cursor_offset else 0
        else:
            start_idx = len(files)
            for idx, f in enumerate(files):
                if (float(f["mtime"]), str(f["name"])) > (cursor_mtime, Path(cursor_path).name):
                    start_idx = idx
                    break
            start_off = 0

    if start_idx >= len(files):
        tail = files[-1]
        return {
            "items": [],
            "next_cursor": _encode_cursor(
                {
                    "v": 1,
                    "path": tail["path"],
                    "inode": int(tail["inode"]),
                    "offset": int(tail["size"]),
                    "mtime": float(tail["mtime"]),
                }
            ),
            "has_more": False,
            "stats": {"parsed": 0, "skipped": 0, "unknown_outcome": 0},
        }

    idx = start_idx
    current_off = start_off
    consumed_up_to_idx = idx

    while 0 <= idx < len(files) and len(items) < limit:
        f = files[idx]
        fp = Path(f["path"])
        if not fp.exists():
            idx += 1
            current_off = 0
            continue

        with fp.open("r", encoding="utf-8", errors="replace") as fh:
            # Cursor pulls can resume mid-file (after the CSV header row was already consumed
            # in a previous request). Prime header state from line 1 so subsequent rows keep
            # structured keys (header_x-job-id, header_message-id, ...).
            source_name = str(f.get("name") or fp.name)
            if current_off and source_name.lower().endswith(".csv"):
                with _CSV_HEADER_STATE_LOCK:
                    have_header = bool(_CSV_HEADER_STATE.get(source_name))
                if not have_header:
                    first_line = fh.readline()
                    if first_line:
                        _parse_accounting_line(first_line.strip(), source_file=source_name, line_no_or_offset=1)
                    fh.seek(current_off)
            if current_off:
                fh.seek(current_off)
            while len(items) < limit:
                line = fh.readline()
                if not line:
                    break
                current_off = fh.tell()
                s = str(line or "").strip()
                if not s:
                    skipped += 1
                    continue
                ev = _parse_accounting_line(s, source_file=f["name"], line_no_or_offset=current_off)
                if not ev:
                    skipped += 1
                    continue
                structured = _structured_event(ev)
                if structured.get("outcome") == "unknown":
                    unknown_outcome += 1
                items.append(structured)
                parsed += 1

        consumed_up_to_idx = idx
        if len(items) >= limit:
            break
        idx += 1
        if idx >= len(files):
            current_off = int(f["size"])
        else:
            current_off = 0

    if not files:
        raise HTTPException(status_code=404, detail="No accounting/log files matched")

    if consumed_up_to_idx >= len(files):
        consumed_up_to_idx = len(files) - 1
        current_off = int(files[-1]["size"])

    cursor_file = files[consumed_up_to_idx]
    next_cursor = _encode_cursor(
        {
            "v": 1,
            "path": cursor_file["path"],
            "inode": int(cursor_file["inode"]),
            "offset": int(current_off),
            "mtime": float(cursor_file["mtime"]),
        }
    )

    has_more = False
    if consumed_up_to_idx < len(files):
        if int(files[consumed_up_to_idx]["size"]) > int(current_off):
            has_more = True
        elif consumed_up_to_idx + 1 < len(files):
            has_more = True

    return {
        "items": items,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "stats": {
            "parsed": parsed,
            "skipped": skipped,
            "unknown_outcome": unknown_outcome,
        },
    }


@app.get("/health")
def health():
    return {
        "ok": True,
        "dir": str(PMTA_LOG_DIR),
        "server_time_utc": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/")
def root():
    return {
        "ok": True,
        "service": "PMTA Accounting/Logs API",
        "version": "1.1.0",
        "endpoints": {
            "health": "/health",
            "files": "/api/v1/files?kind=acct",
            "pull": "/api/v1/pull?kind=acct",
            "pull_latest": "/api/v1/pull/latest?kind=acct",
            "job_outcomes": "/api/v1/job/outcomes?job_id=<job_id>",
            "job_count": "/api/v1/job/count?job_id=<job_id>",
        },
    }


@app.get("/api/v1/status")
def bridge_status(_: None = Depends(require_token)):
    with _BRIDGE_STATUS_LOCK:
        state = dict(_BRIDGE_STATUS)
    state["server_time"] = datetime.now(timezone.utc).isoformat()
    return {"ok": True, **state}




@app.get("/api/v1/job/outcomes")
def get_job_outcomes(
    job_id: str = "",
    _: None = Depends(require_token),
):
    """Scrape all accounting CSV files and return recipients grouped by outcome for one job id."""
    jid = _normalize_job_id(job_id)
    if not jid:
        raise HTTPException(status_code=400, detail="Missing required query param: job_id")

    summary = _calculate_job_outcomes(jid)
    return {
        "ok": True,
        "job_id": jid,
        "count": summary["total_unique"],
        "linked_emails_count": summary["total_unique"],
        "emails": summary["all_emails"],
        "delivered": {
            "count": len(summary["buckets"]["delivered"]),
            "emails": summary["buckets"]["delivered"],
        },
        "deferred": {
            "count": len(summary["buckets"]["deferred"]),
            "emails": summary["buckets"]["deferred"],
        },
        "bounced": {
            "count": len(summary["buckets"]["bounced"]),
            "emails": summary["buckets"]["bounced"],
        },
        "complained": {
            "count": len(summary["buckets"]["complained"]),
            "emails": summary["buckets"]["complained"],
        },
    }


def _calculate_job_outcomes(jid: str) -> Dict[str, Any]:
    """Return unique recipient outcomes for one job id."""

    patterns = ALLOWED_KINDS.get("acct") or ["acct-*.csv"]
    by_recipient: Dict[str, str] = {}
    status_rank = {"deferred": 1, "delivered": 2, "bounced": 2, "complained": 2}

    for ev in _walk_accounting_events(patterns):
        ev_jid = _event_job_id(ev)
        if ev_jid != jid:
            continue

        rcpt = str(
            ev.get("rcpt")
            or ev.get("recipient")
            or ev.get("email")
            or ev.get("to")
            or ev.get("rcpt_to")
            or ""
        ).strip().lower()
        if not rcpt:
            continue

        typ = _normalized_outcome(ev)
        if typ not in {"delivered", "bounced", "deferred", "complained"}:
            print(
                f"[pmta-accounting-bridge] unknown outcome job_id={ev_jid} rcpt={rcpt} "
                f"type={ev.get('type')} dsnAction={ev.get('dsnAction') or ev.get('dsn_action')} "
                f"dsnStatus={ev.get('dsnStatus') or ev.get('dsn_status')} "
                f"source_file={ev.get('source_file')} line={ev.get('line_no_or_offset')}"
            )
            continue

        prev = by_recipient.get(rcpt)
        if not prev:
            by_recipient[rcpt] = typ
            continue
        if status_rank.get(typ, 0) >= status_rank.get(prev, 0):
            by_recipient[rcpt] = typ

    buckets: Dict[str, List[str]] = {
        "delivered": [],
        "deferred": [],
        "bounced": [],
        "complained": [],
    }
    for email, typ in by_recipient.items():
        buckets[typ].append(email)

    for k in buckets:
        buckets[k] = sorted(set(buckets[k]))

    total_unique = sum(len(v) for v in buckets.values())
    return {
        "total_unique": total_unique,
        "all_emails": sorted(by_recipient.keys()),
        "buckets": buckets,
    }


@app.get("/api/v1/job/count")
def get_job_count(
    job_id: str = "",
    _: None = Depends(require_token),
):
    """Return bridge-side unique recipient counts for one job id."""
    jid = _normalize_job_id(job_id)
    if not jid:
        raise HTTPException(status_code=400, detail="Missing required query param: job_id")

    summary = _calculate_job_outcomes(jid)
    buckets = summary["buckets"]
    return {
        "ok": True,
        "job_id": jid,
        "linked_emails_count": summary["total_unique"],
        "delivered_count": len(buckets["delivered"]),
        "deferred_count": len(buckets["deferred"]),
        "bounced_count": len(buckets["bounced"]),
        "complained_count": len(buckets["complained"]),
    }

@app.get("/api/v1/files")
def get_files(
    kind: str = "acct",
    sort: str = "mtime",     # mtime | name | size
    order: str = "desc",     # asc | desc
    limit: int = 200,
    offset: int = 0,
    _: None = Depends(require_token),
):
    patterns = ALLOWED_KINDS.get(kind)
    if not patterns:
        raise HTTPException(status_code=400, detail=f"Invalid kind. Use one of: {list(ALLOWED_KINDS.keys())}")

    items = list_dir_files(patterns)

    key_map = {"mtime": "mtime_epoch", "name": "name", "size": "size_bytes"}
    sort_key = key_map.get(sort, "mtime_epoch")
    reverse = (order.lower() != "asc")
    items.sort(key=lambda x: x[sort_key], reverse=reverse)

    total = len(items)
    items = items[max(offset, 0): max(offset, 0) + max(limit, 1)]

    return {
        "ok": True,
        "dir": str(PMTA_LOG_DIR),
        "kind": kind,
        "total": total,
        "count": len(items),
        "items": items,
    }


def _pull_accounting(
    request: Request,
    kind: str = "acct",
    max_lines: int = DEFAULT_PUSH_MAX_LINES,
    group_by_header: int = 1,
):
    """Pull accounting rows.

    - If X-Job-ID is provided, return only rows that belong to that job id.
    - If missing, return latest general accounting rows (acct-*.csv only by default).
    """
    jid = _normalize_job_id(request.headers.get("x-job-id", ""))
    safe_max = max(1, int(max_lines or 1))

    patterns = ALLOWED_KINDS.get(kind) or ALLOWED_KINDS.get("acct") or ["acct-*.csv"]
    # Default behavior is accounting-only, never diag/log unless explicitly requested.
    if not kind:
        patterns = ALLOWED_KINDS.get("acct") or ["acct-*.csv"]

    if not jid:
        latest_fp = _find_latest_file(patterns)
        events: List[Dict[str, Any]] = []
        with latest_fp.open("r", encoding="utf-8", errors="replace") as f:
            for line_no, raw_line in enumerate(f, start=1):
                line = str(raw_line or "").strip()
                if line:
                    ev = _parse_accounting_line(line, source_file=latest_fp.name, line_no_or_offset=line_no)
                    if ev:
                        events.append(_structured_event(ev))

        return {
            "ok": True,
            "job_id": "",
            "count": min(len(events), safe_max),
            "events": events[-safe_max:],
            "source_file": latest_fp.name,
        }

    files = _find_matching_files(patterns)
    events: List[Dict[str, Any]] = []

    for fp in files:
        with fp.open("r", encoding="utf-8", errors="replace") as f:
            for line_no, raw_line in enumerate(f, start=1):
                line = str(raw_line or "").strip()
                if not line:
                    continue
                ev = _parse_accounting_line(line, source_file=fp.name, line_no_or_offset=line_no)
                if not ev:
                    continue
                if _event_job_id(ev) == jid:
                    events.append(_structured_event(ev))
                if len(events) >= safe_max:
                    break
        if len(events) >= safe_max:
            break

    return {
        "ok": True,
        "job_id": jid,
        "count": len(events),
        "events": events,
    }


@app.get("/api/v1/pull")
def pull_accounting(
    request: Request,
    kinds: str = "acct",
    cursor: str = "",
    limit: int = DEFAULT_PULL_LIMIT,
    kind: str = "",
    max_lines: int = DEFAULT_PUSH_MAX_LINES,
    group_by_header: int = 1,
    _: None = Depends(require_token),
): 
    del request, max_lines, group_by_header
    try:
        requested_kinds = [x.strip() for x in (kinds or "").split(",") if x.strip()]
        if not requested_kinds:
            requested_kinds = [kind.strip() or "acct"]

        patterns: List[str] = []
        for k in requested_kinds:
            p = ALLOWED_KINDS.get(k)
            if not p:
                raise HTTPException(status_code=400, detail=f"Invalid kind: {k}. Use one of: {list(ALLOWED_KINDS.keys())}")
            patterns.extend(p)

        safe_limit = max(1, min(MAX_PULL_LIMIT, int(limit or DEFAULT_PULL_LIMIT)))
        files = _recent_matching_files(patterns)
        payload = _decode_cursor(cursor) if cursor else None
        result = _read_from_cursor(files, payload, safe_limit)

        last_processed_file = ""
        items = result.get("items") or []
        if items:
            last_processed_file = str(items[-1].get("source_file") or "")
        elif result.get("next_cursor"):
            c = _decode_cursor(result.get("next_cursor") or "")
            last_processed_file = Path(str(c.get("path") or "")).name

        stats = result.get("stats") or {}
        _status_update(
            last_processed_file=last_processed_file,
            last_cursor=str(result.get("next_cursor") or ""),
            parsed=int(stats.get("parsed") or 0),
            skipped=int(stats.get("skipped") or 0),
            unknown_outcome=int(stats.get("unknown_outcome") or 0),
            last_error="",
        )

        return {
            "ok": True,
            "kinds": requested_kinds,
            "count": len(result["items"]),
            **result,
        }
    except HTTPException as exc:
        _status_update(last_error=str(exc.detail))
        raise
    except Exception as exc:
        _status_update(last_error=str(exc))
        raise


@app.get("/api/v1/pull/latest")
def pull_latest_accounting(
    request: Request,
    kind: str = "acct",
    max_lines: int = DEFAULT_PUSH_MAX_LINES,
    group_by_header: int = 1,
    _: None = Depends(require_token),
):
    """Backward-compatible alias for /api/v1/pull."""
    return _pull_accounting(request, kind=kind, max_lines=max_lines, group_by_header=group_by_header)


if __name__ == "__main__":
    # Run: python3 pmta_accounting_bridge.py
    import uvicorn

    host = os.getenv("BIND_ADDR", "0.0.0.0")
    port = int(os.getenv("PORT", "8090"))
    uvicorn.run("pmta_accounting_bridge:app", host=host, port=port, reload=False)
