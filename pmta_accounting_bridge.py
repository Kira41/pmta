#!/usr/bin/env python3
import os
import fnmatch
import json
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import URLError, HTTPError

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

# ----------------------------
# Config (ENV)
# ----------------------------
PMTA_LOG_DIR = Path(os.getenv("PMTA_LOG_DIR", "/var/log/pmta")).resolve()
API_TOKEN = os.getenv("API_TOKEN", "")  # required unless ALLOW_NO_AUTH=1
ALLOW_NO_AUTH = os.getenv("ALLOW_NO_AUTH", "0") == "1"
SHIVA_ACCOUNTING_URL = os.getenv("SHIVA_ACCOUNTING_URL", "").strip()
SHIVA_WEBHOOK_TOKEN = os.getenv("SHIVA_WEBHOOK_TOKEN", "").strip()
DEFAULT_PUSH_MAX_LINES = int(os.getenv("DEFAULT_PUSH_MAX_LINES", "5000"))

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


def require_token(request: Request):
    """
    Bearer token auth:
      - Header: Authorization: Bearer <token>
      - Or query param: ?token=<token>  (less secure; avoid if possible)
    """
    if ALLOW_NO_AUTH:
        return

    if not API_TOKEN:
        raise HTTPException(status_code=500, detail="Server misconfig: API_TOKEN is not set")

    auth = request.headers.get("authorization", "")
    token = ""
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
    else:
        token = request.query_params.get("token", "").strip()

    if token != API_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")


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


def _read_tail_lines(path: Path, max_lines: int) -> List[str]:
    lines: List[str] = []
    safe_max = max(1, max_lines)
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            lines.append(s)
            if len(lines) > safe_max:
                lines.pop(0)
    return lines


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


def _push_ndjson(lines: List[str]) -> Dict[str, Any]:
    if not SHIVA_ACCOUNTING_URL:
        raise HTTPException(status_code=500, detail="Server misconfig: SHIVA_ACCOUNTING_URL is not set")
    if not SHIVA_WEBHOOK_TOKEN:
        raise HTTPException(status_code=500, detail="Server misconfig: SHIVA_WEBHOOK_TOKEN is not set")

    payload = "\n".join(lines).encode("utf-8")
    req = UrlRequest(
        SHIVA_ACCOUNTING_URL,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/x-ndjson",
            "X-Webhook-Token": SHIVA_WEBHOOK_TOKEN,
        },
    )

    try:
        with urlopen(req, timeout=20) as resp:
            body = (resp.read() or b"{}").decode("utf-8", errors="replace")
            try:
                out = json.loads(body)
            except json.JSONDecodeError:
                out = {"raw": body}
            return {
                "status": int(getattr(resp, "status", 200)),
                "response": out,
            }
    except HTTPError as e:
        text = (e.read() or b"").decode("utf-8", errors="replace")
        raise HTTPException(
            status_code=502,
            detail={"error": "upstream_http_error", "status": e.code, "body": text[:1000]},
        )
    except URLError as e:
        raise HTTPException(status_code=502, detail={"error": "upstream_connection_error", "reason": str(e)})


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
            "pull_latest": "/api/v1/pull/latest?kind=acct",
            "push_latest": "/api/v1/push/latest?kind=acct",
            "job_push_latest": "/api/v1/jobs/push-latest?kind=acct",
        },
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


@app.post("/api/v1/push/latest")
def push_latest_accounting(
    kind: str = "acct",
    max_lines: int = DEFAULT_PUSH_MAX_LINES,
    _: None = Depends(require_token),
):
    patterns = ALLOWED_KINDS.get(kind)
    if not patterns:
        raise HTTPException(status_code=400, detail=f"Invalid kind. Use one of: {list(ALLOWED_KINDS.keys())}")

    latest = _find_latest_file(patterns)
    lines = _read_tail_lines(latest, max_lines)
    if not lines:
        return {"ok": True, "pushed": 0, "file": latest.name, "note": "file had no non-empty lines"}

    upstream = _push_ndjson(lines)
    return {
        "ok": True,
        "kind": kind,
        "file": latest.name,
        "pushed": len(lines),
        "upstream": upstream,
    }


@app.post("/api/v1/jobs/push-latest")
def job_push_latest_accounting(
    kind: str = "acct",
    max_lines: int = DEFAULT_PUSH_MAX_LINES,
    _: None = Depends(require_token),
):
    result = push_latest_accounting(kind=kind, max_lines=max_lines, _=None)
    return {
        "ok": True,
        "job": "push-latest",
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "result": result,
    }


@app.get("/api/v1/pull/latest")
def pull_latest_accounting(
    kind: str = "acct",
    max_lines: int = DEFAULT_PUSH_MAX_LINES,
    _: None = Depends(require_token),
):
    """Return newly appended accounting lines so Shiva can pull them periodically."""
    patterns = ALLOWED_KINDS.get(kind)
    if not patterns:
        raise HTTPException(status_code=400, detail=f"Invalid kind. Use one of: {list(ALLOWED_KINDS.keys())}")

    latest = _find_latest_file(patterns)
    chunk = _read_new_lines(latest, max_lines)
    return {
        "ok": True,
        "kind": kind,
        "file": chunk["file"],
        "from_offset": chunk["from_offset"],
        "to_offset": chunk["to_offset"],
        "has_more": chunk["has_more"],
        "count": chunk["count"],
        "lines": chunk["lines"],
    }


if __name__ == "__main__":
    # Run: python3 pmta_accounting_bridge.py
    import uvicorn

    host = os.getenv("BIND_ADDR", "0.0.0.0")
    port = int(os.getenv("PORT", "8090"))
    uvicorn.run("pmta_accounting_bridge:app", host=host, port=port, reload=False)
