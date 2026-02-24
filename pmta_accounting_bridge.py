#!/usr/bin/env python3
"""PMTA accounting bridge.

Runs on the PMTA server, tails accounting CSV/NDJSON files, filters/normalizes
outcomes, then sends campaign-grouped payloads to Shiva API.
"""

import csv
import json
import os
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.request import Request, urlopen


def env_bool(name: str, default: str = "0") -> bool:
    return (os.getenv(name, default) or default).strip().lower() in {"1", "true", "yes", "on"}


SHIVA_URL = (os.getenv("SHIVA_ACCOUNTING_URL", "http://127.0.0.1:5000/pmta/accounting") or "").strip()
SHIVA_TOKEN = (os.getenv("SHIVA_ACCOUNTING_TOKEN", "") or "").strip()
FILES = [p.strip() for p in (os.getenv("PMTA_ACCOUNTING_FILES", "") or "").split(",") if p.strip()]
DIRS = [p.strip() for p in (os.getenv("PMTA_ACCOUNTING_DIRS", "") or "").split(",") if p.strip()]
GLOBS = [p.strip() for p in (os.getenv("PMTA_ACCOUNTING_GLOB", "*.csv,*.ndjson") or "").split(",") if p.strip()]
OFFSET_FILE = (os.getenv("PMTA_ACCOUNTING_BRIDGE_OFFSET_FILE", "/tmp/pmta_accounting_bridge_offsets.json") or "").strip()
POLL_S = float((os.getenv("PMTA_ACCOUNTING_POLL_S", "2") or "2").strip())
BATCH_SIZE = int((os.getenv("PMTA_ACCOUNTING_BRIDGE_BATCH_SIZE", "1000") or "1000").strip())
DRY_RUN = env_bool("PMTA_ACCOUNTING_BRIDGE_DRY_RUN", "0")

HEADERS_BY_PATH: Dict[str, List[str]] = {}


def norm_status(v: Any) -> str:
    s = str(v or "").strip().lower()
    if s in {"d", "delivered", "delivery", "success"}:
        return "delivered"
    if s in {"b", "bounce", "bounced", "hardbounce", "softbounce"}:
        return "bounced"
    if s in {"t", "defer", "deferred", "deferral", "transient"}:
        return "deferred"
    if s in {"c", "complaint", "complained", "fbl"}:
        return "complained"
    return ""


def event_value(ev: dict, *names: str) -> str:
    aliases = {n.strip().lower().replace("_", "-") for n in names if n and n.strip()}
    for k, v in ev.items():
        kk = str(k or "").strip().lower().replace("_", "-")
        if kk in aliases and str(v or "").strip():
            return str(v).strip()
    for k, v in ev.items():
        kk = str(k or "").strip().lower().replace("_", "-")
        if any(a in kk for a in aliases) and str(v or "").strip():
            return str(v).strip()
    return ""


def parse_line(line: str, path: str) -> Optional[dict]:
    s = (line or "").strip()
    if not s:
        return None
    if s.startswith("{") and s.endswith("}"):
        try:
            obj = json.loads(s)
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None

    try:
        fields = [x.strip() for x in next(csv.reader([s]))]
    except Exception:
        return None

    if fields and any(x.lower() in {"type", "event", "rcpt", "recipient", "campaign-id", "x-campaign-id"} for x in fields):
        HEADERS_BY_PATH[path] = [x.strip().lower() for x in fields]
        return None

    hdr = HEADERS_BY_PATH.get(path) or []
    ev: Dict[str, Any] = {"raw": s}
    if hdr and len(hdr) == len(fields):
        for k, v in zip(hdr, fields):
            if k:
                ev[k] = v
    else:
        if fields:
            ev["type"] = fields[0]
    return ev


def to_outcome(ev: dict) -> Optional[dict]:
    campaign_id = event_value(ev, "x-campaign-id", "campaign-id", "campaign_id", "cid")
    if not campaign_id:
        return None
    recipient = event_value(ev, "rcpt", "recipient", "to", "rcpt_to")
    status = norm_status(ev.get("type") or ev.get("event") or ev.get("kind") or ev.get("record") or ev.get("status"))
    if not recipient or not status:
        return None
    job_id = event_value(ev, "x-job-id", "job-id", "job_id", "jobid")
    return {
        "campaign_id": campaign_id,
        "recipient": recipient,
        "status": status,
        "job_id": job_id,
    }


def iter_files() -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for p in FILES:
        rp = os.path.realpath(p)
        if rp not in seen:
            seen.add(rp)
            out.append(p)
    for d in DIRS:
        root = Path(d)
        if not root.exists() or not root.is_dir():
            continue
        for pat in GLOBS or ["*.csv", "*.ndjson"]:
            for f in root.rglob(pat):
                if not f.is_file():
                    continue
                rp = os.path.realpath(str(f))
                if rp in seen:
                    continue
                seen.add(rp)
                out.append(str(f))
    return out


def load_offsets() -> Dict[str, int]:
    try:
        with open(OFFSET_FILE, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if isinstance(obj, dict):
            return {str(k): int(v) for k, v in obj.items()}
    except Exception:
        pass
    return {}


def save_offsets(offsets: Dict[str, int]) -> None:
    tmp = OFFSET_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(offsets, f)
    os.replace(tmp, OFFSET_FILE)


def send_grouped(groups: Dict[str, List[dict]]) -> None:
    for campaign_id, outcomes in groups.items():
        if not outcomes:
            continue
        payload = {"campaign_id": campaign_id, "outcomes": outcomes}
        if DRY_RUN:
            print(f"[DRY_RUN] campaign={campaign_id} outcomes={len(outcomes)}")
            continue

        req = Request(
            SHIVA_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Token": SHIVA_TOKEN,
            },
            method="POST",
        )
        with urlopen(req, timeout=20) as resp:
            _ = resp.read()


def collect_batch(offsets: Dict[str, int]) -> Tuple[Dict[str, List[dict]], Dict[str, int]]:
    groups: Dict[str, List[dict]] = defaultdict(list)
    count = 0
    for p in iter_files():
        try:
            if not os.path.exists(p):
                continue
            off = int(offsets.get(p, 0))
            size = os.path.getsize(p)
            if off > size:
                off = 0
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(off)
                data = f.read()
                offsets[p] = f.tell()
            if not data:
                continue
            for line in data.splitlines():
                ev = parse_line(line, p)
                if not ev:
                    continue
                out = to_outcome(ev)
                if not out:
                    continue
                cid = out.pop("campaign_id")
                groups[cid].append(out)
                count += 1
                if count >= BATCH_SIZE:
                    return groups, offsets
        except Exception as e:
            print(f"[WARN] {p}: {e}")
            continue
    return groups, offsets


def main() -> None:
    if not SHIVA_URL:
        raise RuntimeError("SHIVA_ACCOUNTING_URL is required")
    offsets = load_offsets()
    while True:
        groups, offsets = collect_batch(offsets)
        if groups:
            try:
                send_grouped(groups)
                save_offsets(offsets)
            except Exception as e:
                print(f"[ERROR] send failed: {e}")
        time.sleep(max(0.5, POLL_S))


if __name__ == "__main__":
    main()
