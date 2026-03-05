import os
import json
import hashlib
import math
import logging
import random
import re
import socket
try:
    import ssl
except Exception:  # pragma: no cover - runtime compatibility for Python builds without _ssl
    ssl = None  # type: ignore
import http.client
import subprocess
import time
import traceback
import uuid
import threading
import queue
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from email import policy as email_policy
from email.message import EmailMessage
from email.utils import formataddr, format_datetime
from typing import Optional, Any, Tuple, Dict, List, Set, Callable
from concurrent.futures import ThreadPoolExecutor, Future, TimeoutError
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import quote_plus, urlsplit, urlencode, parse_qsl

import sqlite3
from pathlib import Path

import smtplib

# Flask 2.0 expects werkzeug.urls.url_quote; Werkzeug 3 removed it.
try:  # pragma: no cover - import-time compatibility shim
    import werkzeug.urls as _wz_urls
    if not hasattr(_wz_urls, "url_quote"):
        from urllib.parse import quote as _url_quote

        def _compat_url_quote(value, safe="/:", encoding=None, errors=None):
            if isinstance(value, bytes):
                value = value.decode(encoding or "utf-8", errors or "strict")
            return _url_quote(value, safe=safe)

        _wz_urls.url_quote = _compat_url_quote  # type: ignore[attr-defined]
except Exception:
    pass

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
        custom_nameservers = [
            x.strip()
            for x in (os.getenv("DNS_RESOLVER_NAMESERVERS", "1.1.1.1,8.8.8.8,9.9.9.9") or "").split(",")
            if x.strip()
        ]
        if custom_nameservers:
            DNS_RESOLVER.nameservers = custom_nameservers  # type: ignore[attr-defined]
    except Exception:
        DNS_RESOLVER = None

# MX/A cache to avoid repeated DNS queries
_MX_CACHE: Dict[str, dict] = {}
_MX_CACHE_EXPIRES_AT: Dict[str, float] = {}
_MX_CACHE_LOCK = threading.Lock()
MX_CACHE_TTL_OK = 3600.0
MX_CACHE_TTL_SOFT_FAIL = 120.0

# DNS TXT fallback endpoints (free public DNS-over-HTTPS APIs)
DNS_TXT_DOH_ENDPOINTS = (
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
)

# Common DKIM selectors used by mainstream ESPs and default mail setups.
# We only use this list as a best-effort fallback when no selector is configured.
COMMON_DKIM_SELECTORS = (
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "s1",
    "s2",
    "dkim",
    "mail",
)

# =========================
# Safety / Validation
# =========================
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SMTP_CODE_RE = re.compile(r"\b([245])\d{2}\b")
SMTP_ENHANCED_CODE_RE = re.compile(r"\b([245])\.\d\.\d{1,3}\b")

RECIPIENT_FILTER_ENABLE_SMTP_PROBE = (os.getenv("RECIPIENT_FILTER_ENABLE_SMTP_PROBE", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}
RECIPIENT_FILTER_ENABLE_ROUTE_CHECK = (os.getenv("RECIPIENT_FILTER_ENABLE_ROUTE_CHECK", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}
try:
    RECIPIENT_FILTER_SMTP_PROBE_LIMIT = int((os.getenv("RECIPIENT_FILTER_SMTP_PROBE_LIMIT", "25") or "25").strip())
except Exception:
    RECIPIENT_FILTER_SMTP_PROBE_LIMIT = 25
try:
    RECIPIENT_FILTER_SMTP_TIMEOUT = float((os.getenv("RECIPIENT_FILTER_SMTP_TIMEOUT", "5") or "5").strip())
except Exception:
    RECIPIENT_FILTER_SMTP_TIMEOUT = 5.0
try:
    RECIPIENT_FILTER_ROUTE_THREADS = int((os.getenv("RECIPIENT_FILTER_ROUTE_THREADS", "24") or "24").strip())
except Exception:
    RECIPIENT_FILTER_ROUTE_THREADS = 24
RECIPIENT_FILTER_ROUTE_THREADS = max(1, min(128, RECIPIENT_FILTER_ROUTE_THREADS))
try:
    RECIPIENT_FILTER_SMTP_THREADS = int((os.getenv("RECIPIENT_FILTER_SMTP_THREADS", "8") or "8").strip())
except Exception:
    RECIPIENT_FILTER_SMTP_THREADS = 8
RECIPIENT_FILTER_SMTP_THREADS = max(1, min(64, RECIPIENT_FILTER_SMTP_THREADS))

# Extract emails from messy text (handles weird separators / pasted content)
EMAIL_FIND_RE = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
)


def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _ssl_unavailable_error() -> RuntimeError:
    return RuntimeError("SSL/TLS is unavailable in this Python build (_ssl module missing)")


def _create_default_ssl_context():
    if ssl is None:
        raise _ssl_unavailable_error()
    return ssl.create_default_context()


def _create_unverified_ssl_context():
    if ssl is None:
        raise _ssl_unavailable_error()
    return ssl._create_unverified_context()


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


def normalize_recipients_for_sending(emails: List[str]) -> Tuple[List[str], int, int]:
    """Normalize recipients and return (valid_unique, invalid_count, deduplicated_count)."""
    out: List[str] = []
    seen: Set[str] = set()
    invalid_count = 0
    deduplicated_count = 0
    for raw in emails or []:
        e = str(raw or "").strip()
        if not e or e.count("@") != 1:
            invalid_count += 1
            continue
        local, domain = e.split("@", 1)
        local = local.strip()
        domain = domain.strip().lower()
        if not local or not domain:
            invalid_count += 1
            continue
        norm = f"{local}@{domain}"
        k = norm.lower()
        if k in seen:
            deduplicated_count += 1
            continue
        seen.add(k)
        out.append(norm)
    return out, invalid_count, deduplicated_count


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


DEFAULT_PROVIDER_MX_PATTERNS = {
    "googlemail.com": "google",
    "gmail-smtp-in.l.google.com": "google",
    "google.com": "google",
    "protection.outlook.com": "microsoft",
    "outlook.com": "microsoft",
    "yahoodns.net": "yahoo",
    "icloud.com": "apple",
}

def _normalize_provider_token(val: Any) -> str:
    return str(val or "").strip().lower()


def _domain_suffix_match(domain: str, suffix: str) -> bool:
    d = _normalize_provider_token(domain)
    s = _normalize_provider_token(suffix).lstrip(".")
    return bool(d and s and (d == s or d.endswith("." + s)))


def canonical_provider(recipient_domain: str, mx_hosts: Optional[List[str]] = None, *, alias_map: Optional[Dict[str, str]] = None, suffix_map: Optional[Dict[str, str]] = None, use_mx_fingerprint: bool = False, mx_patterns: Optional[Dict[str, str]] = None, unknown_group: str = "other") -> str:
    domain = _normalize_provider_token(recipient_domain)
    unknown = _normalize_provider_token(unknown_group) or "other"
    aliases = { _normalize_provider_token(k): _normalize_provider_token(v) for k, v in (alias_map or {}).items() if _normalize_provider_token(k) and _normalize_provider_token(v) }
    suffixes = { _normalize_provider_token(k).lstrip('.'): _normalize_provider_token(v) for k, v in (suffix_map or {}).items() if _normalize_provider_token(k) and _normalize_provider_token(v) }
    if domain and domain in aliases:
        return aliases[domain]
    for suffix in sorted(suffixes.keys(), key=lambda x: (-len(x), x)):
        if _domain_suffix_match(domain, suffix):
            return suffixes[suffix]
    if use_mx_fingerprint and mx_hosts:
        patterns_src = mx_patterns if isinstance(mx_patterns, dict) else DEFAULT_PROVIDER_MX_PATTERNS
        patterns = { _normalize_provider_token(k): _normalize_provider_token(v) for k, v in (patterns_src or {}).items() if _normalize_provider_token(k) and _normalize_provider_token(v) }
        norm_hosts = [str(h or "").strip().lower() for h in (mx_hosts or []) if str(h or "").strip()]
        for host in norm_hosts:
            for needle in sorted(patterns.keys(), key=lambda x: (-len(x), x)):
                if needle in host:
                    return patterns[needle]
    return unknown


class ProviderCanon:
    DEFAULT_SUFFIX_MAP = {
        "gmail.com": "google",
        "googlemail.com": "google",
        "outlook.com": "microsoft",
        "hotmail.com": "microsoft",
        "live.com": "microsoft",
    }
    DEFAULT_MX_PATTERNS = dict(DEFAULT_PROVIDER_MX_PATTERNS)

    def __init__(self, *, enabled: bool, enforce: bool, export: bool, debug: bool, alias_map: Optional[Dict[str, str]], suffix_map: Optional[Dict[str, str]], use_mx_fingerprint: bool, unknown_group: str):
        self.enabled = bool(enabled)
        self.enforce = bool(enforce and enabled)
        self.export = bool(export)
        self.debug = bool(debug)
        self.alias_map = dict(alias_map or {})
        self.suffix_map = dict(suffix_map or self.DEFAULT_SUFFIX_MAP)
        self.use_mx_fingerprint = bool(use_mx_fingerprint)
        self.mx_patterns = dict(self.DEFAULT_MX_PATTERNS)
        self.unknown_group = _normalize_provider_token(unknown_group) or "other"
        self.domain_to_group: Dict[str, str] = {}
        self.group_counts: Dict[str, int] = {}
        self.unknown_domains: Set[str] = set()

    @classmethod
    def _parse_json_map(cls, raw: str) -> Dict[str, str]:
        txt = str(raw or "").strip()
        if not txt:
            return {}
        try:
            parsed = json.loads(txt)
        except Exception:
            return {}
        if not isinstance(parsed, dict):
            return {}
        out: Dict[str, str] = {}
        for k, v in parsed.items():
            kk = _normalize_provider_token(k)
            vv = _normalize_provider_token(v)
            if kk and vv:
                out[kk] = vv
        return out

    @classmethod
    def from_env(cls, *, enabled: bool, enforce: bool, export: bool, debug: bool, alias_json: str, suffix_json: str, use_mx_fingerprint: bool, unknown_group: str) -> 'ProviderCanon':
        alias_map = cls._parse_json_map(alias_json)
        suffix_map = dict(cls.DEFAULT_SUFFIX_MAP)
        suffix_map.update(cls._parse_json_map(suffix_json))
        return cls(enabled=enabled, enforce=enforce, export=export, debug=debug, alias_map=alias_map, suffix_map=suffix_map, use_mx_fingerprint=use_mx_fingerprint, unknown_group=unknown_group)

    def group_for_domain(self, recipient_domain: str, mx_hosts: Optional[List[str]] = None) -> str:
        domain = _normalize_provider_token(recipient_domain)
        if not domain:
            return self.unknown_group
        if domain in self.domain_to_group:
            return self.domain_to_group[domain]
        grp = canonical_provider(domain, mx_hosts, alias_map=self.alias_map, suffix_map=self.suffix_map, use_mx_fingerprint=self.use_mx_fingerprint, mx_patterns=self.mx_patterns, unknown_group=self.unknown_group)
        self.domain_to_group[domain] = grp
        if grp == self.unknown_group:
            self.unknown_domains.add(domain)
        return grp

    def ingest_provider_counts(self, provider_counts: Dict[str, int], mx_by_domain: Optional[Dict[str, List[str]]] = None) -> None:
        for d, cnt in (provider_counts or {}).items():
            dom = _normalize_provider_token(d)
            if not dom:
                continue
            grp = self.group_for_domain(dom, (mx_by_domain or {}).get(dom))
            self.group_counts[grp] = int(self.group_counts.get(grp) or 0) + max(0, int(cnt or 0))

    def lane_provider_key(self, lane_key: Tuple[int, str]) -> Tuple[int, str]:
        sender_idx = int((lane_key or (0, ""))[0] or 0)
        raw_domain = str((lane_key or (0, ""))[1] or "").strip().lower()
        if not self.enforce:
            return (sender_idx, raw_domain)
        return (sender_idx, self.group_for_domain(raw_domain))

    def snapshot(self, top_n_domains: int = 50) -> dict:
        sorted_domains = sorted(self.domain_to_group.items(), key=lambda kv: kv[0])[:max(1, int(top_n_domains or 50))]
        return {
            "enabled": bool(self.enabled),
            "enforce": bool(self.enforce),
            "provider_groups": {k: int(v) for k, v in sorted(self.group_counts.items())},
            "domain_to_group": {k: v for k, v in sorted_domains},
            "unknown_domains_sample": sorted(list(self.unknown_domains))[:20],
            "mx_fingerprint_used": bool(self.use_mx_fingerprint),
        }


def normalize_and_partition_recipients(
    recipients: List[str],
    sender_emails: List[str],
    seed: str,
) -> Tuple[Dict[str, Dict[str, List[str]]], Dict[str, Any]]:
    """Build buckets[sender_email][recipient_domain] with deterministic balancing."""
    normalized_valid: List[str] = []
    invalid_count = 0
    seen: Set[str] = set()
    deduped_count = 0

    for raw in recipients or []:
        e = str(raw or "").strip()
        if not e or e.count("@") != 1:
            invalid_count += 1
            continue
        local, domain = e.split("@", 1)
        local = local.strip()
        domain = domain.strip().lower()
        if not local or not domain:
            invalid_count += 1
            continue
        norm = f"{local}@{domain}"
        dedupe_key = norm.lower()
        if dedupe_key in seen:
            deduped_count += 1
            continue
        seen.add(dedupe_key)
        normalized_valid.append(norm)

    senders = list(sender_emails or [])
    k = max(1, len(senders))
    domain_map, domain_order = build_provider_buckets(normalized_valid)
    out: Dict[str, Dict[str, List[str]]] = {s: {} for s in senders}

    for domain in domain_order:
        domain_items = list(domain_map.get(domain) or [])
        seed_material = f"{seed}|{domain}".encode("utf-8", errors="ignore")
        domain_seed = int(hashlib.sha256(seed_material).hexdigest()[:16], 16)
        random.Random(domain_seed).shuffle(domain_items)

        n = len(domain_items)
        base = n // k
        rem = n % k
        pos = 0
        for i in range(k):
            size = base + (1 if i < rem else 0)
            if size <= 0:
                continue
            slice_items = domain_items[pos : pos + size]
            pos += size
            if not slice_items:
                continue
            sender = senders[i]
            if sender not in out:
                out[sender] = {}
            out[sender].setdefault(domain, []).extend(slice_items)

    sender_totals: Dict[str, int] = {}
    sender_domain_counts: Dict[str, Dict[str, int]] = {}
    for sender, domains in out.items():
        sender_domain_counts[sender] = {d: len(v) for d, v in domains.items()}
        sender_totals[sender] = sum(sender_domain_counts[sender].values())

    domain_spread_ok = True
    for domain in domain_order:
        counts = [len((out.get(sender) or {}).get(domain) or []) for sender in senders]
        if counts and (max(counts) - min(counts) > 1):
            domain_spread_ok = False
            break

    stats: Dict[str, Any] = {
        "valid_total": len(normalized_valid),
        "invalid_count": invalid_count,
        "deduplicated_count": deduped_count,
        "sender_totals": sender_totals,
        "sender_domain_counts": sender_domain_counts,
        "totals_match": (sum(sender_totals.values()) == len(normalized_valid)),
        "domain_spread_ok": domain_spread_ok,
    }
    return out, stats


def build_baseline_report(
    job: 'SendJob',
    sender_buckets: Dict[int, Dict[str, List[str]]],
    provider_buckets: Dict[str, List[str]],
    partition_seed: str,
    overrides: dict,
    pmta_live: dict,
    pressure_caps: dict,
    health_caps: dict,
    provider_retry_chunks: Dict[str, List[dict]],
) -> dict:
    """Build a read-only scheduler baseline snapshot (no mutations)."""
    sender_counts: Dict[str, Dict[str, int]] = {}
    sender_totals: Dict[str, int] = {}
    for sender_idx, domains in (sender_buckets or {}).items():
        key = str(int(sender_idx))
        domain_counts = {str(dom): int(len(rcpts or [])) for dom, rcpts in (domains or {}).items() if dom is not None}
        sender_counts[key] = domain_counts
        sender_totals[key] = int(sum(domain_counts.values()))

    provider_counts = {str(dom): int(len(rcpts or [])) for dom, rcpts in (provider_buckets or {}).items() if dom is not None}

    retry_key_counts = {str(k): int(len(v or [])) for k, v in (provider_retry_chunks or {}).items()}
    retry_total_items = int(sum(retry_key_counts.values()))
    retry_earliest = None
    for items in (provider_retry_chunks or {}).values():
        for item in (items or []):
            try:
                ts = float(item.get("next_retry_ts") or 0.0)
            except Exception:
                ts = 0.0
            if ts <= 0:
                continue
            retry_earliest = ts if (retry_earliest is None or ts < retry_earliest) else retry_earliest

    return {
        "job_id": str(getattr(job, "id", "") or ""),
        "campaign_id": str(getattr(job, "campaign_id", "") or ""),
        "partition_seed": str(partition_seed or ""),
        "total_valid_recipients": int(sum(provider_counts.values())),
        "invalid_count": 0,
        "deduped_count": 0,
        "sender_email_count": int(len(sender_counts)),
        "provider_domains": provider_counts,
        "per_sender_provider_counts": sender_counts,
        "per_sender_totals": sender_totals,
        "runtime_overrides": dict(overrides or {}),
        "pmta_live": dict(pmta_live or {}),
        "pmta_pressure": dict(pressure_caps or {}),
        "health_policy": dict(health_caps or {}),
        "provider_retry_chunks": {
            "keys": int(len(retry_key_counts)),
            "items": retry_total_items,
            "per_key_counts": retry_key_counts,
            "earliest_next_retry_ts": retry_earliest,
        },
    }


def lane_debug_self_check(report: dict) -> None:
    """Validate scheduler baseline invariants in debug mode."""
    logger = logging.getLogger("shiva")
    if not isinstance(report, dict):
        logger.warning("lane_debug_self_check: report missing or invalid")
        return

    total_valid = int(report.get("total_valid_recipients") or 0)
    per_sender = report.get("per_sender_provider_counts") if isinstance(report.get("per_sender_provider_counts"), dict) else {}
    provider_domains = report.get("provider_domains") if isinstance(report.get("provider_domains"), dict) else {}

    sender_sum = 0
    for sender_idx, dom_counts in per_sender.items():
        if not str(sender_idx).strip():
            logger.warning("lane_debug_self_check: empty sender index key")
        if not isinstance(dom_counts, dict):
            logger.warning("lane_debug_self_check: sender %s counts are not a dict", sender_idx)
            continue
        for dom, cnt in dom_counts.items():
            if dom in {None, "", "none"}:
                logger.warning("lane_debug_self_check: sender %s has empty provider domain", sender_idx)
            n = int(cnt or 0)
            if n < 0:
                raise ValueError(f"lane_debug_self_check: negative count sender={sender_idx} domain={dom} count={n}")
            sender_sum += n

    if sender_sum != total_valid:
        raise ValueError(f"lane_debug_self_check: sender totals mismatch sender_sum={sender_sum} total_valid={total_valid}")

    for dom, bucket_count in provider_domains.items():
        b = int(bucket_count or 0)
        if b < 0:
            raise ValueError(f"lane_debug_self_check: negative provider bucket domain={dom} count={b}")
        per_domain_sum = 0
        for dom_counts in per_sender.values():
            if not isinstance(dom_counts, dict):
                continue
            per_domain_sum += int(dom_counts.get(dom) or 0)
        if per_domain_sum != b:
            raise ValueError(
                f"lane_debug_self_check: provider mismatch domain={dom} sender_sum={per_domain_sum} provider_bucket={b}"
            )

    partition_seed = str(report.get("partition_seed") or "").strip()
    if not partition_seed:
        raise ValueError("lane_debug_self_check: deterministic partition seed missing")
    logger.info("lane_debug_self_check: partition_seed=%s", partition_seed)


class LaneMetrics:
    """In-memory rolling lane health metrics keyed by (sender_idx, provider_domain)."""

    def __init__(self, window: int, use_ema: bool):
        self.window = max(1, int(window or 1))
        self.use_ema = bool(use_ema)
        self._lanes: Dict[str, dict] = {}

    def _lane_id(self, lane_key: Tuple[int, str]) -> str:
        sender_idx, provider_domain = lane_key
        return f"{int(sender_idx)}|{str(provider_domain or '').strip().lower()}"

    def ensure_lane(self, lane_key: Tuple[int, str], *, sender_email: str = "", sender_domain: str = "") -> dict:
        lid = self._lane_id(lane_key)
        lane = self._lanes.get(lid)
        if lane is None:
            lane = {
                "sender_idx": int(lane_key[0] or 0),
                "provider_domain": str(lane_key[1] or "").strip().lower(),
                "sender_email": str(sender_email or "").strip(),
                "sender_domain": str(sender_domain or "").strip().lower(),
                "window": deque(maxlen=self.window),
                "sums": {
                    "attempts_total": 0,
                    "sent_attempts": 0,
                    "accepted_2xx": 0,
                    "deferrals_4xx": 0,
                    "hardfails_5xx": 0,
                    "timeouts_conn": 0,
                    "blocked_events": 0,
                    "backoff_events": 0,
                    "acct_delivered": 0,
                    "acct_bounced": 0,
                    "acct_deferred": 0,
                    "acct_complained": 0,
                },
                "chunks_selected": 0,
                "selected_messages": 0,
                "last_error_samples": deque(maxlen=5),
                "last_backoff": {"wait_s": 0.0, "failure_type": ""},
            }
            self._lanes[lid] = lane
        else:
            if sender_email:
                lane["sender_email"] = str(sender_email).strip()
            if sender_domain:
                lane["sender_domain"] = str(sender_domain).strip().lower()
        return lane

    def _push_window(self, lane: dict, sample: dict) -> None:
        w = lane["window"]
        sums = lane["sums"]
        if len(w) >= self.window:
            old = w[0]
            for k in sums.keys():
                sums[k] = int(sums.get(k) or 0) - int(old.get(k) or 0)
        w.append(sample)
        for k in sums.keys():
            sums[k] = int(sums.get(k) or 0) + int(sample.get(k) or 0)

    def _add_error_signature(self, lane: dict, signature: str) -> None:
        sig = str(signature or "").strip()
        if sig:
            lane["last_error_samples"].append(sig[:160])

    def on_chunk_selected(self, lane_key: Tuple[int, str], chunk_size: int, *, sender_email: str = "", sender_domain: str = "") -> None:
        lane = self.ensure_lane(lane_key, sender_email=sender_email, sender_domain=sender_domain)
        lane["chunks_selected"] = int(lane.get("chunks_selected") or 0) + 1
        lane["selected_messages"] = int(lane.get("selected_messages") or 0) + max(0, int(chunk_size or 0))

    def on_probe_sample(self, lane_key: Tuple[int, str], *, sender_email: str = "", sender_domain: str = "") -> None:
        lane = self.ensure_lane(lane_key, sender_email=sender_email, sender_domain=sender_domain)
        lane["probe_samples"] = int(lane.get("probe_samples") or 0) + 1

    def on_blocked(self, lane_key: Tuple[int, str], reason: str, *, sender_email: str = "", sender_domain: str = "") -> None:
        lane = self.ensure_lane(lane_key, sender_email=sender_email, sender_domain=sender_domain)
        self._push_window(
            lane,
            {
                "attempts_total": 0,
                "sent_attempts": 0,
                "accepted_2xx": 0,
                "deferrals_4xx": 0,
                "hardfails_5xx": 0,
                "timeouts_conn": 0,
                "blocked_events": 1,
                "backoff_events": 0,
            },
        )
        self._add_error_signature(lane, f"blocked:{str(reason or 'policy').strip()[:140]}")

    def on_chunk_result(self, lane_key: Tuple[int, str], counts_dict: dict, *, sender_email: str = "", sender_domain: str = "") -> None:
        lane = self.ensure_lane(lane_key, sender_email=sender_email, sender_domain=sender_domain)
        sample = {
            "attempts_total": max(0, int((counts_dict or {}).get("attempts_total") or 0)),
            "sent_attempts": max(0, int((counts_dict or {}).get("sent_attempts") or 0)),
            "accepted_2xx": max(0, int((counts_dict or {}).get("accepted_2xx") or 0)),
            "deferrals_4xx": max(0, int((counts_dict or {}).get("deferrals_4xx") or 0)),
            "hardfails_5xx": max(0, int((counts_dict or {}).get("hardfails_5xx") or 0)),
            "timeouts_conn": max(0, int((counts_dict or {}).get("timeouts_conn") or 0)),
            "blocked_events": max(0, int((counts_dict or {}).get("blocked_events") or 0)),
            "backoff_events": 0,
        }
        self._push_window(lane, sample)
        for sig in list((counts_dict or {}).get("error_signatures") or [])[:5]:
            self._add_error_signature(lane, str(sig))

    def on_backoff_scheduled(self, lane_key: Tuple[int, str], wait_s: float, failure_type: str, *, sender_email: str = "", sender_domain: str = "") -> None:
        lane = self.ensure_lane(lane_key, sender_email=sender_email, sender_domain=sender_domain)
        self._push_window(
            lane,
            {
                "attempts_total": 0,
                "sent_attempts": 0,
                "accepted_2xx": 0,
                "deferrals_4xx": 0,
                "hardfails_5xx": 0,
                "timeouts_conn": 0,
                "blocked_events": 0,
                "backoff_events": 1,
            },
        )
        lane["last_backoff"] = {"wait_s": float(wait_s or 0.0), "failure_type": str(failure_type or "")}
        self._add_error_signature(lane, f"backoff:{str(failure_type or 'unknown')}")

    def on_accounting_delta(
        self,
        lane_key: Tuple[int, str],
        *,
        delivered: int = 0,
        bounced: int = 0,
        deferred: int = 0,
        complained: int = 0,
        sender_email: str = "",
        sender_domain: str = "",
    ) -> None:
        lane = self.ensure_lane(lane_key, sender_email=sender_email, sender_domain=sender_domain)
        self._push_window(
            lane,
            {
                "attempts_total": 0,
                "sent_attempts": 0,
                "accepted_2xx": 0,
                "deferrals_4xx": 0,
                "hardfails_5xx": 0,
                "timeouts_conn": 0,
                "blocked_events": 0,
                "backoff_events": 0,
                "acct_delivered": max(0, int(delivered or 0)),
                "acct_bounced": max(0, int(bounced or 0)),
                "acct_deferred": max(0, int(deferred or 0)),
                "acct_complained": max(0, int(complained or 0)),
            },
        )

    def snapshot(self) -> dict:
        out: Dict[str, Any] = {
            "window": int(self.window),
            "use_ema": bool(self.use_ema),
            "lanes": {},
        }
        for lane_id, lane in self._lanes.items():
            sums = lane.get("sums") or {}
            attempts = max(1, int(sums.get("attempts_total") or 0))
            out["lanes"][lane_id] = {
                "sender_idx": int(lane.get("sender_idx") or 0),
                "sender_email": str(lane.get("sender_email") or ""),
                "sender_domain": str(lane.get("sender_domain") or ""),
                "provider_domain": str(lane.get("provider_domain") or ""),
                "window_samples": int(len(lane.get("window") or [])),
                "chunks_selected": int(lane.get("chunks_selected") or 0),
                "selected_messages": int(lane.get("selected_messages") or 0),
                "probe_samples": int(lane.get("probe_samples") or 0),
                "attempts_total": int(sums.get("attempts_total") or 0),
                "sent_attempts": int(sums.get("sent_attempts") or 0),
                "accepted_2xx": int(sums.get("accepted_2xx") or 0),
                "deferrals_4xx": int(sums.get("deferrals_4xx") or 0),
                "hardfails_5xx": int(sums.get("hardfails_5xx") or 0),
                "timeouts_conn": int(sums.get("timeouts_conn") or 0),
                "blocked_events": int(sums.get("blocked_events") or 0),
                "backoff_events": int(sums.get("backoff_events") or 0),
                "acct_delivered": int(sums.get("acct_delivered") or 0),
                "acct_bounced": int(sums.get("acct_bounced") or 0),
                "acct_deferred": int(sums.get("acct_deferred") or 0),
                "acct_complained": int(sums.get("acct_complained") or 0),
                "acct_total": int(
                    int(sums.get("acct_delivered") or 0)
                    + int(sums.get("acct_bounced") or 0)
                    + int(sums.get("acct_deferred") or 0)
                    + int(sums.get("acct_complained") or 0)
                ),
                "deferral_rate": float(int(sums.get("deferrals_4xx") or 0) / attempts),
                "hardfail_rate": float(int(sums.get("hardfails_5xx") or 0) / attempts),
                "timeout_rate": float(int(sums.get("timeouts_conn") or 0) / attempts),
                "acct_deferred_rate": float(
                    int(sums.get("acct_deferred") or 0)
                    / max(1, int(
                        int(sums.get("acct_delivered") or 0)
                        + int(sums.get("acct_bounced") or 0)
                        + int(sums.get("acct_deferred") or 0)
                        + int(sums.get("acct_complained") or 0)
                    ))
                ),
                "last_backoff": dict(lane.get("last_backoff") or {}),
                "last_error_samples": list(lane.get("last_error_samples") or []),
            }
        return out

    def reset_for_job(self, job_id: str) -> None:
        _ = str(job_id or "")
        self._lanes = {}


class LaneRegistry:
    """Read-only lane state machine (HEALTHY/THROTTLED/QUARANTINED/INFRA_FAIL).

    This registry is intentionally non-enforcing in this phase. It computes per-lane state,
    next_allowed_ts, and recommended caps from LaneMetrics + blocked/backoff signals and only
    exports debug snapshots.
    """

    def __init__(self, thresholds: Optional[dict], quarantine_base_s: int, quarantine_max_s: int):
        self.thresholds = self._normalize_thresholds(thresholds or {})
        self.quarantine_base_s = max(1, int(quarantine_base_s or 120))
        self.quarantine_max_s = max(self.quarantine_base_s, int(quarantine_max_s or 1800))
        self._lanes: Dict[str, dict] = {}
        self._quarantine_decay_s = 1800.0

    def _lane_id(self, lane_key: Tuple[int, str]) -> str:
        sender_idx, provider_domain = lane_key
        return f"{int(sender_idx)}|{str(provider_domain or '').strip().lower()}"

    def _normalize_thresholds(self, raw: dict) -> dict:
        defaults = {
            "timeout_rate_infra": 0.05,
            "hardfail_rate_quarantine": 0.02,
            "deferral_rate_quarantine": 0.30,
            "deferral_rate_throttled": 0.15,
            "throttle_workers_mul": 0.50,
            "throttle_chunk_mul": 0.60,
            "throttle_delay_mul": 1.50,
        }
        out = dict(defaults)

        def _clamp_rate(v: Any, d: float) -> float:
            try:
                return min(1.0, max(0.0, float(v)))
            except Exception:
                return d

        def _clamp_mul(v: Any, d: float, lo: float, hi: float) -> float:
            try:
                return min(hi, max(lo, float(v)))
            except Exception:
                return d

        out["timeout_rate_infra"] = _clamp_rate(raw.get("timeout_rate_infra"), defaults["timeout_rate_infra"])
        out["hardfail_rate_quarantine"] = _clamp_rate(raw.get("hardfail_rate_quarantine"), defaults["hardfail_rate_quarantine"])
        out["deferral_rate_quarantine"] = _clamp_rate(raw.get("deferral_rate_quarantine"), defaults["deferral_rate_quarantine"])
        out["deferral_rate_throttled"] = _clamp_rate(raw.get("deferral_rate_throttled"), defaults["deferral_rate_throttled"])
        if out["deferral_rate_throttled"] > out["deferral_rate_quarantine"]:
            out["deferral_rate_throttled"] = out["deferral_rate_quarantine"]
        out["throttle_workers_mul"] = _clamp_mul(raw.get("throttle_workers_mul"), defaults["throttle_workers_mul"], 0.1, 1.0)
        out["throttle_chunk_mul"] = _clamp_mul(raw.get("throttle_chunk_mul"), defaults["throttle_chunk_mul"], 0.1, 1.0)
        out["throttle_delay_mul"] = _clamp_mul(raw.get("throttle_delay_mul"), defaults["throttle_delay_mul"], 1.0, 5.0)
        return out

    def ensure_lane(self, lane_key: Tuple[int, str], sender_label: str = "", provider_domain: str = "") -> dict:
        lid = self._lane_id(lane_key)
        lane = self._lanes.get(lid)
        if lane is None:
            lane = {
                "sender_idx": int(lane_key[0] or 0),
                "sender_label": str(sender_label or "").strip(),
                "provider_domain": str(provider_domain or lane_key[1] or "").strip().lower(),
                "state": "HEALTHY",
                "last_state_change_ts": 0.0,
                "next_allowed_ts": 0.0,
                "last_reason": "init",
                "recommended_caps": {},
                "recommended_caps_learning": {},
                "deferral_rate": 0.0,
                "hardfail_rate": 0.0,
                "timeout_rate": 0.0,
                "recent_error_samples": [],
                "blocked_events": 0,
                "blocked_reasons": deque(maxlen=5),
                "last_backoff": {"wait_s": 0.0, "failure_type": ""},
                "infra_fail_hits": 0,
                "quarantine_hits": 0,
                "last_quarantine_ts": 0.0,
            }
            self._lanes[lid] = lane
        else:
            if sender_label:
                lane["sender_label"] = str(sender_label).strip()
            if provider_domain:
                lane["provider_domain"] = str(provider_domain).strip().lower()
        return lane

    def _build_caps(self, state: str, base_caps_hint: Optional[dict]) -> dict:
        base = base_caps_hint if isinstance(base_caps_hint, dict) else {}
        base_workers = max(1, int(base.get("workers") or 1))
        base_chunk = max(1, int(base.get("chunk_size") or 100))
        base_delay = max(0.0, float(base.get("delay_s") or 0.0))
        base_sleep = max(0.0, float(base.get("sleep_chunks") or 0.0))

        if state == "HEALTHY":
            return {
                "chunk_size_cap": None,
                "workers_cap": None,
                "delay_floor": None,
                "sleep_floor": None,
            }
        if state == "INFRA_FAIL":
            return {
                "chunk_size_cap": 50,
                "workers_cap": 1,
                "delay_floor": max(1.0, base_delay),
                "sleep_floor": max(base_sleep, base_sleep + 2.0),
            }

        workers_cap = max(1, int(math.floor(base_workers * float(self.thresholds.get("throttle_workers_mul") or 0.5))))
        chunk_cap = max(50, int(math.floor(base_chunk * float(self.thresholds.get("throttle_chunk_mul") or 0.6))))
        delay_mul = float(self.thresholds.get("throttle_delay_mul") or 1.5)
        return {
            "chunk_size_cap": chunk_cap,
            "workers_cap": workers_cap,
            "delay_floor": max(base_delay * delay_mul, base_delay + 0.3),
            "sleep_floor": max(base_sleep, base_sleep + 1.0),
        }

    def _derive_state(self, lane: dict, metrics: dict) -> Tuple[str, str]:
        d = float(metrics.get("deferral_rate") or 0.0)
        h = float(metrics.get("hardfail_rate") or 0.0)
        t = float(metrics.get("timeout_rate") or 0.0)
        acct_total = int(metrics.get("acct_total") or 0)
        if acct_total > 0:
            d = float(metrics.get("acct_deferred_rate") or d)
            h = float((int(metrics.get("acct_bounced") or 0) + int(metrics.get("acct_complained") or 0)) / max(1, acct_total))
        backoff_type = str((lane.get("last_backoff") or {}).get("failure_type") or "").strip().lower()
        blocked_recent = len(lane.get("blocked_reasons") or []) > 0
        if t >= float(self.thresholds.get("timeout_rate_infra") or 0.05):
            return "INFRA_FAIL", f"timeout_rate={t:.3f}"
        if any(x in backoff_type for x in ("timeout", "connect", "connection", "auth")) and (t >= 0.02 or blocked_recent):
            return "INFRA_FAIL", f"backoff_type={backoff_type or 'infra'}"
        if h >= float(self.thresholds.get("hardfail_rate_quarantine") or 0.02):
            return "QUARANTINED", f"hardfail_rate={h:.3f}"
        if d >= float(self.thresholds.get("deferral_rate_quarantine") or 0.30):
            return "QUARANTINED", f"deferral_rate={d:.3f}"
        if d >= float(self.thresholds.get("deferral_rate_throttled") or 0.15):
            return "THROTTLED", f"deferral_rate={d:.3f}"
        return "HEALTHY", "within_thresholds"

    def update_from_metrics(self, now_ts: float, lane_key: Tuple[int, str], lane_metrics_snapshot_for_lane: dict, base_caps_hint: Optional[dict] = None) -> None:
        lane = self.ensure_lane(lane_key, provider_domain=str(lane_key[1] or ""))
        snap = lane_metrics_snapshot_for_lane if isinstance(lane_metrics_snapshot_for_lane, dict) else {}
        lane["deferral_rate"] = float(snap.get("deferral_rate") or 0.0)
        lane["hardfail_rate"] = float(snap.get("hardfail_rate") or 0.0)
        lane["timeout_rate"] = float(snap.get("timeout_rate") or 0.0)
        lane["recent_error_samples"] = list(snap.get("last_error_samples") or [])[-5:]
        lane["blocked_events"] = int(snap.get("blocked_events") or lane.get("blocked_events") or 0)
        lane["last_backoff"] = dict(snap.get("last_backoff") or lane.get("last_backoff") or {"wait_s": 0.0, "failure_type": ""})

        next_state, reason = self._derive_state(lane, snap)
        prev_state = str(lane.get("state") or "HEALTHY")
        if next_state != prev_state:
            lane["state"] = next_state
            lane["last_state_change_ts"] = float(now_ts or time.time())
            lane["last_reason"] = str(reason or "")[:200]
            if next_state == "QUARANTINED":
                if (float(now_ts or 0.0) - float(lane.get("last_quarantine_ts") or 0.0)) > self._quarantine_decay_s:
                    lane["quarantine_hits"] = 0
                lane["quarantine_hits"] = int(lane.get("quarantine_hits") or 0) + 1
                lane["last_quarantine_ts"] = float(now_ts or 0.0)
                wait_s = min(self.quarantine_max_s, self.quarantine_base_s * (2 ** max(0, int(lane.get("quarantine_hits") or 1) - 1)))
                lane["next_allowed_ts"] = float(now_ts or 0.0) + float(wait_s)
            elif next_state == "INFRA_FAIL":
                lane["infra_fail_hits"] = int(lane.get("infra_fail_hits") or 0) + 1
                wait_s = min(self.quarantine_max_s, self.quarantine_base_s * (2 ** max(0, int(lane.get("infra_fail_hits") or 1) - 1)))
                lane["next_allowed_ts"] = float(now_ts or 0.0) + float(wait_s)
            else:
                lane["next_allowed_ts"] = 0.0
        else:
            lane["last_reason"] = str(reason or lane.get("last_reason") or "")[:200]
            if next_state not in {"QUARANTINED", "INFRA_FAIL"}:
                lane["next_allowed_ts"] = 0.0

        lane["recommended_caps"] = self._build_caps(next_state, base_caps_hint)

    def set_signal_blocked(self, lane_key: Tuple[int, str], reason: str) -> None:
        lane = self.ensure_lane(lane_key, provider_domain=str(lane_key[1] or ""))
        lane["blocked_events"] = int(lane.get("blocked_events") or 0) + 1
        lane["blocked_reasons"].append(str(reason or "blocked")[:160])

    def set_signal_backoff(self, lane_key: Tuple[int, str], wait_s: float, failure_type: str) -> None:
        lane = self.ensure_lane(lane_key, provider_domain=str(lane_key[1] or ""))
        lane["last_backoff"] = {"wait_s": float(wait_s or 0.0), "failure_type": str(failure_type or "")[:80]}

    def get_lane_info(self, lane_key: Tuple[int, str]) -> dict:
        lane = self.ensure_lane(lane_key, provider_domain=str(lane_key[1] or ""))
        return {
            "sender_idx": int(lane.get("sender_idx") or 0),
            "sender_label": str(lane.get("sender_label") or ""),
            "provider_domain": str(lane.get("provider_domain") or ""),
            "state": str(lane.get("state") or "HEALTHY"),
            "last_state_change_ts": float(lane.get("last_state_change_ts") or 0.0),
            "next_allowed_ts": float(lane.get("next_allowed_ts") or 0.0),
            "last_reason": str(lane.get("last_reason") or ""),
            "recommended_caps": dict(lane.get("recommended_caps") or {}),
            "recommended_caps_learning": dict(lane.get("recommended_caps_learning") or {}),
            "deferral_rate": float(lane.get("deferral_rate") or 0.0),
            "hardfail_rate": float(lane.get("hardfail_rate") or 0.0),
            "timeout_rate": float(lane.get("timeout_rate") or 0.0),
            "recent_error_samples": list(lane.get("recent_error_samples") or []),
            "blocked_events": int(lane.get("blocked_events") or 0),
            "last_backoff": dict(lane.get("last_backoff") or {}),
            "quarantine_hits": int(lane.get("quarantine_hits") or 0),
            "infra_fail_hits": int(lane.get("infra_fail_hits") or 0),
        }

    def snapshot(self) -> dict:
        return {
            "thresholds": dict(self.thresholds),
            "quarantine_base_s": int(self.quarantine_base_s),
            "quarantine_max_s": int(self.quarantine_max_s),
            "lanes": {lid: self.get_lane_info((int(v.get("sender_idx") or 0), str(v.get("provider_domain") or ""))) for lid, v in self._lanes.items()},
        }

    def set_learning_caps(self, lane_key: Tuple[int, str], learning_caps: Optional[dict]) -> None:
        lane = self.ensure_lane(lane_key, provider_domain=str(lane_key[1] or ""))
        lane["recommended_caps_learning"] = dict(learning_caps or {})


@dataclass
class BudgetConfig:
    enabled: bool = False
    debug: bool = False
    provider_max_inflight_default: int = 1
    provider_max_inflight_map: Dict[str, int] = field(default_factory=dict)
    provider_min_gap_s_default: float = 0.0
    provider_min_gap_s_map: Dict[str, float] = field(default_factory=dict)
    provider_cooldown_s_default: float = 0.0
    provider_cooldown_s_map: Dict[str, float] = field(default_factory=dict)
    sender_max_inflight: int = 1
    apply_to_retry: bool = False
    apply_to_probe: bool = True
    export: bool = False


class PolicyPackLoader:
    """Loads/validates provider policy packs from JSON with safe built-in defaults."""

    BUILTIN_DEFAULT_PACK: Dict[str, Any] = {
        "provider_defaults": {
            "google": {"max_inflight": 1, "min_gap_s": 20.0, "cooldown_s": 120.0, "delay_floor": 1.0, "chunk_cap": 150, "workers_cap": 3},
            "gmail": {"max_inflight": 1, "min_gap_s": 20.0, "cooldown_s": 120.0, "delay_floor": 1.0, "chunk_cap": 150, "workers_cap": 3},
            "microsoft": {"max_inflight": 1, "min_gap_s": 10.0, "cooldown_s": 60.0, "delay_floor": 0.7, "chunk_cap": 200, "workers_cap": 4},
            "yahoo": {"max_inflight": 1, "min_gap_s": 15.0, "cooldown_s": 90.0, "delay_floor": 0.8, "chunk_cap": 180, "workers_cap": 3},
            "other": {"max_inflight": 2, "min_gap_s": 0.0, "cooldown_s": 0.0, "delay_floor": 0.4, "chunk_cap": 300, "workers_cap": 5},
            "*": {"max_inflight": 2, "min_gap_s": 0.0, "cooldown_s": 0.0, "delay_floor": 0.4, "chunk_cap": 300, "workers_cap": 5},
        },
        "single_domain_wave": {"max_inflight": 1, "burst_tokens": 400, "refill_per_sec": 3.0, "max_burst": 1200.0, "max_refill": 10.0},
        "resource_governor": {"max_total_workers": 40},
        "fallback": {"deferral_rate": 0.35, "hardfail_rate": 0.05, "timeout_rate": 0.08},
    }

    @staticmethod
    def _f(v: Any, default: float, min_v: float, max_v: float) -> float:
        try:
            out = float(v)
        except Exception:
            out = float(default)
        return max(min_v, min(max_v, out))

    @staticmethod
    def _i(v: Any, default: int, min_v: int, max_v: int) -> int:
        out = _coerce_scalar_number(v, as_type="int", default=default)
        out = _coerce_scalar_number(out, as_type="int", default=default)
        return max(min_v, min(max_v, out))

    @classmethod
    def validate_and_normalize(cls, pack_raw: Any) -> dict:
        src = dict(pack_raw or {}) if isinstance(pack_raw, dict) else {}
        builtins = dict(cls.BUILTIN_DEFAULT_PACK)
        provider_src = src.get("provider_defaults") if isinstance(src.get("provider_defaults"), dict) else {}
        provider_defaults: Dict[str, dict] = {}
        for k, v in provider_src.items():
            if not isinstance(v, dict):
                continue
            kk = str(k or "").strip().lower()
            if not kk:
                continue
            provider_defaults[kk] = {
                "max_inflight": cls._i(v.get("max_inflight"), 1, 1, 10),
                "min_gap_s": cls._f(v.get("min_gap_s"), 0.0, 0.0, 3600.0),
                "cooldown_s": cls._f(v.get("cooldown_s"), 0.0, 0.0, 3600.0),
                "delay_floor": cls._f(v.get("delay_floor"), 0.4, 0.0, 10.0),
                "chunk_cap": cls._i(v.get("chunk_cap"), 300, 1, 50000),
                "workers_cap": cls._i(v.get("workers_cap"), 5, 1, 200),
            }
        if not provider_defaults:
            provider_defaults = dict((builtins.get("provider_defaults") or {}))
        if "other" not in provider_defaults and "*" in provider_defaults:
            provider_defaults["other"] = dict(provider_defaults["*"])
        if "*" not in provider_defaults and "other" in provider_defaults:
            provider_defaults["*"] = dict(provider_defaults["other"])

        wave_src = src.get("single_domain_wave") if isinstance(src.get("single_domain_wave"), dict) else {}
        wave_defaults = dict((builtins.get("single_domain_wave") or {}))
        wave = {
            "max_inflight": cls._i(wave_src.get("max_inflight"), wave_defaults.get("max_inflight", 1), 1, 10),
            "burst_tokens": cls._i(wave_src.get("burst_tokens"), wave_defaults.get("burst_tokens", 400), 1, 200000),
            "refill_per_sec": cls._f(wave_src.get("refill_per_sec"), wave_defaults.get("refill_per_sec", 3.0), 0.01, 200.0),
            "max_burst": cls._f(wave_src.get("max_burst"), wave_defaults.get("max_burst", 1200.0), 1.0, 500000.0),
            "max_refill": cls._f(wave_src.get("max_refill"), wave_defaults.get("max_refill", 10.0), 0.01, 500.0),
        }

        gov_src = src.get("resource_governor") if isinstance(src.get("resource_governor"), dict) else {}
        fallback_src = src.get("fallback") if isinstance(src.get("fallback"), dict) else {}
        fb_defaults = dict((builtins.get("fallback") or {}))
        return {
            "provider_defaults": provider_defaults,
            "single_domain_wave": wave,
            "resource_governor": {
                "max_total_workers": cls._i(gov_src.get("max_total_workers"), int((builtins.get("resource_governor") or {}).get("max_total_workers", 40)), 1, 10000),
            },
            "fallback": {
                "deferral_rate": cls._f(fallback_src.get("deferral_rate"), fb_defaults.get("deferral_rate", 0.35), 0.0, 1.0),
                "hardfail_rate": cls._f(fallback_src.get("hardfail_rate"), fb_defaults.get("hardfail_rate", 0.05), 0.0, 1.0),
                "timeout_rate": cls._f(fallback_src.get("timeout_rate"), fb_defaults.get("timeout_rate", 0.08), 0.0, 1.0),
            },
        }

    @classmethod
    def load(cls, packs_json: str, default_pack_name: str) -> dict:
        parsed = {}
        txt = str(packs_json or "").strip()
        if txt:
            try:
                candidate = json.loads(txt)
                if isinstance(candidate, dict):
                    parsed = candidate
            except Exception:
                parsed = {}
        out: Dict[str, dict] = {}
        for name, pack_raw in (parsed or {}).items():
            pname = str(name or "").strip().lower()
            if not pname:
                continue
            out[pname] = cls.validate_and_normalize(pack_raw)
        if not out:
            out = {"default": cls.validate_and_normalize(cls.BUILTIN_DEFAULT_PACK)}
        default_name = str(default_pack_name or "default").strip().lower() or "default"
        if default_name not in out:
            out[default_name] = cls.validate_and_normalize(out.get("default") or cls.BUILTIN_DEFAULT_PACK)
        if "default" not in out:
            out["default"] = cls.validate_and_normalize(out.get(default_name) or cls.BUILTIN_DEFAULT_PACK)
        return out


class PolicyPackApplier:
    def __init__(self, pack: dict, enforce: bool):
        self.pack = dict(pack or {})
        self.enforce = bool(enforce)

    def _provider_settings(self, provider_key: str) -> dict:
        defaults = dict(self.pack.get("provider_defaults") or {})
        p = str(provider_key or "").strip().lower()
        return dict(defaults.get(p) or defaults.get("other") or defaults.get("*") or {})

    def compute_recommendations(self, job_context: dict) -> dict:
        provider_keys = [str(x or "").strip().lower() for x in (job_context.get("provider_keys") or []) if str(x or "").strip()]
        providers = {k: self._provider_settings(k) for k in sorted(set(provider_keys))}
        return {
            "provider_defaults": providers,
            "single_domain_wave": dict(self.pack.get("single_domain_wave") or {}),
            "resource_governor": dict(self.pack.get("resource_governor") or {}),
            "fallback": dict(self.pack.get("fallback") or {}),
        }

    def apply_job_local_overrides(self, job_context: dict) -> dict:
        if not self.enforce:
            return {}
        applied: Dict[str, Any] = {"budget_manager": {}, "caps_resolver": {}, "wave": {}, "resource_governor": {}, "fallback": {}}
        provider_keys = [str(x or "").strip().lower() for x in (job_context.get("provider_keys") or []) if str(x or "").strip()]

        budget_config = job_context.get("budget_config")
        for provider_key in sorted(set(provider_keys)):
            pset = self._provider_settings(provider_key)
            if not pset:
                continue
            if budget_config is not None:
                cur_max = _coerce_scalar_number(
                    (budget_config.provider_max_inflight_map or {}).get(provider_key, budget_config.provider_max_inflight_default),
                    as_type="int",
                    default=budget_config.provider_max_inflight_default,
                )
                cur_gap = float((budget_config.provider_min_gap_s_map or {}).get(provider_key, budget_config.provider_min_gap_s_default))
                cur_cd = float((budget_config.provider_cooldown_s_map or {}).get(provider_key, budget_config.provider_cooldown_s_default))
                pset_max_inflight = _coerce_scalar_number(pset.get("max_inflight", cur_max), as_type="int", default=cur_max)
                budget_config.provider_max_inflight_map[provider_key] = min(int(cur_max), int(pset_max_inflight))
                budget_config.provider_min_gap_s_map[provider_key] = max(float(cur_gap), float(pset.get("min_gap_s", cur_gap)))
                budget_config.provider_cooldown_s_map[provider_key] = max(float(cur_cd), float(pset.get("cooldown_s", cur_cd)))
                applied["budget_manager"][provider_key] = {
                    "max_inflight": int(budget_config.provider_max_inflight_map[provider_key]),
                    "min_gap_s": float(budget_config.provider_min_gap_s_map[provider_key]),
                    "cooldown_s": float(budget_config.provider_cooldown_s_map[provider_key]),
                }

            caps_clamps = job_context.setdefault("policy_pack_caps_clamps", {})
            lane_clamp = dict(caps_clamps.get(provider_key) or {})
            if pset.get("chunk_cap") is not None:
                lane_chunk_cap = _coerce_scalar_number(lane_clamp.get("chunk_size_cap") or 50000, as_type="int", default=50000)
                pset_chunk_cap = _coerce_scalar_number(pset.get("chunk_cap") or 50000, as_type="int", default=50000)
                lane_clamp["chunk_size_cap"] = min(int(lane_chunk_cap), int(pset_chunk_cap))
            if pset.get("workers_cap") is not None:
                lane_workers_cap = _coerce_scalar_number(lane_clamp.get("workers_cap") or 200, as_type="int", default=200)
                pset_workers_cap = _coerce_scalar_number(pset.get("workers_cap") or 200, as_type="int", default=200)
                lane_clamp["workers_cap"] = min(int(lane_workers_cap), int(pset_workers_cap))
            if pset.get("delay_floor") is not None:
                lane_clamp["delay_floor"] = max(float(lane_clamp.get("delay_floor") or 0.0), float(pset.get("delay_floor") or 0.0))
            caps_clamps[provider_key] = lane_clamp
            applied["caps_resolver"][provider_key] = dict(lane_clamp)

        wave_controller = job_context.get("wave_controller")
        wave_cfg = dict(self.pack.get("single_domain_wave") or {})
        if wave_controller is not None and wave_cfg:
            wave_controller.burst_tokens = min(float(wave_controller.burst_tokens), float(wave_cfg.get("max_burst") or wave_cfg.get("burst_tokens") or wave_controller.burst_tokens))
            wave_controller.tokens_current = min(float(wave_controller.tokens_current), float(wave_controller.burst_tokens))
            wave_controller.refill_per_sec = min(float(wave_controller.refill_per_sec), float(wave_cfg.get("max_refill") or wave_cfg.get("refill_per_sec") or wave_controller.refill_per_sec))
            applied["wave"] = {
                "burst_tokens": float(wave_controller.burst_tokens),
                "refill_per_sec": float(wave_controller.refill_per_sec),
            }

        resource_governor = job_context.get("resource_governor")
        if resource_governor is not None:
            cfg = dict(self.pack.get("resource_governor") or {})
            if cfg.get("max_total_workers") is not None:
                governor_current = _coerce_scalar_number(resource_governor.max_total_workers, as_type="int", default=40)
                governor_cap = _coerce_scalar_number(cfg.get("max_total_workers") or governor_current, as_type="int", default=governor_current)
                resource_governor.max_total_workers = min(int(governor_current), int(governor_cap))
                applied["resource_governor"] = {"max_total_workers": int(resource_governor.max_total_workers)}

        fb_thresholds = job_context.get("fallback_thresholds")
        if isinstance(fb_thresholds, dict):
            fb_cfg = dict(self.pack.get("fallback") or {})
            if fb_cfg:
                for key in ("deferral_rate", "hardfail_rate", "timeout_rate"):
                    if key in fb_cfg and key in fb_thresholds:
                        fb_thresholds[key] = min(float(fb_thresholds.get(key) or 0.0), float(fb_cfg.get(key) or fb_thresholds.get(key) or 0.0))
                applied["fallback"] = {k: float(fb_thresholds.get(k) or 0.0) for k in ("deferral_rate", "hardfail_rate", "timeout_rate")}
        return applied


@dataclass
class ProviderPolicy:
    provider_max_inflight_suggested: Optional[int] = None
    provider_min_gap_s_suggested: Optional[float] = None
    provider_cooldown_s_suggested: Optional[float] = None
    delay_floor_s_suggested: Optional[float] = None
    chunk_cap_suggested: Optional[int] = None
    workers_cap_suggested: Optional[int] = None
    tier: str = "MIXED"
    confidence: float = 0.0
    attempts_total: int = 0
    reasons: List[str] = field(default_factory=list)


@dataclass
class LanePolicy:
    lane_state_bias: Optional[float] = None
    delay_floor_s: Optional[float] = None
    chunk_cap: Optional[int] = None
    workers_cap: Optional[int] = None
    confidence: float = 0.0
    tier: str = "MIXED"
    attempts_total: int = 0
    reasons: List[str] = field(default_factory=list)


@dataclass
class LearningPolicy:
    per_provider: Dict[str, ProviderPolicy] = field(default_factory=dict)
    per_lane: Dict[str, LanePolicy] = field(default_factory=dict)
    generated_ts: float = 0.0
    data_quality: Dict[str, Any] = field(default_factory=dict)


class LearningCapsEngine:
    def __init__(
        self,
        db_getter: Optional[Callable[[], sqlite3.Connection]] = None,
        refresh_s: int = 120,
        min_samples: int = 200,
        recency_days: int = 14,
        debug: bool = False,
    ):
        self.db_getter = db_getter or _db_conn
        self.refresh_s = max(10, int(refresh_s or 120))
        self.min_samples = max(1, int(min_samples or 200))
        self.recency_days = max(1, int(recency_days or 14))
        self.debug = bool(debug)
        self._last_refresh_ts = 0.0
        self._policy = LearningPolicy(generated_ts=time.time())

    def _clamp(self, val: Any, lo: float, hi: float, as_int: bool = False) -> Any:
        try:
            v = max(lo, min(hi, float(val)))
            return int(round(v)) if as_int else float(v)
        except Exception:
            return int(round(lo)) if as_int else float(lo)

    def _tier_for_rates(self, deferral_rate: float, hardfail_rate: float) -> Tuple[str, List[str]]:
        reasons: List[str] = []
        if hardfail_rate >= 0.04 or deferral_rate >= 0.40:
            reasons.append(f"severe_rates d={deferral_rate:.3f} h={hardfail_rate:.3f}")
            return "SLOW_OR_FAILING", reasons
        if hardfail_rate >= 0.02 or deferral_rate >= 0.25:
            reasons.append(f"degrading_rates d={deferral_rate:.3f} h={hardfail_rate:.3f}")
            return "DEGRADING", reasons
        if deferral_rate <= 0.08 and hardfail_rate <= 0.01:
            reasons.append(f"healthy_rates d={deferral_rate:.3f} h={hardfail_rate:.3f}")
            return "FAST_SUCCESS", reasons
        reasons.append(f"mixed_rates d={deferral_rate:.3f} h={hardfail_rate:.3f}")
        return "MIXED", reasons

    def _derive_lane_policy(self, attempts: int, deferrals: int, hardfails: int) -> LanePolicy:
        attempts_f = max(1, int(attempts or 0))
        d_rate = float(deferrals) / float(attempts_f)
        h_rate = float(hardfails) / float(attempts_f)
        tier, reasons = self._tier_for_rates(d_rate, h_rate)
        conf = min(1.0, float(attempts_f) / float(max(1, self.min_samples)))
        if attempts_f < self.min_samples:
            reasons.append("insufficient_samples")
            return LanePolicy(confidence=conf, tier=tier, attempts_total=attempts_f, reasons=reasons)
        if tier == "SLOW_OR_FAILING":
            return LanePolicy(lane_state_bias=0.2, delay_floor_s=2.0, chunk_cap=80, workers_cap=1, confidence=conf, tier=tier, attempts_total=attempts_f, reasons=reasons)
        if tier == "DEGRADING":
            return LanePolicy(lane_state_bias=0.4, delay_floor_s=1.2, chunk_cap=150, workers_cap=2, confidence=conf, tier=tier, attempts_total=attempts_f, reasons=reasons)
        if tier == "MIXED":
            return LanePolicy(lane_state_bias=0.8, delay_floor_s=0.8, chunk_cap=300, workers_cap=3, confidence=conf, tier=tier, attempts_total=attempts_f, reasons=reasons)
        return LanePolicy(lane_state_bias=1.0, delay_floor_s=0.5, chunk_cap=500, workers_cap=4, confidence=conf, tier=tier, attempts_total=attempts_f, reasons=reasons)

    def _provider_from_lane_policies(self, lane_rows: List[dict]) -> ProviderPolicy:
        attempts = sum(int(r.get("attempts") or 0) for r in lane_rows)
        deferrals = sum(int(r.get("deferrals") or 0) for r in lane_rows)
        hardfails = sum(int(r.get("hardfails") or 0) for r in lane_rows)
        lane_policy = self._derive_lane_policy(attempts, deferrals, hardfails)
        if attempts < self.min_samples:
            return ProviderPolicy(tier=lane_policy.tier, confidence=lane_policy.confidence, attempts_total=attempts, reasons=list(lane_policy.reasons))
        if lane_policy.tier == "SLOW_OR_FAILING":
            return ProviderPolicy(1, 15.0, 300.0, 2.0, 100, 1, lane_policy.tier, lane_policy.confidence, attempts, lane_policy.reasons)
        if lane_policy.tier == "DEGRADING":
            return ProviderPolicy(2, 8.0, 180.0, 1.2, 180, 2, lane_policy.tier, lane_policy.confidence, attempts, lane_policy.reasons)
        if lane_policy.tier == "MIXED":
            return ProviderPolicy(3, 3.0, 90.0, 0.8, 300, 3, lane_policy.tier, lane_policy.confidence, attempts, lane_policy.reasons)
        return ProviderPolicy(4, 1.0, 30.0, 0.4, 500, 4, lane_policy.tier, lane_policy.confidence, attempts, lane_policy.reasons)

    def compute_policy(self, job: Any, senders: List[str], providers: List[str]) -> LearningPolicy:
        providers_norm = sorted({str(p or "").strip().lower() for p in (providers or []) if str(p or "").strip()})
        sender_domains = sorted({_extract_domain_from_email(s) for s in (senders or []) if _extract_domain_from_email(s)})
        policy = LearningPolicy(generated_ts=time.time(), data_quality={"min_samples": self.min_samples, "recency_days": self.recency_days})
        if not providers_norm or not sender_domains:
            policy.data_quality["empty_scope"] = True
            return policy
        cutoff_iso = datetime.fromtimestamp(time.time() - (86400 * self.recency_days), tz=timezone.utc).isoformat().replace("+00:00", "Z")
        rows: List[Tuple[str, str, int, int, int]] = []
        with DB_LOCK:
            conn = self.db_getter()
            try:
                provider_ph = ",".join(["?"] * len(providers_norm))
                sender_ph = ",".join(["?"] * len(sender_domains))
                q = (
                    "SELECT sender_domain, provider_domain, "
                    "SUM(CASE WHEN lower(outcome) LIKE '%defer%' OR lower(outcome) LIKE '%4xx%' THEN 1 ELSE 0 END) AS deferrals, "
                    "SUM(CASE WHEN lower(outcome) LIKE '%fail%' OR lower(outcome) LIKE '%5xx%' THEN 1 ELSE 0 END) AS hardfails, "
                    "COUNT(*) AS attempts "
                    "FROM email_attempt_logs "
                    f"WHERE provider_domain IN ({provider_ph}) AND sender_domain IN ({sender_ph}) AND attempt_ts >= ? "
                    "GROUP BY sender_domain, provider_domain"
                )
                rows = conn.execute(q, providers_norm + sender_domains + [cutoff_iso]).fetchall()
            except Exception:
                rows = []
            finally:
                conn.close()
        lane_rows_by_provider: Dict[str, List[dict]] = {}
        for r in rows:
            sender_dom = str(r[0] or "").strip().lower()
            provider_dom = str(r[1] or "").strip().lower()
            deferrals = int(r[2] or 0)
            hardfails = int(r[3] or 0)
            attempts = int(r[4] or 0)
            lane_policy = self._derive_lane_policy(attempts, deferrals, hardfails)
            if lane_policy.delay_floor_s is not None:
                lane_policy.delay_floor_s = self._clamp(lane_policy.delay_floor_s, 0.2, 3.0)
            if lane_policy.chunk_cap is not None:
                lane_policy.chunk_cap = self._clamp(lane_policy.chunk_cap, 50, 1000, as_int=True)
            if lane_policy.workers_cap is not None:
                lane_policy.workers_cap = self._clamp(lane_policy.workers_cap, 1, 10, as_int=True)
            policy.per_lane[f"{sender_dom}|{provider_dom}"] = lane_policy
            lane_rows_by_provider.setdefault(provider_dom, []).append({"attempts": attempts, "deferrals": deferrals, "hardfails": hardfails})
        for provider_dom in providers_norm:
            p = self._provider_from_lane_policies(lane_rows_by_provider.get(provider_dom, []))
            if p.provider_max_inflight_suggested is not None:
                p.provider_max_inflight_suggested = self._clamp(p.provider_max_inflight_suggested, 1, 10, as_int=True)
            if p.provider_min_gap_s_suggested is not None:
                p.provider_min_gap_s_suggested = self._clamp(p.provider_min_gap_s_suggested, 0.0, 300.0)
            if p.provider_cooldown_s_suggested is not None:
                p.provider_cooldown_s_suggested = self._clamp(p.provider_cooldown_s_suggested, 0.0, 3600.0)
            if p.delay_floor_s_suggested is not None:
                p.delay_floor_s_suggested = self._clamp(p.delay_floor_s_suggested, 0.2, 3.0)
            if p.chunk_cap_suggested is not None:
                p.chunk_cap_suggested = self._clamp(p.chunk_cap_suggested, 50, 1000, as_int=True)
            if p.workers_cap_suggested is not None:
                p.workers_cap_suggested = self._clamp(p.workers_cap_suggested, 1, 10, as_int=True)
            policy.per_provider[provider_dom] = p
        return policy

    def refresh_if_needed(self, now_ts: float, job: Any, senders: List[str], providers: List[str]) -> None:
        now = float(now_ts or time.time())
        if self._last_refresh_ts > 0 and (now - self._last_refresh_ts) < float(self.refresh_s):
            return
        self._policy = self.compute_policy(job, senders, providers)
        self._last_refresh_ts = now

    def get_provider_policy(self, provider_domain: str) -> Optional[ProviderPolicy]:
        return self._policy.per_provider.get(str(provider_domain or "").strip().lower())

    def get_lane_policy(self, lane_key: str) -> Optional[LanePolicy]:
        return self._policy.per_lane.get(str(lane_key or "").strip().lower())

    def snapshot(self) -> dict:
        return {
            "generated_ts": float(self._policy.generated_ts or 0.0),
            "refresh_s": int(self.refresh_s),
            "last_refresh_age_s": max(0.0, time.time() - float(self._last_refresh_ts or 0.0)) if self._last_refresh_ts else None,
            "data_quality": dict(self._policy.data_quality or {}),
            "providers": {
                k: {
                    "provider_max_inflight_suggested": v.provider_max_inflight_suggested,
                    "provider_min_gap_s_suggested": v.provider_min_gap_s_suggested,
                    "provider_cooldown_s_suggested": v.provider_cooldown_s_suggested,
                    "delay_floor_s_suggested": v.delay_floor_s_suggested,
                    "chunk_cap_suggested": v.chunk_cap_suggested,
                    "workers_cap_suggested": v.workers_cap_suggested,
                    "tier": v.tier,
                    "confidence": v.confidence,
                    "attempts_total": v.attempts_total,
                    "reasons": list(v.reasons or []),
                }
                for k, v in sorted((self._policy.per_provider or {}).items())
            },
            "lanes": {
                k: {
                    "lane_state_bias": v.lane_state_bias,
                    "delay_floor_s": v.delay_floor_s,
                    "chunk_cap": v.chunk_cap,
                    "workers_cap": v.workers_cap,
                    "confidence": v.confidence,
                    "tier": v.tier,
                    "attempts_total": v.attempts_total,
                    "reasons": list(v.reasons or []),
                }
                for k, v in sorted((self._policy.per_lane or {}).items())
            },
        }


class BudgetManager:
    """Job-scoped budget gate for lane start decisions (sequential today, concurrency-ready)."""

    def __init__(self, config: BudgetConfig, lane_registry: Optional[LaneRegistry] = None, debug: bool = False, provider_key_resolver: Optional[Callable[[Tuple[int, str]], Tuple[int, str]]] = None):
        self.config = config or BudgetConfig()
        self.lane_registry = lane_registry
        self.debug = bool(debug)
        self.inflight_by_provider: Dict[str, int] = {}
        self.inflight_by_sender: Dict[int, int] = {}
        self.provider_last_start_ts: Dict[str, float] = {}
        self.provider_cooldown_until: Dict[str, float] = {}
        self.lane_inflight: Dict[str, bool] = {}
        self.last_denied_reasons: List[dict] = []
        self.provider_max_inflight_overrides: Dict[str, int] = {}
        self.external_gates: Dict[str, Callable[[Tuple[int, str], float, bool, bool, Optional[int]], Tuple[bool, str]]] = {}
        self.provider_key_resolver = provider_key_resolver

    def _resolved_lane_key(self, lane_key: Tuple[int, str]) -> Tuple[int, str]:
        base = (int((lane_key or (0, ""))[0] or 0), str((lane_key or (0, ""))[1] or "").strip().lower())
        if not callable(self.provider_key_resolver):
            return base
        try:
            resolved = self.provider_key_resolver(base)
            return (int((resolved or base)[0] or 0), str((resolved or base)[1] or "").strip().lower())
        except Exception:
            return base

    def _lane_id(self, lane_key: Tuple[int, str]) -> str:
        rk = self._resolved_lane_key(lane_key)
        return f"{int(rk[0])}|{str(rk[1] or '').strip().lower()}"

    def _provider_name(self, provider_domain: str) -> str:
        return str(provider_domain or "").strip().lower()

    def _int_provider_value(self, provider_domain: str, mapping: Dict[str, int], default_v: int) -> int:
        p = self._provider_name(provider_domain)
        return int(mapping.get(p, mapping.get("*", default_v)))

    def _float_provider_value(self, provider_domain: str, mapping: Dict[str, float], default_v: float) -> float:
        p = self._provider_name(provider_domain)
        return float(mapping.get(p, mapping.get("*", default_v)))

    def provider_max_inflight(self, provider_domain: str) -> int:
        p = self._provider_name(provider_domain)
        if p in self.provider_max_inflight_overrides:
            return max(1, min(10, int(self.provider_max_inflight_overrides.get(p) or 1)))
        return max(1, min(10, self._int_provider_value(provider_domain, self.config.provider_max_inflight_map, self.config.provider_max_inflight_default)))

    def set_provider_max_inflight_override(self, provider_domain: str, value: int) -> None:
        p = self._provider_name(provider_domain)
        if not p:
            return
        self.provider_max_inflight_overrides[p] = max(1, min(10, int(value or 1)))

    def register_external_gate(
        self,
        name: str,
        gate_callable: Callable[[Tuple[int, str], float, bool, bool, Optional[int]], Tuple[bool, str]],
    ) -> None:
        gate_name = str(name or "").strip().lower()
        if not gate_name or not callable(gate_callable):
            return
        self.external_gates[gate_name] = gate_callable

    def provider_min_gap(self, provider_domain: str) -> float:
        return max(0.0, min(3600.0, self._float_provider_value(provider_domain, self.config.provider_min_gap_s_map, self.config.provider_min_gap_s_default)))

    def provider_cooldown_s(self, provider_domain: str) -> float:
        return max(0.0, min(3600.0, self._float_provider_value(provider_domain, self.config.provider_cooldown_s_map, self.config.provider_cooldown_s_default)))

    def _push_denial(self, lane_key: Tuple[int, str], reason: str, now_ts: float) -> None:
        self.last_denied_reasons.append({
            "ts": float(now_ts or time.time()),
            "lane": self._lane_id(lane_key),
            "reason": str(reason or "denied"),
        })
        if len(self.last_denied_reasons) > 10:
            self.last_denied_reasons = self.last_denied_reasons[-10:]

    def can_start(self, lane_key: Tuple[int, str], now_ts: float, is_retry: bool, is_probe: bool, planned_chunk_size_hint: Optional[int] = None) -> Tuple[bool, str]:
        if not self.config.enabled:
            return True, "disabled"
        resolved_lane_key = self._resolved_lane_key(lane_key)
        sender_idx = int((resolved_lane_key or (0, ""))[0] or 0)
        provider_domain = self._provider_name((resolved_lane_key or (0, ""))[1])

        if self.lane_registry:
            lane_info = self.lane_registry.get_lane_info((sender_idx, provider_domain))
            lane_state = str(lane_info.get("state") or "HEALTHY")
            lane_next_allowed = float(lane_info.get("next_allowed_ts") or 0.0)
            if lane_state in {"QUARANTINED", "INFRA_FAIL"} and float(now_ts or 0.0) < lane_next_allowed:
                self._push_denial((sender_idx, provider_domain), "lane_quarantine_until", now_ts)
                return False, "lane_quarantine_until"

        cooldown_until = float(self.provider_cooldown_until.get(provider_domain) or 0.0)
        if float(now_ts or 0.0) < cooldown_until:
            self._push_denial((sender_idx, provider_domain), "provider_cooldown_until", now_ts)
            return False, "provider_cooldown_until"

        min_gap = self.provider_min_gap(provider_domain)
        if min_gap > 0.0:
            last_start_ts = float(self.provider_last_start_ts.get(provider_domain) or 0.0)
            if last_start_ts > 0.0 and (float(now_ts or 0.0) - last_start_ts) < min_gap:
                self._push_denial((sender_idx, provider_domain), "provider_min_gap", now_ts)
                return False, "provider_min_gap"

        if int(self.inflight_by_provider.get(provider_domain) or 0) >= int(self.provider_max_inflight(provider_domain)):
            self._push_denial((sender_idx, provider_domain), "provider_inflight_cap", now_ts)
            return False, "provider_inflight_cap"
        if int(self.inflight_by_sender.get(sender_idx) or 0) >= int(max(1, min(10, self.config.sender_max_inflight))):
            self._push_denial((sender_idx, provider_domain), "sender_inflight_cap", now_ts)
            return False, "sender_inflight_cap"
        for gate_name, gate_fn in self.external_gates.items():
            try:
                allowed, reason = gate_fn((sender_idx, provider_domain), now_ts, bool(is_retry), bool(is_probe), planned_chunk_size_hint)
            except Exception:
                allowed, reason = True, "allow"
            if not allowed:
                denied_reason = str(reason or f"{gate_name}_denied")
                self._push_denial((sender_idx, provider_domain), denied_reason, now_ts)
                return False, denied_reason
        return True, "allow"

    def on_start(self, lane_key: Tuple[int, str], now_ts: float) -> None:
        if not self.config.enabled:
            return
        resolved_lane_key = self._resolved_lane_key(lane_key)
        sender_idx = int((resolved_lane_key or (0, ""))[0] or 0)
        provider_domain = self._provider_name((resolved_lane_key or (0, ""))[1])
        self.inflight_by_provider[provider_domain] = int(self.inflight_by_provider.get(provider_domain) or 0) + 1
        self.inflight_by_sender[sender_idx] = int(self.inflight_by_sender.get(sender_idx) or 0) + 1
        self.provider_last_start_ts[provider_domain] = float(now_ts or time.time())
        self.lane_inflight[self._lane_id((sender_idx, provider_domain))] = True

    def on_finish(self, lane_key: Tuple[int, str], now_ts: float) -> None:
        if not self.config.enabled:
            return
        resolved_lane_key = self._resolved_lane_key(lane_key)
        sender_idx = int((resolved_lane_key or (0, ""))[0] or 0)
        provider_domain = self._provider_name((resolved_lane_key or (0, ""))[1])
        self.inflight_by_provider[provider_domain] = max(0, int(self.inflight_by_provider.get(provider_domain) or 0) - 1)
        self.inflight_by_sender[sender_idx] = max(0, int(self.inflight_by_sender.get(sender_idx) or 0) - 1)
        self.lane_inflight[self._lane_id((sender_idx, provider_domain))] = False

    def on_lane_state_signal(self, lane_key: Tuple[int, str], state: str, now_ts: float, failure_type: Optional[str] = None) -> None:
        if not self.config.enabled:
            return
        resolved_lane_key = self._resolved_lane_key(lane_key)
        provider_domain = self._provider_name((resolved_lane_key or (0, ""))[1])
        state_v = str(state or "").strip().upper()
        severe_failure = str(failure_type or "").strip().lower()
        severe = state_v in {"QUARANTINED", "INFRA_FAIL"} or severe_failure in {"infra", "timeout", "network", "connection"}
        if not severe:
            return
        cooldown_s = self.provider_cooldown_s(provider_domain)
        if cooldown_s <= 0:
            return
        self.provider_cooldown_until[provider_domain] = max(
            float(self.provider_cooldown_until.get(provider_domain) or 0.0),
            float(now_ts or time.time()) + float(cooldown_s),
        )

    def clone_for_shadow(self) -> 'BudgetManager':
        cloned = BudgetManager(self.config, lane_registry=self.lane_registry, debug=self.debug, provider_key_resolver=self.provider_key_resolver)
        cloned.inflight_by_provider = dict(self.inflight_by_provider)
        cloned.inflight_by_sender = dict(self.inflight_by_sender)
        cloned.provider_last_start_ts = dict(self.provider_last_start_ts)
        cloned.provider_cooldown_until = dict(self.provider_cooldown_until)
        cloned.lane_inflight = dict(self.lane_inflight)
        cloned.provider_max_inflight_overrides = dict(self.provider_max_inflight_overrides)
        cloned.external_gates = dict(self.external_gates)
        return cloned

    def snapshot(self) -> dict:
        return {
            "enabled": bool(self.config.enabled),
            "inflight_by_provider": {k: int(v) for k, v in sorted(self.inflight_by_provider.items()) if int(v) != 0},
            "inflight_by_sender": {str(k): int(v) for k, v in sorted(self.inflight_by_sender.items(), key=lambda x: x[0]) if int(v) != 0},
            "provider_last_start_ts": {k: float(v) for k, v in sorted(self.provider_last_start_ts.items())},
            "provider_cooldown_until": {k: float(v) for k, v in sorted(self.provider_cooldown_until.items()) if float(v) > 0.0},
            "provider_max_inflight_overrides": {k: int(v) for k, v in sorted(self.provider_max_inflight_overrides.items())},
            "lane_inflight": {k: bool(v) for k, v in sorted(self.lane_inflight.items()) if bool(v)},
            "external_gates": sorted(self.external_gates.keys()),
            "last_denied_reasons": list(self.last_denied_reasons[-10:]),
        }


class WaveController:
    """Single-provider deterministic token-bucket gate (job-scoped)."""

    def __init__(self, enabled: bool, provider_domain: str, burst_tokens: float, refill_per_sec: float, min_tokens_to_start_chunk: int, adaptive_config: dict, stagger_config: dict):
        self.enabled = bool(enabled)
        self.provider_domain = str(provider_domain or "").strip().lower()
        self.burst_tokens = float(max(1.0, burst_tokens or 1.0))
        self.refill_per_sec = float(max(0.01, refill_per_sec or 0.01))
        self.min_tokens_to_start_chunk = max(1, int(min_tokens_to_start_chunk or 1))
        self.token_cost_per_msg = max(1, int((adaptive_config or {}).get("token_cost_per_msg") or 1))
        self.tokens_current = float(self.burst_tokens)
        self.last_refill_ts = 0.0
        self.job_start_ts = 0.0
        self.sender_offsets: Dict[int, float] = {}
        self.adaptive = dict(adaptive_config or {})
        self.stagger = dict(stagger_config or {})
        self.last_adjustment_reason = ""
        self.deny_reasons: Dict[str, int] = {}

    def start(self, job_start_ts: float, num_senders: int, partition_seed: str) -> None:
        self.job_start_ts = float(job_start_ts or time.time())
        self.last_refill_ts = self.job_start_ts
        self.tokens_current = float(self.burst_tokens)
        self.sender_offsets = {}
        if not self.enabled:
            return
        step_s = max(0.0, float(self.stagger.get("step_s") or 0.0))
        stagger_enabled = bool(self.stagger.get("enabled", True))
        seed_mode = str(self.stagger.get("seed_mode") or "job").strip().lower()
        for sender_idx in range(max(0, int(num_senders or 0))):
            base_offset = float(sender_idx) * step_s if stagger_enabled else 0.0
            jitter = 0.0
            if stagger_enabled and seed_mode == "job":
                h = hashlib.sha256(f"{str(partition_seed or '')}|{sender_idx}".encode("utf-8")).hexdigest()
                jitter = (int(h[:6], 16) % 1000) / 1000.0
            self.sender_offsets[sender_idx] = base_offset + jitter

    def tokens_available(self, now_ts: float) -> float:
        if not self.enabled:
            return float("inf")
        now = float(now_ts or time.time())
        if self.last_refill_ts <= 0:
            self.last_refill_ts = now
            return self.tokens_current
        elapsed = max(0.0, now - self.last_refill_ts)
        if elapsed > 0:
            self.tokens_current = min(float(self.burst_tokens), float(self.tokens_current) + (elapsed * float(self.refill_per_sec)))
            self.last_refill_ts = now
        return self.tokens_current

    def next_allowed_ts_for_sender(self, sender_idx: int) -> float:
        return float(self.job_start_ts) + float(self.sender_offsets.get(int(sender_idx or 0), 0.0))

    def _inc_deny(self, reason: str) -> None:
        r = str(reason or "denied")
        self.deny_reasons[r] = int(self.deny_reasons.get(r) or 0) + 1

    def can_start_lane(self, lane_key: Tuple[int, str], now_ts: float, planned_chunk_size: int) -> Tuple[bool, str]:
        if not self.enabled:
            return True, "disabled"
        provider = str((lane_key or (0, ""))[1] or "").strip().lower()
        if provider != self.provider_domain:
            return True, "provider_mismatch"
        sender_idx = int((lane_key or (0, ""))[0] or 0)
        now = float(now_ts or time.time())
        if bool(self.stagger.get("enabled", True)) and now < self.next_allowed_ts_for_sender(sender_idx):
            self._inc_deny("stagger_wait")
            return False, "stagger_wait"
        planned_cost = max(1, int(planned_chunk_size or 1)) * int(self.token_cost_per_msg)
        required = max(int(self.min_tokens_to_start_chunk), planned_cost)
        if self.tokens_available(now) < float(required):
            self._inc_deny("wave_tokens")
            return False, "wave_tokens"
        return True, "allow"

    def reserve_tokens(self, lane_key: Tuple[int, str], now_ts: float, planned_cost: int) -> None:
        if not self.enabled:
            return
        provider = str((lane_key or (0, ""))[1] or "").strip().lower()
        if provider != self.provider_domain:
            return
        available = self.tokens_available(now_ts)
        cost = max(0, int(planned_cost or 0))
        self.tokens_current = max(0.0, min(float(self.burst_tokens), float(available) - float(cost)))

    def release_tokens_partial(self, lane_key: Tuple[int, str], now_ts: float, unused_cost: int) -> None:
        if not self.enabled:
            return
        provider = str((lane_key or (0, ""))[1] or "").strip().lower()
        if provider != self.provider_domain:
            return
        self.tokens_available(now_ts)
        self.tokens_current = min(float(self.burst_tokens), float(self.tokens_current) + float(max(0, int(unused_cost or 0))))

    def on_feedback(self, now_ts: float, provider_metrics_snapshot: dict) -> None:
        if not (self.enabled and bool(self.adaptive.get("enabled", True))):
            return
        d_rate = float((provider_metrics_snapshot or {}).get("deferral_rate") or 0.0)
        h_rate = float((provider_metrics_snapshot or {}).get("hardfail_rate") or 0.0)
        self.tokens_available(now_ts)
        ramp_up = float(self.adaptive.get("ramp_up_factor") or 1.0)
        ramp_down = float(self.adaptive.get("ramp_down_factor") or 1.0)
        min_refill = float(self.adaptive.get("min_refill") or 0.5)
        max_refill = float(self.adaptive.get("max_refill") or 10.0)
        min_burst = float(self.adaptive.get("min_burst") or 100.0)
        max_burst = float(self.adaptive.get("max_burst") or 1200.0)
        if d_rate > float(self.adaptive.get("deferral_down") or 0.2) or h_rate > float(self.adaptive.get("hardfail_down") or 0.03):
            self.refill_per_sec = max(min_refill, min(max_refill, float(self.refill_per_sec) * ramp_down))
            self.burst_tokens = max(min_burst, min(max_burst, float(self.burst_tokens) * ramp_down))
            self.tokens_current = min(float(self.tokens_current), float(self.burst_tokens))
            self.last_adjustment_reason = "ramp_down"
        elif d_rate < float(self.adaptive.get("deferral_up") or 0.1) and h_rate <= max(0.0, float(self.adaptive.get("hardfail_down") or 0.03) * 0.5):
            self.refill_per_sec = max(min_refill, min(max_refill, float(self.refill_per_sec) * ramp_up))
            self.burst_tokens = max(min_burst, min(max_burst, float(self.burst_tokens) * (1.0 + (ramp_up - 1.0) * 0.5)))
            self.last_adjustment_reason = "ramp_up"

    def snapshot(self) -> dict:
        return {
            "enabled": bool(self.enabled),
            "provider_domain": str(self.provider_domain),
            "tokens_current": float(self.tokens_current),
            "burst_tokens": float(self.burst_tokens),
            "refill_per_sec": float(self.refill_per_sec),
            "min_tokens_to_start_chunk": int(self.min_tokens_to_start_chunk),
            "token_cost_per_msg": int(self.token_cost_per_msg),
            "last_adjustment_reason": str(self.last_adjustment_reason),
            "next_allowed_ts_by_sender": {str(k): self.next_allowed_ts_for_sender(k) for k in sorted(self.sender_offsets.keys())},
            "deny_reasons": {k: int(v) for k, v in sorted(self.deny_reasons.items())},
        }


class LanePickerV2:
    """Sequential lane selector (sender_idx, provider_domain) with retry priority."""

    def __init__(
        self,
        scheduler_rng: random.Random,
        lane_registry: Optional[LaneRegistry] = None,
        budget_mgr: Optional[BudgetManager] = None,
        debug: bool = False,
        export_debug: bool = False,
        respect_lane_states: bool = True,
        use_budgets: bool = True,
        use_soft_bias: bool = True,
        max_scan: int = 50,
        lane_weight_multiplier: Optional[Callable[[Tuple[int, str]], float]] = None,
        debug_log: Optional[Callable[[str], None]] = None,
    ):
        self.scheduler_rng = scheduler_rng
        self.lane_registry = lane_registry
        self.budget_mgr = budget_mgr
        self.debug = bool(debug)
        self.export_debug = bool(export_debug)
        self.respect_lane_states = bool(respect_lane_states)
        self.use_budgets = bool(use_budgets)
        self.use_soft_bias = bool(use_soft_bias)
        self.max_scan = max(1, int(max_scan or 50))
        self._lane_weight_multiplier = lane_weight_multiplier
        self._debug_log = debug_log

    def _lane_key(self, sender_idx: int, provider_domain: str) -> Tuple[int, str]:
        return (int(sender_idx or 0), str(provider_domain or "").strip().lower())

    def _denied(self, meta: dict, lane_key: Tuple[int, str], reason: str) -> None:
        denied = meta.setdefault("denied_reasons", [])
        denied.append({"lane": f"{int(lane_key[0])}|{str(lane_key[1])}", "reason": str(reason or "denied")})

    def _state_denied_reason(self, lane_key: Tuple[int, str], now_ts: float) -> Optional[str]:
        if not (self.respect_lane_states and self.lane_registry):
            return None
        lane_info = self.lane_registry.get_lane_info(lane_key)
        lane_state = str(lane_info.get("state") or "HEALTHY")
        next_allowed_ts = float(lane_info.get("next_allowed_ts") or 0.0)
        if lane_state in {"QUARANTINED", "INFRA_FAIL"} and float(now_ts or 0.0) < next_allowed_ts:
            return "lane_quarantine_until"
        return None

    def _budget_denied_reason(self, lane_key: Tuple[int, str], now_ts: float, is_retry: bool, is_probe: bool) -> Optional[str]:
        if not (self.use_budgets and self.budget_mgr):
            return None
        allowed, reason = self.budget_mgr.can_start(lane_key, now_ts, is_retry, is_probe)
        if allowed:
            return None
        return str(reason or "budget_denied")

    def _retry_domains_for_sender(self, sender_idx: int, provider_retry_chunks: Dict[str, List[dict]]) -> List[str]:
        pref = f"{int(sender_idx)}|"
        out: List[str] = []
        for k in (provider_retry_chunks or {}).keys():
            sk = str(k or "")
            if not sk.startswith(pref):
                continue
            _, _, dom = sk.partition("|")
            dom2 = str(dom or "").strip().lower()
            if dom2:
                out.append(dom2)
        return out

    def pick_next(
        self,
        now_ts: float,
        sender_cursor: int,
        sender_buckets: Dict[int, Dict[str, List[str]]],
        provider_retry_chunks: Dict[str, List[dict]],
        probe_active: bool = False,
    ) -> Tuple[Optional[Tuple[int, str]], dict]:
        n = max(0, len(sender_buckets or {}))
        meta: Dict[str, Any] = {
            "pick_type": "none",
            "sender_idx": None,
            "provider_domain": None,
            "scanned_senders_count": 0,
            "scanned_candidates_count": 0,
        }
        if n <= 0:
            return None, meta

        for step in range(n):
            sidx = (int(sender_cursor or 0) + step) % n
            meta["scanned_senders_count"] = int(meta["scanned_senders_count"] or 0) + 1
            for dom in self._retry_domains_for_sender(sidx, provider_retry_chunks):
                lane_key = self._lane_key(sidx, dom)
                retry_q = provider_retry_chunks.get(f"{sidx}|{dom}") or []
                if not retry_q or float(retry_q[0].get("next_retry_ts") or 0.0) > float(now_ts or 0.0):
                    continue
                meta["scanned_candidates_count"] = int(meta["scanned_candidates_count"] or 0) + 1
                deny_state = self._state_denied_reason(lane_key, now_ts)
                if deny_state:
                    self._denied(meta, lane_key, deny_state)
                    continue
                deny_budget = self._budget_denied_reason(lane_key, now_ts, True, bool(probe_active))
                if deny_budget:
                    self._denied(meta, lane_key, deny_budget)
                    continue
                meta.update({"pick_type": "retry", "sender_idx": sidx, "provider_domain": dom})
                if self.debug and callable(self._debug_log):
                    self._debug_log(f"LanePickerV2 pick retry lane={sidx}|{dom}")
                return lane_key, meta

        for step in range(n):
            sidx = (int(sender_cursor or 0) + step) % n
            domains = sender_buckets.get(sidx) or {}
            weighted_int: List[Tuple[str, int]] = []
            weighted_float: List[Tuple[str, float]] = []
            scanned_for_sender = 0
            for d, v in domains.items():
                if scanned_for_sender >= self.max_scan:
                    break
                scanned_for_sender += 1
                remaining = len(v or [])
                if remaining <= 0:
                    continue
                dom = str(d or "").strip().lower()
                lane_key = self._lane_key(sidx, dom)
                meta["scanned_candidates_count"] = int(meta["scanned_candidates_count"] or 0) + 1
                deny_state = self._state_denied_reason(lane_key, now_ts)
                if deny_state:
                    self._denied(meta, lane_key, deny_state)
                    continue
                deny_budget = self._budget_denied_reason(lane_key, now_ts, False, bool(probe_active))
                if deny_budget:
                    self._denied(meta, lane_key, deny_budget)
                    continue
                if not self.use_soft_bias:
                    weighted_int.append((dom, remaining))
                    continue
                mul = 1.0
                if callable(self._lane_weight_multiplier):
                    mul = float(self._lane_weight_multiplier(lane_key))
                adjusted = float(remaining) * max(0.0, float(mul))
                if adjusted < 0.01:
                    self._denied(meta, lane_key, "weight_too_low")
                    continue
                weighted_float.append((dom, adjusted))

            if not self.use_soft_bias:
                if not weighted_int:
                    continue
                total_weight = sum(w for _, w in weighted_int)
                if total_weight <= 0:
                    continue
                draw = self.scheduler_rng.randint(1, total_weight)
                acc = 0
                selected_dom = weighted_int[-1][0]
                for dom, w in weighted_int:
                    acc += w
                    if draw <= acc:
                        selected_dom = dom
                        break
                lane_key = self._lane_key(sidx, selected_dom)
                meta.update({"pick_type": "weighted", "sender_idx": sidx, "provider_domain": selected_dom})
                if self.debug and callable(self._debug_log):
                    self._debug_log(f"LanePickerV2 pick weighted lane={sidx}|{selected_dom}")
                return lane_key, meta

            if not weighted_float:
                continue
            total_weight_f = sum(w for _, w in weighted_float)
            if total_weight_f <= 0.0:
                continue
            draw_f = self.scheduler_rng.random() * total_weight_f
            acc_f = 0.0
            selected_dom_f = weighted_float[-1][0]
            for dom, w in weighted_float:
                acc_f += w
                if draw_f <= acc_f:
                    selected_dom_f = dom
                    break
            lane_key = self._lane_key(sidx, selected_dom_f)
            meta.update({"pick_type": "weighted", "sender_idx": sidx, "provider_domain": selected_dom_f})
            if self.debug and callable(self._debug_log):
                self._debug_log(f"LanePickerV2 pick weighted lane={sidx}|{selected_dom_f}")
            return lane_key, meta

        if self.debug and callable(self._debug_log):
            self._debug_log("LanePickerV2 pick none")
        return None, meta


class ProbeController:
    """Job-scoped probe mode controller to sample early lane signals conservatively."""

    def __init__(self, enabled: bool, duration_s: int, rounds: int, probe_caps: dict, min_providers: int):
        self.enabled = bool(enabled)
        self.duration_s = max(1, int(duration_s or 1))
        self.max_rounds = max(1, int(rounds or 1))
        self.probe_caps = dict(probe_caps or {})
        self.min_providers = max(1, int(min_providers or 1))
        self.probe_start_ts = 0.0
        self.rounds_completed = 0
        self.round_target = 0
        self.per_round_used_providers: Set[str] = set()
        self.per_round_used_senders: Set[int] = set()
        self.total_probed_by_provider: Dict[str, int] = {}
        self.total_probed_by_sender: Dict[int, int] = {}
        self.probe_active = False

    def start(self, job_start_ts: float, provider_domains: List[str], num_senders: int) -> None:
        providers = sorted({str(d or "").strip().lower() for d in (provider_domains or []) if str(d or "").strip()})
        self.round_target = max(1, min(max(1, int(num_senders or 1)), len(providers)))
        self.probe_start_ts = float(job_start_ts or time.time())
        self.rounds_completed = 0
        self.per_round_used_providers = set()
        self.per_round_used_senders = set()
        self.total_probed_by_provider = {}
        self.total_probed_by_sender = {}
        self.probe_active = self.should_probe(provider_domains)

    def should_probe(self, provider_domains: List[str]) -> bool:
        providers = {str(d or "").strip().lower() for d in (provider_domains or []) if str(d or "").strip()}
        return bool(self.enabled and len(providers) >= self.min_providers)

    def stop(self) -> None:
        self.probe_active = False

    def is_active(self, now_ts: float) -> bool:
        if not self.probe_active:
            return False
        if self.rounds_completed >= self.max_rounds:
            self.probe_active = False
            return False
        if (float(now_ts or 0.0) - float(self.probe_start_ts or 0.0)) >= float(self.duration_s):
            self.probe_active = False
            return False
        return True

    def _advance_round_if_needed(self) -> None:
        if len(self.per_round_used_providers) < max(1, self.round_target):
            return
        self.rounds_completed += 1
        self.per_round_used_providers = set()
        self.per_round_used_senders = set()
        if self.rounds_completed >= self.max_rounds:
            self.probe_active = False

    def pick_probe_lane(
        self,
        now_ts: float,
        sender_buckets: Dict[int, Dict[str, List[str]]],
        lane_registry: Optional[LaneRegistry],
        soft_budgets: Optional[dict],
        budget_can_start: Optional[Callable[[Tuple[int, str], float, bool, bool], Tuple[bool, str]]],
        sender_cursor: int,
    ) -> Optional[Tuple[int, str]]:
        if not self.is_active(now_ts):
            return None
        n = max(0, len(sender_buckets or {}))
        if n <= 0:
            return None
        blocked_fn = (soft_budgets or {}).get("is_lane_temporarily_blocked") if isinstance(soft_budgets, dict) else None
        for strict_diversity in (True, False):
            for step in range(n):
                sender_idx = (int(sender_cursor or 0) + step) % n
                domains = sender_buckets.get(sender_idx) or {}
                if strict_diversity and sender_idx in self.per_round_used_senders:
                    continue
                for provider_domain in sorted(domains.keys()):
                    bucket = domains.get(provider_domain) or []
                    if not bucket:
                        continue
                    provider = str(provider_domain or "").strip().lower()
                    if strict_diversity and provider in self.per_round_used_providers:
                        continue
                    lane_key = (int(sender_idx), provider)
                    if callable(blocked_fn) and blocked_fn(lane_key, now_ts):
                        continue
                    if callable(budget_can_start):
                        allowed, _reason = budget_can_start(lane_key, now_ts, False, True)
                        if not allowed:
                            continue
                    if lane_registry:
                        lane_info = lane_registry.get_lane_info(lane_key)
                        if float(lane_info.get("next_allowed_ts") or 0.0) > float(now_ts or 0.0):
                            continue
                    return lane_key
            if strict_diversity and self.per_round_used_providers:
                self.rounds_completed += 1
                self.per_round_used_providers = set()
                self.per_round_used_senders = set()
                if self.rounds_completed >= self.max_rounds:
                    self.probe_active = False
                    return None
        return None

    def mark_probed(self, lane_key: Tuple[int, str]) -> None:
        provider = str((lane_key or (0, ""))[1] or "").strip().lower()
        sender_idx = int((lane_key or (0, ""))[0] or 0)
        self.per_round_used_providers.add(provider)
        self.per_round_used_senders.add(sender_idx)
        self.total_probed_by_provider[provider] = int(self.total_probed_by_provider.get(provider) or 0) + 1
        self.total_probed_by_sender[sender_idx] = int(self.total_probed_by_sender.get(sender_idx) or 0) + 1
        self._advance_round_if_needed()

    def apply_probe_caps(self, caps: dict) -> dict:
        out = dict(caps or {})
        out["chunk_size"] = max(1, min(int(out.get("chunk_size") or 1), int(self.probe_caps.get("chunk_size") or 1)))
        out["workers"] = max(1, min(int(out.get("workers") or 1), int(self.probe_caps.get("workers") or 1)))
        out["delay_s"] = max(float(out.get("delay_s") or 0.0), float(self.probe_caps.get("delay_floor_s") or 0.0))
        out["sleep_chunks"] = max(float(out.get("sleep_chunks") or 0.0), float(self.probe_caps.get("sleep_floor_s") or 0.0))
        return out

    def snapshot(self) -> dict:
        return {
            "enabled": bool(self.enabled),
            "active": bool(self.probe_active),
            "probe_start_ts": float(self.probe_start_ts or 0.0),
            "duration_s": int(self.duration_s),
            "max_rounds": int(self.max_rounds),
            "rounds_completed": int(self.rounds_completed),
            "round_target": int(self.round_target),
            "per_round_used_providers": sorted(self.per_round_used_providers),
            "per_round_used_senders": sorted(self.per_round_used_senders),
            "total_probed_by_provider": {k: int(v) for k, v in sorted(self.total_probed_by_provider.items())},
            "total_probed_by_sender": {str(k): int(v) for k, v in sorted(self.total_probed_by_sender.items(), key=lambda x: x[0])},
            "probe_caps": dict(self.probe_caps),
            "min_providers": int(self.min_providers),
        }


def clamp_caps_to_bounds(caps: dict, bounds_override: Optional[dict] = None) -> dict:
    def _num(v: Any, *, as_type: str, default: Any) -> Any:
        return _coerce_scalar_number(v, as_type=as_type, default=default)

    out = dict(caps or {})
    min_chunk = max(1, int(_env_int("SHIVA_CAPS_MIN_CHUNK", 50)))
    max_chunk = max(min_chunk, int(_env_int("SHIVA_CAPS_MAX_CHUNK", 2000)))
    min_workers = max(1, int(_env_int("SHIVA_CAPS_MIN_WORKERS", 1)))
    max_workers = max(min_workers, int(_env_int("SHIVA_CAPS_MAX_WORKERS", 50)))
    min_delay = max(0.0, float(_env_float("SHIVA_CAPS_MIN_DELAY_S", 0.0)))
    max_delay = max(min_delay, float(_env_float("SHIVA_CAPS_MAX_DELAY_S", 5.0)))
    min_sleep = max(0.0, float(_env_float("SHIVA_CAPS_MIN_SLEEP_CHUNKS", 0)))
    max_sleep = max(min_sleep, float(_env_float("SHIVA_CAPS_MAX_SLEEP_CHUNKS", 60)))
    if isinstance(bounds_override, dict):
        if bounds_override.get("max_chunk") is not None:
            max_chunk = min(max_chunk, max(1, _num(bounds_override.get("max_chunk"), as_type="int", default=max_chunk)))
        if bounds_override.get("max_workers") is not None:
            max_workers = min(max_workers, max(1, _num(bounds_override.get("max_workers"), as_type="int", default=max_workers)))
        if bounds_override.get("max_delay_s") is not None:
            max_delay = min(max_delay, max(0.0, _num(bounds_override.get("max_delay_s"), as_type="float", default=max_delay)))

    out["chunk_size"] = max(min_chunk, min(max_chunk, _num(out.get("chunk_size"), as_type="int", default=min_chunk)))
    out["thread_workers"] = max(
        min_workers,
        min(max_workers, _num(out.get("thread_workers") if out.get("thread_workers") is not None else out.get("workers"), as_type="int", default=min_workers)),
    )
    out["delay_s"] = max(min_delay, min(max_delay, _num(out.get("delay_s"), as_type="float", default=0.0)))
    out["sleep_chunks"] = max(min_sleep, min(max_sleep, _num(out.get("sleep_chunks"), as_type="float", default=0.0)))
    return out


def resolve_caps_for_attempt(
    job,
    now_ts,
    lane_key: Tuple[int, str],
    base_caps,
    runtime_overrides,
    pressure_caps,
    health_caps,
    lane_registry: Optional[LaneRegistry],
    learning_engine=None,
    probe_selected: bool = False,
    policy_pack_clamps: Optional[dict] = None,
    caps_bounds_override: Optional[dict] = None,
) -> Tuple[dict, dict]:
    def _coerce_num(value: Any, *, as_type: str, default: Any) -> Any:
        return _coerce_scalar_number(value, as_type=as_type, default=default)

    lane = (int((lane_key or (0, ""))[0] or 0), str((lane_key or (0, ""))[1] or "").strip().lower())
    rt = dict(runtime_overrides or {})
    caps = clamp_caps_to_bounds(base_caps or {}, bounds_override=caps_bounds_override)
    meta: Dict[str, Any] = {
        "lane_key": f"{lane[0]}|{lane[1]}",
        "timestamp": float(now_ts or time.time()),
        "source_order": ["base", "overrides", "pressure", "health", "learning", "lane_state", "probe", "policy_pack"],
        "steps": [],
        "lane_state": None,
        "learning": {},
        "probe_selected": bool(probe_selected),
    }

    def _record(step: str, before: dict, after: dict, reason: str) -> None:
        meta["steps"].append({"step": step, "before": dict(before), "after": dict(after), "reason": str(reason or "")})

    before = dict(caps)
    direct = dict(caps)
    if rt:
        if rt.get("chunk_size") is not None:
            direct["chunk_size"] = _coerce_num(rt.get("chunk_size"), as_type="int", default=direct["chunk_size"])
        if rt.get("thread_workers") is not None:
            direct["thread_workers"] = _coerce_num(rt.get("thread_workers"), as_type="int", default=direct["thread_workers"])
        if rt.get("delay_s") is not None:
            direct["delay_s"] = _coerce_num(rt.get("delay_s"), as_type="float", default=direct["delay_s"])
        if rt.get("sleep_chunks") is not None:
            direct["sleep_chunks"] = _coerce_num(rt.get("sleep_chunks"), as_type="float", default=direct["sleep_chunks"])
    caps = clamp_caps_to_bounds(direct, bounds_override=caps_bounds_override)
    _record("overrides", before, caps, "campaign_form runtime overrides")

    def _apply_clamps(src: dict, *, chunk_key: str, workers_key: str, delay_key: str, sleep_key: str) -> None:
        nonlocal caps
        if not isinstance(src, dict):
            return
        c2 = dict(caps)
        if src.get(chunk_key) is not None:
            chunk_cap = _coerce_num(src.get(chunk_key), as_type="int", default=c2["chunk_size"])
            c2["chunk_size"] = min(_coerce_num(c2["chunk_size"], as_type="int", default=1), chunk_cap)
        if src.get(workers_key) is not None:
            workers_cap = _coerce_num(src.get(workers_key), as_type="int", default=c2["thread_workers"])
            c2["thread_workers"] = min(_coerce_num(c2["thread_workers"], as_type="int", default=1), workers_cap)
        if src.get(delay_key) is not None:
            delay_floor = _coerce_num(src.get(delay_key), as_type="float", default=c2["delay_s"])
            c2["delay_s"] = max(_coerce_num(c2["delay_s"], as_type="float", default=0.0), delay_floor)
        if src.get(sleep_key) is not None:
            sleep_floor = _coerce_num(src.get(sleep_key), as_type="float", default=c2["sleep_chunks"])
            c2["sleep_chunks"] = max(_coerce_num(c2["sleep_chunks"], as_type="float", default=0.0), sleep_floor)
        caps = clamp_caps_to_bounds(c2, bounds_override=caps_bounds_override)

    before = dict(caps)
    _apply_clamps(dict(pressure_caps or {}), chunk_key="chunk_size_max", workers_key="workers_max", delay_key="delay_min", sleep_key="sleep_min")
    pressure_level = _coerce_num((pressure_caps or {}).get("level"), as_type="int", default=0)
    _record("pressure", before, caps, f"pmta_level={pressure_level}")

    before = dict(caps)
    health_applied = (health_caps or {}).get("applied") if isinstance(health_caps, dict) else {}
    _apply_clamps(dict(health_applied or {}), chunk_key="chunk_size", workers_key="workers", delay_key="delay_s", sleep_key="sleep_chunks")
    health_level = _coerce_num((health_caps or {}).get("level"), as_type="int", default=0)
    _record("health", before, caps, f"health_level={health_level}")

    learning_caps: Dict[str, Any] = {}
    if isinstance(learning_engine, dict):
        learning_caps = dict(learning_engine)
    if bool(get_env_bool("SHIVA_LEARNING_CAPS_ENFORCE", False)) and learning_caps:
        before = dict(caps)
        _apply_clamps(learning_caps, chunk_key="chunk_size_cap", workers_key="workers_cap", delay_key="delay_floor", sleep_key="sleep_floor")
        meta["learning"] = {
            "enforced": True,
            "tier": learning_caps.get("tier"),
            "confidence": learning_caps.get("confidence"),
            "caps": dict(learning_caps),
        }
        _record("learning", before, caps, "learning clamp-only")

    lane_state_enforce = bool(get_env_bool("SHIVA_LANE_STATE_CAPS_ENFORCE", False))
    lane_only_v2 = bool(get_env_bool("SHIVA_LANE_STATE_CAPS_ONLY_IN_LANE_V2", True))
    scheduler_mode_runtime = str(rt.get("__scheduler_mode_runtime") or "legacy").strip().lower() or "legacy"
    if lane_state_enforce and (not lane_only_v2 or scheduler_mode_runtime == "lane_v2") and lane_registry:
        lane_info = lane_registry.get_lane_info(lane)
        lane_rec = dict(lane_info.get("recommended_caps") or {}) if isinstance(lane_info, dict) else {}
        if lane_rec:
            before = dict(caps)
            _apply_clamps(lane_rec, chunk_key="chunk_size_cap", workers_key="workers_cap", delay_key="delay_floor", sleep_key="sleep_floor")
            meta["lane_state"] = {
                "state": str((lane_info or {}).get("state") or "HEALTHY"),
                "recommended_caps": lane_rec,
            }
            _record("lane_state", before, caps, f"lane_state={meta['lane_state']['state']}")

    if probe_selected:
        probe_caps = {
            "chunk_size_cap": int(_env_int("SHIVA_PROBE_CHUNK_SIZE", 80)),
            "workers_cap": int(_env_int("SHIVA_PROBE_WORKERS", 2)),
            "delay_floor": float(_env_float("SHIVA_PROBE_DELAY_FLOOR_S", 0.8)),
            "sleep_floor": float(_env_float("SHIVA_PROBE_SLEEP_FLOOR_S", 2.0)),
        }
        before = dict(caps)
        _apply_clamps(probe_caps, chunk_key="chunk_size_cap", workers_key="workers_cap", delay_key="delay_floor", sleep_key="sleep_floor")
        _record("probe", before, caps, "probe-selected lane clamp")

    if isinstance(policy_pack_clamps, dict) and policy_pack_clamps:
        before = dict(caps)
        _apply_clamps(policy_pack_clamps, chunk_key="chunk_size_cap", workers_key="workers_cap", delay_key="delay_floor", sleep_key="sleep_floor")
        _record("policy_pack", before, caps, "policy-pack clamp-only")

    meta["final"] = dict(caps)
    return caps, meta


class LaneExecutor:
    """Concurrent lane-task runner (job-scoped)."""

    def __init__(self, max_parallel_lanes: int, lane_picker_v2: Optional[LanePickerV2], budget_mgr: Optional[BudgetManager], locks: dict, debug: bool = False, governor: Optional['GlobalResourceGovernor'] = None):
        self.max_parallel_lanes = max(1, int(max_parallel_lanes or 1))
        self.lane_picker_v2 = lane_picker_v2
        self.budget_mgr = budget_mgr
        self.governor = governor
        self.debug = bool(debug)
        self._locks = dict(locks or {})
        self._executor = ThreadPoolExecutor(max_workers=self.max_parallel_lanes)
        self._inflight: Dict[Tuple[int, str], dict] = {}
        self._recent: deque = deque(maxlen=10)
        self._accept_new = True
        self._lock_inflight = threading.Lock()

    def submit_ready_tasks(self, now_ts: float, job_context: dict) -> int:
        if not self._accept_new:
            return 0
        submitted = 0
        picker = job_context.get("pick_lane")
        task_fn = job_context.get("task_fn")
        resolve_caps = job_context.get("resolve_caps")
        pmta_pressure_level = int((job_context.get("pmta_pressure_level")() if callable(job_context.get("pmta_pressure_level")) else (job_context.get("pmta_pressure_level") or 0)) or 0)
        should_stop = job_context.get("should_stop")
        wait_if_paused = job_context.get("wait_if_paused")
        max_scan_attempts = max(1, int(job_context.get("max_scan_attempts") or (self.max_parallel_lanes * 3)))
        attempts = 0
        while len(self._inflight) < self.max_parallel_lanes and attempts < max_scan_attempts:
            if callable(should_stop) and bool(should_stop()):
                self._accept_new = False
                break
            attempts += 1
            lane_key, meta = picker(float(now_ts or time.time()))
            if not lane_key:
                break
            if lane_key in self._inflight:
                continue
            is_retry = str((meta or {}).get("pick_type") or "") == "retry"
            is_probe = bool((meta or {}).get("probe_active"))
            effective_caps = {}
            caps_meta = {}
            if callable(resolve_caps):
                try:
                    effective_caps, caps_meta = resolve_caps(lane_key, float(now_ts or time.time()), bool(is_probe), dict(meta or {}))
                except Exception:
                    effective_caps, caps_meta = {}, {}
            workers_needed = max(1, int((effective_caps or {}).get("thread_workers") or (effective_caps or {}).get("workers") or (meta or {}).get("thread_workers") or (job_context.get("thread_workers_default") or 1)))
            if self.budget_mgr:
                allowed, reason = self.budget_mgr.can_start(lane_key, now_ts, is_retry, is_probe)
                if not allowed:
                    if self.debug:
                        job_context.get("debug_log", lambda *_: None)(f"LaneExecutor deny {lane_key[0]}|{lane_key[1]} reason={reason}")
                    continue
            if self.governor:
                allowed, reason = self.governor.can_reserve(workers_needed, now_ts, pmta_pressure_level)
                if not allowed:
                    if self.debug:
                        job_context.get("debug_log", lambda *_: None)(f"LaneExecutor governor deny {lane_key[0]}|{lane_key[1]} reason={reason}")
                    continue
            release_state = {"released": False}
            if self.governor:
                self.governor.reserve(workers_needed, lane_key, now_ts)
            if self.budget_mgr:
                self.budget_mgr.on_start(lane_key, now_ts)

            def _task_wrapper() -> dict:
                try:
                    if callable(should_stop) and bool(should_stop()):
                        return {"status": "stopped", "lane": f"{lane_key[0]}|{lane_key[1]}", "reason": "stop_requested"}
                    if callable(wait_if_paused) and not bool(wait_if_paused()):
                        return {"status": "stopped", "lane": f"{lane_key[0]}|{lane_key[1]}", "reason": "stop_requested"}
                    if callable(should_stop) and bool(should_stop()):
                        return {"status": "stopped", "lane": f"{lane_key[0]}|{lane_key[1]}", "reason": "stop_requested"}
                    try:
                        return task_fn(
                            lane_key,
                            now_ts,
                            bool(is_probe),
                            meta or {},
                            reserved_workers=workers_needed,
                            effective_caps=(effective_caps or {}),
                            caps_meta=(caps_meta or {}),
                        )
                    except TypeError:
                        return task_fn(lane_key, now_ts, bool(is_probe), meta or {})
                finally:
                    if not release_state["released"]:
                        release_state["released"] = True
                        if self.budget_mgr:
                            self.budget_mgr.on_finish(lane_key, time.time())
                        if self.governor:
                            self.governor.release(workers_needed, lane_key, time.time())

            fut = self._executor.submit(_task_wrapper)
            self._inflight[lane_key] = {
                "future": fut,
                "started_ts": float(now_ts or time.time()),
                "meta": {**dict(meta or {}), "effective_caps": dict(effective_caps or {}), "caps_meta": dict(caps_meta or {})},
                "reserved_workers": int(workers_needed),
                "release_state": release_state,
                "managed_cleanup": True,
            }
            submitted += 1
        return submitted

    def poll_completed_tasks(self, timeout_s: float, on_result: Callable[[Tuple[int, str], dict], None], on_error: Callable[[Tuple[int, str], Exception], None]) -> None:
        now_ts = time.time()
        for lane_key, info in list(self._inflight.items()):
            fut = info.get("future")
            started_ts = float(info.get("started_ts") or 0.0)
            if isinstance(fut, Future) and fut.done():
                try:
                    res = fut.result()
                    self._recent.append({"lane": f"{lane_key[0]}|{lane_key[1]}", "status": str((res or {}).get("status") or "ok"), "ts": now_ts})
                    on_result(lane_key, res if isinstance(res, dict) else {"status": "ok"})
                except Exception as e:
                    self._recent.append({"lane": f"{lane_key[0]}|{lane_key[1]}", "status": "exception", "error": str(e), "ts": now_ts})
                    on_error(lane_key, e)
                finally:
                    self._inflight.pop(lane_key, None)
                continue
            if started_ts > 0 and timeout_s > 0 and (now_ts - started_ts) > timeout_s:
                canceled = False
                try:
                    if isinstance(fut, Future):
                        canceled = bool(fut.cancel())
                except Exception:
                    pass
                self._recent.append({"lane": f"{lane_key[0]}|{lane_key[1]}", "status": "timeout", "ts": now_ts})
                on_error(lane_key, TimeoutError(f"lane task timeout > {int(timeout_s)}s"))
                release_state = info.get("release_state") if isinstance(info.get("release_state"), dict) else None
                if canceled and release_state is not None and not bool(release_state.get("released")):
                    release_state["released"] = True
                    if self.budget_mgr:
                        self.budget_mgr.on_finish(lane_key, time.time())
                    if self.governor:
                        self.governor.release(int(info.get("reserved_workers") or 0), lane_key, time.time())
                self._inflight.pop(lane_key, None)

    def snapshot(self) -> dict:
        return {
            "inflight_count": len(self._inflight),
            "inflight_lanes": [
                {"lane": f"{k[0]}|{k[1]}", "started_ts": float(v.get("started_ts") or 0.0), "meta": dict(v.get("meta") or {})}
                for k, v in sorted(self._inflight.items(), key=lambda x: (x[0][0], x[0][1]))
            ],
            "recent_completions": list(self._recent),
            "budget": self.budget_mgr.snapshot() if self.budget_mgr else {},
            "resource_governor": self.governor.snapshot() if self.governor else {},
        }

    def stop_gracefully(self, grace_s: float = 30.0, force_disable: bool = True, on_force_disable: Optional[Callable[[], None]] = None) -> bool:
        self._accept_new = False
        deadline = time.time() + max(0.0, float(grace_s or 0.0))
        while time.time() < deadline:
            if not self._inflight:
                self._executor.shutdown(wait=False, cancel_futures=False)
                return True
            self.poll_completed_tasks(0.0, lambda *_: None, lambda *_: None)
            time.sleep(0.05)
        drained = not bool(self._inflight)
        if (not drained) and force_disable and callable(on_force_disable):
            try:
                on_force_disable()
            except Exception:
                pass
        self._executor.shutdown(wait=False, cancel_futures=False)
        return drained


class GlobalResourceGovernor:
    """Job-scoped workers/session reservation governor for concurrent lane scheduling."""

    def __init__(self, max_total_workers: int, debug: bool = False, pmta_scale_config: Optional[dict] = None):
        self.max_total_workers = max(1, int(max_total_workers or 1))
        self.debug = bool(debug)
        self.pmta_scale_config = dict(pmta_scale_config or {})
        self.total_workers_inflight = 0
        self.inflight_by_lane: Dict[str, int] = {}
        self.last_denials: deque = deque(maxlen=20)
        self.lock_governor = threading.Lock()

    def _lane_id(self, lane_key: Tuple[int, str]) -> str:
        return f"{int((lane_key or (0, ''))[0] or 0)}|{str((lane_key or (0, ''))[1] or '').strip().lower()}"

    def effective_max_total_workers(self, pmta_pressure_level: Optional[int] = None) -> int:
        level = int(pmta_pressure_level or 0)
        if not bool(self.pmta_scale_config.get("enabled", True)):
            return int(self.max_total_workers)
        factor = 1.0
        if level >= 3:
            factor = float(self.pmta_scale_config.get("level3_factor") or 0.50)
        elif level >= 2:
            factor = float(self.pmta_scale_config.get("level2_factor") or 0.75)
        return max(1, int(math.floor(float(self.max_total_workers) * max(0.05, factor))))

    def can_reserve(self, workers_needed: int, now_ts: float, pmta_pressure_level: Optional[int] = None) -> Tuple[bool, str]:
        needed = max(1, int(workers_needed or 1))
        with self.lock_governor:
            effective_max = self.effective_max_total_workers(pmta_pressure_level)
            projected = int(self.total_workers_inflight) + needed
            if projected > effective_max:
                reason = f"workers_budget projected={projected} max={effective_max}"
                self.last_denials.append({"ts": float(now_ts or time.time()), "reason": reason, "needed": needed, "inflight": int(self.total_workers_inflight), "max": int(effective_max)})
                return False, reason
            return True, "ok"

    def reserve(self, workers_needed: int, lane_key: Tuple[int, str], now_ts: float) -> None:
        needed = max(1, int(workers_needed or 1))
        lid = self._lane_id(lane_key)
        with self.lock_governor:
            self.total_workers_inflight += needed
            self.inflight_by_lane[lid] = int(self.inflight_by_lane.get(lid) or 0) + needed

    def release(self, workers_needed: int, lane_key: Tuple[int, str], now_ts: float) -> None:
        needed = max(0, int(workers_needed or 0))
        lid = self._lane_id(lane_key)
        with self.lock_governor:
            self.total_workers_inflight = max(0, int(self.total_workers_inflight) - needed)
            left = max(0, int(self.inflight_by_lane.get(lid) or 0) - needed)
            if left <= 0:
                self.inflight_by_lane.pop(lid, None)
            else:
                self.inflight_by_lane[lid] = left

    def snapshot(self) -> dict:
        with self.lock_governor:
            return {
                "max_total_workers": int(self.max_total_workers),
                "total_workers_inflight": int(self.total_workers_inflight),
                "inflight_by_lane": dict(sorted(self.inflight_by_lane.items())),
                "last_denials": list(self.last_denials),
            }


class FallbackController:
    """Job-scoped safety controller that can downgrade to legacy scheduling under risk."""

    def __init__(
        self,
        thresholds: dict,
        window_s: int,
        debug: bool,
        disable_reenable: bool,
        min_active_s: int,
        recovery_s: int,
        actions_config: dict,
    ):
        self.thresholds = dict(thresholds or {})
        self.window_s = max(30, int(window_s or 300))
        self.debug = bool(debug)
        self.disable_reenable = bool(disable_reenable)
        self.min_active_s = max(1, int(min_active_s or 180))
        self.recovery_s = max(1, int(recovery_s or 300))
        self.actions_config = dict(actions_config or {})
        self._samples: deque = deque()
        self._active = False
        self._triggered_ts = 0.0
        self._last_reasons: List[str] = []
        self._actions_taken: List[str] = []
        self._last_rates = {
            "attempts": 0,
            "global_deferral_rate": 0.0,
            "global_hardfail_rate": 0.0,
            "global_timeout_rate": 0.0,
            "blocked_per_minute": 0.0,
            "exceptions_per_minute": 0.0,
            "pmta_pressure_level": 0,
            "pmta_pressure_high_seconds": 0.0,
        }
        self._stable_since = 0.0

    def _prune(self, now_ts: float) -> None:
        cutoff = float(now_ts or 0.0) - float(self.window_s)
        while self._samples and float(self._samples[0].get("ts") or 0.0) < cutoff:
            self._samples.popleft()

    def observe(self, now_ts: float, global_metrics_snapshot: dict, pmta_pressure_level: int, executor_snapshot: Optional[dict] = None) -> None:
        ts = float(now_ts or time.time())
        gm = dict(global_metrics_snapshot or {})
        sample = {
            "ts": ts,
            "attempts_total": int(gm.get("attempts_total") or 0),
            "deferrals_4xx": int(gm.get("deferrals_4xx") or 0),
            "hardfails_5xx": int(gm.get("hardfails_5xx") or 0),
            "timeouts_conn": int(gm.get("timeouts_conn") or 0),
            "blocked_events": int(gm.get("blocked_events") or 0),
            "exceptions_count": int(gm.get("exceptions_count") or 0),
            "pmta_pressure_level": int(pmta_pressure_level or 0),
            "quarantine_count": int(gm.get("quarantine_count") or 0),
            "inflight_count": int(gm.get("inflight_count") or 0),
        }
        if isinstance(executor_snapshot, dict):
            sample["inflight_count"] = int(executor_snapshot.get("inflight_count") or sample["inflight_count"] or 0)
        self._samples.append(sample)
        self._prune(ts)

    def _rolling_rates(self) -> dict:
        if not self._samples:
            return dict(self._last_rates)
        first = self._samples[0]
        last = self._samples[-1]
        attempts = max(0, int(last.get("attempts_total") or 0) - int(first.get("attempts_total") or 0))
        deferrals = max(0, int(last.get("deferrals_4xx") or 0) - int(first.get("deferrals_4xx") or 0))
        hardfails = max(0, int(last.get("hardfails_5xx") or 0) - int(first.get("hardfails_5xx") or 0))
        timeouts = max(0, int(last.get("timeouts_conn") or 0) - int(first.get("timeouts_conn") or 0))
        blocked = max(0, int(last.get("blocked_events") or 0) - int(first.get("blocked_events") or 0))
        exceptions = max(0, int(last.get("exceptions_count") or 0) - int(first.get("exceptions_count") or 0))
        elapsed = max(1.0, float(last.get("ts") or 0.0) - float(first.get("ts") or 0.0))
        blocked_per_min = float(blocked) * (60.0 / elapsed)
        exceptions_per_min = float(exceptions) * (60.0 / elapsed)
        high_level = int(self.thresholds.get("pmta_pressure_level") or 3)
        high_seconds = 0.0
        prev = None
        for sm in self._samples:
            if prev is not None and int(prev.get("pmta_pressure_level") or 0) >= high_level:
                high_seconds += max(0.0, float(sm.get("ts") or 0.0) - float(prev.get("ts") or 0.0))
            prev = sm
        self._last_rates = {
            "attempts": int(attempts),
            "global_deferral_rate": float(deferrals / max(1, attempts)),
            "global_hardfail_rate": float(hardfails / max(1, attempts)),
            "global_timeout_rate": float(timeouts / max(1, attempts)),
            "blocked_per_minute": float(blocked_per_min),
            "exceptions_per_minute": float(exceptions_per_min),
            "pmta_pressure_level": int(last.get("pmta_pressure_level") or 0),
            "pmta_pressure_high_seconds": float(high_seconds),
        }
        return dict(self._last_rates)

    def should_trigger(self, now_ts: float) -> Tuple[bool, List[str]]:
        rates = self._rolling_rates()
        reasons: List[str] = []
        if rates["global_deferral_rate"] >= float(self.thresholds.get("deferral_rate") or 0.35):
            reasons.append(f"deferral_rate={rates['global_deferral_rate']:.3f}")
        if rates["global_hardfail_rate"] >= float(self.thresholds.get("hardfail_rate") or 0.05):
            reasons.append(f"hardfail_rate={rates['global_hardfail_rate']:.3f}")
        if rates["global_timeout_rate"] >= float(self.thresholds.get("timeout_rate") or 0.08):
            reasons.append(f"timeout_rate={rates['global_timeout_rate']:.3f}")
        if rates["blocked_per_minute"] >= float(self.thresholds.get("blocked_per_min") or 10.0):
            reasons.append(f"blocked_per_minute={rates['blocked_per_minute']:.2f}")
        if rates["pmta_pressure_high_seconds"] >= (float(self.window_s) / 2.0):
            reasons.append(f"pmta_pressure_high_seconds={rates['pmta_pressure_high_seconds']:.1f}")
        if rates["exceptions_per_minute"] >= float(self.thresholds.get("exceptions_per_min") or 3.0):
            reasons.append(f"exceptions_per_minute={rates['exceptions_per_minute']:.2f}")

        ts = float(now_ts or time.time())
        if self._active:
            if self.disable_reenable:
                return False, []
            if (ts - float(self._triggered_ts or ts)) < float(self.min_active_s):
                return False, []
            if reasons:
                self._stable_since = 0.0
                return False, []
            if self._stable_since <= 0.0:
                self._stable_since = ts
                return False, []
            if (ts - self._stable_since) >= float(self.recovery_s):
                self._active = False
                self._actions_taken.append("reenabled_new_layers")
            return False, []

        if reasons:
            self._last_reasons = list(reasons)
            self._active = True
            self._triggered_ts = ts
            self._stable_since = 0.0
            return True, reasons
        return False, []

    def apply_actions(self, job_context: dict) -> None:
        if not self._active:
            return
        act = dict(self.actions_config or {})
        if bool(act.get("step1_disable_concurrency", True)):
            fn = job_context.get("disable_concurrency")
            if callable(fn):
                fn()
                self._actions_taken.append("disabled_concurrency")
        if bool(act.get("step2_disable_probe", True)):
            fn = job_context.get("disable_probe")
            if callable(fn):
                fn()
                self._actions_taken.append("disabled_probe")
        if bool(act.get("step3_switch_to_legacy", True)):
            fn = job_context.get("switch_scheduler_legacy")
            if callable(fn):
                fn()
                self._actions_taken.append("switched_legacy")

    def is_in_fallback(self, now_ts: float) -> bool:
        if not self._active:
            return False
        if self.disable_reenable:
            return True
        return bool(float(now_ts or time.time()) - float(self._triggered_ts or 0.0) >= 0.0)

    def snapshot(self) -> dict:
        return {
            "active": bool(self._active),
            "triggered_ts": float(self._triggered_ts or 0.0),
            "reasons": list(self._last_reasons),
            "rolling": dict(self._last_rates),
            "actions_taken": list(self._actions_taken),
            "reenable_allowed": not bool(self.disable_reenable),
            "window_s": int(self.window_s),
            "min_active_s": int(self.min_active_s),
            "recovery_s": int(self.recovery_s),
        }


class RolloutDecider:
    """Job-scoped rollout selector for legacy/shadow/canary/on."""

    def __init__(self, mode: str, canary_percent: int, allowlists: dict, denylists: dict, seed_mode: str, debug: bool = False):
        self.mode = str(mode or "off").strip().lower() or "off"
        if self.mode not in {"off", "shadow", "canary", "on"}:
            self.mode = "off"
        self.canary_percent = max(0, min(100, int(canary_percent or 0)))
        self.allowlist_campaigns = {str(x or "").strip() for x in (allowlists or {}).get("campaigns", set()) if str(x or "").strip()}
        self.allowlist_senders = {str(x or "").strip().lower() for x in (allowlists or {}).get("senders", set()) if str(x or "").strip()}
        self.denylist_campaigns = {str(x or "").strip() for x in (denylists or {}).get("campaigns", set()) if str(x or "").strip()}
        self.seed_mode = str(seed_mode or "job_id").strip().lower() or "job_id"
        if self.seed_mode not in {"job_id", "campaign_id"}:
            self.seed_mode = "job_id"
        self.debug = bool(debug)

    def _deterministic_bucket(self, seed: str) -> int:
        raw = str(seed or "").encode("utf-8", errors="ignore")
        return int(hashlib.sha256(raw).hexdigest()[:8], 16) % 100

    def _sender_allowed(self, sender_emails: Optional[List[str]]) -> bool:
        if not self.allowlist_senders:
            return False
        for sender in sender_emails or []:
            sender_v = str(sender or "").strip().lower()
            sender_domain = _extract_domain_from_email(sender_v) or ""
            if sender_v in self.allowlist_senders or sender_domain in self.allowlist_senders:
                return True
        return False

    def decide(self, job: Any, sender_emails: Optional[List[str]] = None, force_legacy: bool = False) -> dict:
        reasons: List[str] = []
        job_id = str(getattr(job, "id", "") or "")
        campaign_id = str(getattr(job, "campaign_id", "") or "")

        if force_legacy:
            reasons.append("force_legacy")
            effective = "legacy"
        elif self.mode == "off":
            reasons.append("rollout_off")
            effective = "legacy"
        elif self.mode == "shadow":
            reasons.append("shadow_compute_only")
            effective = "shadow"
        elif self.mode == "on":
            reasons.append("rollout_on")
            effective = "v2"
        else:
            if campaign_id and campaign_id in self.denylist_campaigns:
                reasons.append("campaign_denylist")
                effective = "legacy"
            elif campaign_id and campaign_id in self.allowlist_campaigns:
                reasons.append("campaign_allowlist")
                effective = "v2"
            elif self._sender_allowed(sender_emails):
                reasons.append("sender_allowlist")
                effective = "v2"
            else:
                seed_value = job_id if self.seed_mode == "job_id" else campaign_id
                bucket = self._deterministic_bucket(seed_value)
                if bucket < self.canary_percent:
                    reasons.append(f"canary_percent:{bucket}<{self.canary_percent}")
                    effective = "v2"
                else:
                    reasons.append(f"canary_percent:{bucket}>={self.canary_percent}")
                    effective = "legacy"
        return {
            "rollout_mode": self.mode,
            "effective_mode": effective,
            "reasons": reasons,
            "is_canary": bool(self.mode == "canary" and effective == "v2"),
            "is_shadow": bool(effective == "shadow"),
            "is_on": bool(effective == "v2"),
        }


@dataclass
class EffectivePlan:
    scheduler_mode: str = "legacy"
    concurrency_enabled: bool = False
    probe_enabled: bool = False
    waves_enabled: bool = False
    provider_canon_enabled: bool = False
    provider_canon_enforced: bool = False
    policy_pack_enabled: bool = False
    policy_pack_enforced: bool = False
    learning_caps_enabled: bool = False
    learning_caps_enforced: bool = False
    backoff_jitter_mode: str = "off"
    fallback_controller_enabled: bool = False
    resource_governor_enabled: bool = False
    accounting_recon_enabled: bool = False
    ui_telemetry_enabled: bool = False


@dataclass
class ValidationResult:
    ok: bool = True
    critical_issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    clamps_applied: List[dict] = field(default_factory=list)


class GuardrailsValidator:
    """Job-local runtime safety validator for scheduler plan/config."""

    def __init__(self, limits: dict, strict: bool = False, debug: bool = False):
        self.limits = dict(limits or {})
        self.strict = bool(strict)
        self.debug = bool(debug)

    def validate_plan(self, plan: EffectivePlan, config_snapshot: dict) -> ValidationResult:
        cfg = dict(config_snapshot or {})
        out = ValidationResult(ok=True)

        def _num(name: str, default: Any, as_type: str = "int") -> Any:
            return _coerce_scalar_number(cfg.get(name), as_type=as_type, default=default)

        def _critical(msg: str) -> None:
            out.critical_issues.append(str(msg))

        def _warn(msg: str) -> None:
            out.warnings.append(str(msg))

        def _clamp(name: str, before: Any, after: Any, reason: str) -> None:
            if before == after:
                return
            out.clamps_applied.append({"field": name, "before": before, "after": after, "reason": str(reason)})
            _warn(f"Guardrails clamp applied: {name} {before} -> {after} ({reason})")

        max_parallel_lanes = _num("lane_max_parallel", 1, "int")
        max_total_workers = _num("max_total_workers", 1, "int")
        caps_max_workers = _num("caps_max_workers", 1, "int")
        caps_max_chunk = _num("caps_max_chunk", 1, "int")
        caps_max_delay_s = _num("caps_max_delay_s", 0.0, "float")
        provider_min_gap_s = _num("provider_min_gap_s", 0.0, "float")
        provider_cooldown_s = _num("provider_cooldown_s", 0, "int")
        wave_max_parallel_single_domain = _num("wave_max_parallel_single_domain", 1, "int")
        wave_burst_tokens = _num("wave_burst_tokens", 1, "int")
        wave_refill_per_sec = _num("wave_refill_per_sec", 0.1, "float")
        jitter_mode = str(cfg.get("backoff_jitter_mode") or "off").strip().lower() or "off"
        jitter_pct = max(0.0, _num("backoff_jitter_pct", 0.0, "float"))
        rollout_effective_mode = str(cfg.get("rollout_effective_mode") or "legacy").strip().lower() or "legacy"
        fallback_requested = bool(cfg.get("fallback_controller_enabled_requested"))
        resource_gov_requested = bool(cfg.get("resource_governor_enabled_requested"))

        if plan.concurrency_enabled:
            if not bool(plan.fallback_controller_enabled):
                _critical("Concurrency requires fallback controller to be enabled.")
            if (not bool(plan.resource_governor_enabled)) and max_total_workers > int(self.limits.get("max_total_workers", 80)):
                _critical("Concurrency without resource governor exceeds safe max_total_workers limit.")
            if not fallback_requested:
                _critical("Concurrency is enabled while fallback controller is explicitly disabled by operator configuration.")
            if (not resource_gov_requested) and max_total_workers > int(self.limits.get("max_total_workers", 80)):
                _critical("Concurrency is enabled while resource governor is explicitly disabled and workers exceed safe cap.")

        if plan.waves_enabled and wave_max_parallel_single_domain != 1:
            _critical("Single-domain waves require SHIVA_WAVE_MAX_PARALLEL_LANES_SINGLE_DOMAIN=1.")

        if rollout_effective_mode in {"v2", "on", "canary"} and not bool(plan.fallback_controller_enabled):
            _critical("Rollout canary/on requires fallback controller.")
        if rollout_effective_mode in {"v2", "on", "canary"} and not bool(cfg.get("guardrails_export")):
            _warn("Guardrails telemetry export is recommended during canary/on rollout.")

        if jitter_mode == "random":
            _warn("Backoff jitter mode=random reduces reproducibility; deterministic is recommended.")
        if jitter_pct > 0.30:
            _clamp("backoff_jitter_pct", jitter_pct, 0.30, "max jitter pct safety cap")

        _clamp("lane_max_parallel", max_parallel_lanes, min(max_parallel_lanes, int(self.limits.get("max_parallel_lanes", 8))), "max parallel lanes safety cap")
        _clamp("max_total_workers", max_total_workers, min(max_total_workers, int(self.limits.get("max_total_workers", 80))), "max total workers safety cap")
        _clamp("caps_max_workers", caps_max_workers, min(caps_max_workers, int(self.limits.get("max_workers_per_lane", 12))), "max workers per lane safety cap")
        _clamp("caps_max_chunk", caps_max_chunk, min(caps_max_chunk, int(self.limits.get("max_chunk_size", 1000))), "max chunk size safety cap")
        _clamp("caps_max_delay_s", caps_max_delay_s, min(caps_max_delay_s, float(self.limits.get("max_delay_s", 5.0))), "max delay safety cap")
        _clamp("provider_min_gap_s", provider_min_gap_s, min(provider_min_gap_s, float(self.limits.get("max_min_gap_s", 300.0))), "provider min gap sanity cap")
        _clamp("provider_cooldown_s", provider_cooldown_s, min(provider_cooldown_s, int(self.limits.get("max_cooldown_s", 3600))), "provider cooldown sanity cap")
        if plan.waves_enabled:
            _clamp("wave_max_parallel_single_domain", wave_max_parallel_single_domain, 1, "single-domain wave inflight safety")
            _clamp("wave_burst_tokens", wave_burst_tokens, min(wave_burst_tokens, 400), "single-domain wave burst cap")
            _clamp("wave_refill_per_sec", wave_refill_per_sec, min(wave_refill_per_sec, 3.0), "single-domain wave refill cap")

        if out.critical_issues:
            out.ok = not self.strict
            if not self.strict:
                if not bool(plan.fallback_controller_enabled) and plan.concurrency_enabled:
                    _clamp("plan.fallback_controller_enabled", False, True, "dependency safety auto-enable")
                if (not bool(plan.resource_governor_enabled)) and plan.concurrency_enabled:
                    _clamp("plan.resource_governor_enabled", False, True, "dependency safety auto-enable")
        return out


class ModeOrchestrator:
    """Job-local feature plan resolver with safe dependency ordering."""

    def decide_effective_features(self, job: Any, config: dict, rollout_decision: dict) -> EffectivePlan:
        cfg = dict(config or {})
        rd = dict(rollout_decision or {})
        effective_mode = str(rd.get("effective_mode") or "legacy").strip().lower() or "legacy"
        force_legacy = bool(cfg.get("force_legacy"))

        scheduler_mode = "legacy"
        if not force_legacy and effective_mode in {"v2"}:
            scheduler_mode = "lane_v2"

        concurrency_enabled = bool(
            scheduler_mode == "lane_v2"
            and bool(cfg.get("lane_concurrency_enabled"))
            and not bool(cfg.get("force_disable_concurrency"))
        )

        provider_canon_enabled = bool(cfg.get("provider_canon_enabled"))
        provider_canon_enforced = bool(provider_canon_enabled and cfg.get("provider_canon_enforce"))
        policy_pack_enabled = bool(cfg.get("policy_packs_enabled"))
        policy_pack_enforced = bool(policy_pack_enabled and cfg.get("policy_packs_enforce"))
        learning_caps_enabled = bool(cfg.get("learning_caps_enabled"))
        learning_caps_enforced = bool(learning_caps_enabled and cfg.get("learning_caps_enforce"))

        provider_groups_count = int(cfg.get("provider_groups_count") or 0)
        provider_domains_count = int(cfg.get("provider_domains_count") or 0)
        fallback_active = bool(cfg.get("fallback_active"))
        pmta_pressure_level = int(cfg.get("pmta_pressure_level") or 0)

        probe_candidate_multi = provider_groups_count >= 2 if provider_canon_enforced else provider_domains_count >= 2
        probe_enabled = bool(cfg.get("probe_mode_enabled") and probe_candidate_multi)
        if fallback_active or pmta_pressure_level >= 3:
            probe_enabled = False

        wave_scope_single = provider_groups_count == 1 if provider_canon_enforced else provider_domains_count == 1
        waves_enabled = bool(cfg.get("single_domain_waves_enabled") and wave_scope_single)

        backoff_jitter_mode = str(cfg.get("backoff_jitter_mode") or "off").strip().lower() or "off"
        if backoff_jitter_mode not in {"off", "deterministic", "random"}:
            backoff_jitter_mode = "off"

        fallback_controller_enabled = bool(cfg.get("fallback_controller_enabled"))
        if concurrency_enabled or effective_mode in {"v2"}:
            fallback_controller_enabled = True

        resource_governor_enabled = bool(cfg.get("resource_governor_enabled"))
        if concurrency_enabled and not bool(cfg.get("resource_governor_enabled_explicit")):
            resource_governor_enabled = True

        return EffectivePlan(
            scheduler_mode=scheduler_mode,
            concurrency_enabled=concurrency_enabled,
            probe_enabled=probe_enabled,
            waves_enabled=waves_enabled,
            provider_canon_enabled=provider_canon_enabled,
            provider_canon_enforced=provider_canon_enforced,
            policy_pack_enabled=policy_pack_enabled,
            policy_pack_enforced=policy_pack_enforced,
            learning_caps_enabled=learning_caps_enabled,
            learning_caps_enforced=learning_caps_enforced,
            backoff_jitter_mode=backoff_jitter_mode,
            fallback_controller_enabled=fallback_controller_enabled,
            resource_governor_enabled=resource_governor_enabled,
            accounting_recon_enabled=bool(cfg.get("lane_accounting_recon_enabled")),
            ui_telemetry_enabled=bool(cfg.get("ui_telemetry_enabled")),
        )


class ShadowRecorder:
    def __init__(self, max_events: int):
        self.max_events = max(1, int(max_events or 50))
        self._events: deque = deque(maxlen=self.max_events)

    def record(self, event_type: str, payload: dict) -> None:
        self._events.append({
            "ts": float(time.time()),
            "type": str(event_type or "event"),
            "payload": dict(payload or {}),
        })

    def snapshot(self) -> List[dict]:
        return [dict(x) for x in list(self._events)]


def _shadow_state_counts(sender_buckets: Dict[int, Dict[str, List[str]]], provider_retry_chunks: Dict[str, List[dict]]) -> dict:
    bucket_total = 0
    for domains in (sender_buckets or {}).values():
        for items in (domains or {}).values():
            bucket_total += len(items or [])
    retry_total = 0
    for retry_items in (provider_retry_chunks or {}).values():
        retry_total += len(retry_items or [])
    return {"sender_bucket_total": int(bucket_total), "retry_queue_total": int(retry_total)}


def _run_rollout_selftests() -> List[str]:
    logs: List[str] = []
    rcpts = [f"user{i}@gmail.com" for i in range(12)] + [f"user{i}@yahoo.com" for i in range(9)]
    senders = ["s1@sender-a.com", "s2@sender-b.com"]
    out1, stats1 = normalize_and_partition_recipients(rcpts, senders, "seed-selftest")
    out2, stats2 = normalize_and_partition_recipients(rcpts, senders, "seed-selftest")
    assert out1 == out2 and stats1 == stats2, "determinism test failed"
    logs.append("determinism_ok")

    decider = RolloutDecider("off", 5, {"campaigns": set(), "senders": set()}, {"campaigns": set()}, "job_id")
    j = type("JobStub", (), {"id": "job-1", "campaign_id": "camp-1"})()
    decision = decider.decide(j, sender_emails=senders, force_legacy=False)
    assert str(decision.get("effective_mode") or "") == "legacy", "off-mode must stay legacy"
    logs.append("legacy_off_mode_ok")

    state_buckets = {0: {"gmail.com": ["a@gmail.com", "b@gmail.com"]}}
    retries = {"0|gmail.com": [{"next_retry_ts": 0.0, "chunk": ["a@gmail.com"]}]}
    before = _shadow_state_counts(state_buckets, retries)
    picker = LanePickerV2(scheduler_rng=random.Random(7), use_soft_bias=False)
    _ = picker.pick_next(
        now_ts=time.time(),
        sender_cursor=0,
        sender_buckets={0: {"gmail.com": list(state_buckets[0]["gmail.com"])}},
        provider_retry_chunks={"0|gmail.com": list(retries["0|gmail.com"])},
    )
    after = _shadow_state_counts(state_buckets, retries)
    assert before == after, "shadow purity failed"
    logs.append("shadow_purity_ok")
    return logs


def run_acceptance_suite() -> List[str]:
    """Fast deterministic acceptance checks (no SMTP/network)."""
    logs: List[str] = []

    rcpts = [f"u{i}@gmail.com" for i in range(6)] + [f"u{i}@googlemail.com" for i in range(3)] + [f"u{i}@yahoo.com" for i in range(5)]
    senders = ["a@sender-a.com", "b@sender-b.com"]
    a1, st1 = normalize_and_partition_recipients(rcpts, senders, "acc-seed")
    a2, st2 = normalize_and_partition_recipients(rcpts, senders, "acc-seed")
    assert a1 == a2 and st1 == st2, "partition determinism failed"
    logs.append("partition_determinism_ok")

    grp1 = canonical_provider("googlemail.com", alias_map={"googlemail.com": "google"})
    grp2 = canonical_provider("googlemail.com", alias_map={"googlemail.com": "google"})
    assert grp1 == grp2 == "google", "provider canonicalization determinism failed"
    logs.append("provider_canon_determinism_ok")

    bm_inflight = BudgetManager(BudgetConfig(enabled=True, provider_max_inflight_default=1, provider_min_gap_s_default=0.0, sender_max_inflight=2))
    lane = (0, "gmail.com")
    bm_inflight.on_start(lane, now_ts=10.0)
    allowed_now, reason_now = bm_inflight.can_start(lane, now_ts=10.5, is_retry=False, is_probe=False)
    assert (not allowed_now) and ("inflight" in reason_now), "budget inflight cap must block"

    bm_gap = BudgetManager(BudgetConfig(enabled=True, provider_max_inflight_default=2, provider_min_gap_s_default=2.0, sender_max_inflight=2))
    bm_gap.on_start(lane, now_ts=10.0)
    bm_gap.on_finish(lane, now_ts=10.2)
    allowed_gap, reason_gap = bm_gap.can_start(lane, now_ts=11.0, is_retry=False, is_probe=False)
    assert (not allowed_gap) and ("min_gap" in reason_gap), "budget min-gap must block"
    allowed_after, _ = bm_gap.can_start(lane, now_ts=12.3, is_retry=False, is_probe=False)
    assert allowed_after, "budget min-gap should allow after delay"
    logs.append("budget_manager_correctness_ok")

    gov = GlobalResourceGovernor(max_total_workers=4)
    ok1, _ = gov.can_reserve(3, now_ts=1.0, pmta_pressure_level=0)
    assert ok1
    gov.reserve(3, lane_key=(0, "gmail.com"), now_ts=1.0)
    ok2, _ = gov.can_reserve(2, now_ts=1.1, pmta_pressure_level=0)
    assert not ok2
    gov.release(10, lane_key=(0, "gmail.com"), now_ts=1.2)
    snap = gov.snapshot()
    assert int(snap.get("inflight_workers") or 0) == 0, "governor inflight must not go negative"
    logs.append("governor_correctness_ok")

    picker = LanePickerV2(scheduler_rng=random.Random(2), use_soft_bias=False)
    pick, _meta = picker.pick_next(
        now_ts=100.0,
        sender_cursor=0,
        sender_buckets={0: {"gmail.com": ["x@gmail.com"]}},
        provider_retry_chunks={"0|gmail.com": [{"next_retry_ts": 99.0, "chunk": ["a@gmail.com"]}]},
    )
    assert pick == (0, "gmail.com"), "retry-ready lane must be preferred"
    logs.append("lane_picker_retry_priority_ok")

    base_caps = {"chunk_size": 200, "thread_workers": 5, "delay_s": 0.2, "sleep_chunks": 0.0}
    caps, _ = resolve_caps_for_attempt(
        job=None,
        now_ts=1.0,
        lane_key=(0, "gmail.com"),
        base_caps=base_caps,
        runtime_overrides={},
        pressure_caps={},
        health_caps={},
        lane_registry=None,
        learning_engine={"chunk_size_cap": 100, "workers_cap": 2, "delay_floor": 0.8, "sleep_floor": 1.0},
        probe_selected=False,
        policy_pack_clamps={"chunk_size_cap": 80, "workers_cap": 1, "delay_floor": 1.0, "sleep_floor": 2.0},
    )
    assert int(caps["chunk_size"]) <= 200 and int(caps["thread_workers"]) <= 5
    assert float(caps["delay_s"]) >= 0.2 and float(caps["sleep_chunks"]) >= 0.0
    logs.append("caps_resolver_clamp_only_ok")

    sb = {0: {"gmail.com": ["a@gmail.com"]}}
    rq = {"0|gmail.com": [{"next_retry_ts": 0.0, "chunk": ["a@gmail.com"]}]}
    before = _shadow_state_counts(sb, rq)
    shadow_picker = LanePickerV2(scheduler_rng=random.Random(11), use_soft_bias=False)
    _ = shadow_picker.pick_next(now_ts=10.0, sender_cursor=0, sender_buckets={0: {"gmail.com": list(sb[0]["gmail.com"])}}, provider_retry_chunks={"0|gmail.com": list(rq["0|gmail.com"])})
    after = _shadow_state_counts(sb, rq)
    assert before == after, "shadow mode must not mutate queues"
    logs.append("shadow_mode_purity_ok")

    fc = FallbackController(thresholds={"deferral_rate": 0.2, "hardfail_rate": 0.1, "timeout_rate": 0.1, "blocked_per_min": 5.0, "pmta_pressure_level": 3, "exceptions_per_min": 1.0}, window_s=60, debug=False, disable_reenable=True, min_active_s=120, recovery_s=60, actions_config={"step1_disable_concurrency": True, "step2_disable_probe": True, "step3_switch_to_legacy": True})
    fc.observe(10.0, {"attempts_total": 10, "deferrals_4xx": 0, "hardfails_5xx": 0, "timeouts_conn": 0, "blocked_events": 0, "exceptions_count": 0}, pmta_pressure_level=0)
    fc.observe(20.0, {"attempts_total": 60, "deferrals_4xx": 20, "hardfails_5xx": 0, "timeouts_conn": 0, "blocked_events": 0, "exceptions_count": 0}, pmta_pressure_level=0)
    triggered, _reasons = fc.should_trigger(20.0)
    assert triggered and fc.is_in_fallback(21.0), "fallback should trigger"
    fc.observe(30.0, {"attempts_total": 80, "deferrals_4xx": 20, "hardfails_5xx": 0, "timeouts_conn": 0, "blocked_events": 0, "exceptions_count": 0}, pmta_pressure_level=0)
    _t2, _r2 = fc.should_trigger(30.0)
    assert fc.is_in_fallback(40.0), "fallback hysteresis should prevent immediate flapping"
    logs.append("fallback_controller_hysteresis_ok")
    return logs


def map_provider_domains_to_sender_indexes(provider_domains: List[str], sender_emails: List[str]) -> Dict[str, int]:
    """Distribute provider domains evenly across sender emails.

    Mapping is by *domain count* (not recipient count): if there are 50 provider domains
    and 5 sender emails, each sender will be assigned ~10 provider domains.
    """
    if not provider_domains or not sender_emails:
        return {}

    out: Dict[str, int] = {}
    n = max(1, len(sender_emails))
    for i, dom in enumerate(provider_domains):
        if not dom:
            continue
        out[dom] = i % n
    return out


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
    pmta_job_id: str = ""
    bridge_mode: str = ""

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

    # Scheduler baseline snapshot (optional; debug-only, additive)
    debug_baseline_report: dict = field(default_factory=dict)
    debug_lane_metrics_snapshot: dict = field(default_factory=dict)
    debug_lane_states_snapshot: dict = field(default_factory=dict)
    debug_probe_status: dict = field(default_factory=dict)
    debug_budget_status: dict = field(default_factory=dict)
    debug_lane_executor: dict = field(default_factory=dict)
    debug_resource_governor: dict = field(default_factory=dict)
    debug_fallback: dict = field(default_factory=dict)
    debug_provider_canon: dict = field(default_factory=dict)
    debug_backoff_jitter: List[dict] = field(default_factory=list)
    debug_rollout: dict = field(default_factory=dict)
    debug_effective_plan: dict = field(default_factory=dict)
    debug_wave_status: dict = field(default_factory=dict)
    debug_policy_pack: dict = field(default_factory=dict)
    debug_learning_policy: dict = field(default_factory=dict)
    debug_last_lane_pick: dict = field(default_factory=dict)
    debug_last_caps_resolve: dict = field(default_factory=dict)
    debug_shadow_events: List[dict] = field(default_factory=list)
    debug_lane_accounting: dict = field(default_factory=dict)
    debug_guardrails: dict = field(default_factory=dict)

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
    # Shiva internal errors (worker/queue/parser/etc)
    internal_error_counts: Dict[str, int] = field(default_factory=dict)
    internal_last_errors: List[dict] = field(default_factory=list)  # {ts, job_id, type, detail, email}

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
    def record_internal_error(self, err_type: str, detail: str, *, email: str = ""):
        """Record Shiva-side internal errors using a bounded rolling window."""
        self.updated_at = now_iso()
        t = str(err_type or "other").strip().lower() or "other"
        d = str(detail or "").strip()[:300]
        self.internal_error_counts[t] = int(self.internal_error_counts.get(t, 0) or 0) + 1
        self.internal_last_errors.append(
            {
                "ts": now_iso(),
                "job_id": self.id,
                "type": t,
                "detail": d,
                "email": (email or "").strip(),
            }
        )
        if len(self.internal_last_errors) > 80:
            self.internal_last_errors = self.internal_last_errors[-40:]
        try:
            _bridge_push_sample(
                "internal_error_samples",
                {
                    "ts": now_iso(),
                    "job_id": self.id,
                    "type": t,
                    "detail": d,
                    "email": (email or "").strip(),
                },
            )
        except Exception:
            pass
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
    """Resolve SQLite path from env with safe fallback to app-local DB file."""
    raw = (
        os.getenv("SHIVA_DB_PATH")
        or os.getenv("SMTP_SENDER_DB_PATH")
        or str(APP_DIR / "smtp_sender.db")
    )
    candidate = Path(str(raw or "").strip()).expanduser()
    if not candidate.is_absolute():
        candidate = (APP_DIR / candidate).resolve()

    try:
        candidate.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        # If parent creation fails, keep candidate; sqlite/open will emit a clear error.
        pass

    return str(candidate)


DB_PATH = _resolve_db_path()
DB_LOCK = threading.Lock()

try:
    DB_WRITE_BATCH_SIZE = max(50, min(1000, int((os.getenv("SHIVA_DB_WRITE_BATCH_SIZE", "500") or "500").strip())))
except Exception:
    DB_WRITE_BATCH_SIZE = 500
try:
    DB_WRITE_QUEUE_MAX = max(1000, int((os.getenv("SHIVA_DB_WRITE_QUEUE_MAX", "50000") or "50000").strip()))
except Exception:
    DB_WRITE_QUEUE_MAX = 50000

_DB_WRITE_QUEUE: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=DB_WRITE_QUEUE_MAX)
_DB_WRITE_RETRY: List[Dict[str, Any]] = []
_DB_WRITE_LOCK = threading.Lock()
_DB_WRITER_STARTED = False
_DB_WRITER_LOCAL = threading.local()
_DB_WRITER_STATUS: Dict[str, Any] = {
    "queued": 0,
    "written": 0,
    "failed": 0,
    "last_error": "",
    "last_error_ts": "",
    "queue_full": 0,
}

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


def _db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15.0)
    try:
        conn.execute("PRAGMA busy_timeout = 15000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA foreign_keys=ON")
    except Exception:
        pass
    return conn


def _is_sqlite_upsert_unsupported(err: Exception) -> bool:
    msg = str(err).lower()
    return (
        "near \"on\": syntax error" in msg
        or "near 'on': syntax error" in msg
        or "on conflict clause" in msg
    )


def _exec_upsert_compat(
    conn: sqlite3.Connection,
    upsert_sql: str,
    upsert_params: tuple,
    update_sql: str,
    update_params: tuple,
    insert_sql: str,
    insert_params: tuple,
) -> None:
    """Execute UPSERT and transparently fall back for legacy SQLite builds/schemas."""
    try:
        conn.execute(upsert_sql, upsert_params)
        return
    except sqlite3.OperationalError as e:
        if not _is_sqlite_upsert_unsupported(e):
            raise

    cur = conn.execute(update_sql, update_params)
    if (cur.rowcount or 0) <= 0:
        conn.execute(insert_sql, insert_params)


def _db_writer_active() -> bool:
    return bool(getattr(_DB_WRITER_LOCAL, "active", False))


def _db_writer_enqueue(item: Dict[str, Any]) -> bool:
    if not isinstance(item, dict):
        return False
    item.setdefault("attempts", 0)
    try:
        _DB_WRITE_QUEUE.put(item, timeout=0.2)
        with _DB_WRITE_LOCK:
            _DB_WRITER_STATUS["queued"] = int(_DB_WRITER_STATUS.get("queued", 0) or 0) + 1
        return True
    except queue.Full:
        with _DB_WRITE_LOCK:
            _DB_WRITER_STATUS["queue_full"] = int(_DB_WRITER_STATUS.get("queue_full", 0) or 0) + 1
            _DB_WRITER_STATUS["last_error"] = "db_write_queue_full"
            _DB_WRITER_STATUS["last_error_ts"] = now_iso()
            _DB_WRITE_RETRY.append(item)
        return True


def _db_upsert_job_payload(conn: sqlite3.Connection, payload: Dict[str, Any]) -> None:
    _exec_upsert_compat(
        conn,
        "INSERT INTO jobs(id, campaign_id, created_at, updated_at, status, snapshot) VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET campaign_id=excluded.campaign_id, updated_at=excluded.updated_at, status=excluded.status, snapshot=excluded.snapshot",
        (
            str(payload.get("id") or ""),
            str(payload.get("campaign_id") or ""),
            str(payload.get("created_at") or now_iso()),
            str(payload.get("updated_at") or now_iso()),
            str(payload.get("status") or ""),
            str(payload.get("snapshot") or ""),
        ),
        "UPDATE jobs SET campaign_id=?, updated_at=?, status=?, snapshot=? WHERE id=?",
        (
            str(payload.get("campaign_id") or ""),
            str(payload.get("updated_at") or now_iso()),
            str(payload.get("status") or ""),
            str(payload.get("snapshot") or ""),
            str(payload.get("id") or ""),
        ),
        "INSERT INTO jobs(id, campaign_id, created_at, updated_at, status, snapshot) VALUES(?,?,?,?,?,?)",
        (
            str(payload.get("id") or ""),
            str(payload.get("campaign_id") or ""),
            str(payload.get("created_at") or now_iso()),
            str(payload.get("updated_at") or now_iso()),
            str(payload.get("status") or ""),
            str(payload.get("snapshot") or ""),
        ),
    )


def _db_set_outcome_payload(conn: sqlite3.Connection, payload: Dict[str, Any]) -> None:
    _exec_upsert_compat(
        conn,
        "INSERT INTO job_outcomes(job_id, rcpt, status, last_message_id, last_dsn_status, last_dsn_diag, updated_at) "
        "VALUES(?,?,?,?,?,?,?) "
        "ON CONFLICT(job_id, rcpt) DO UPDATE SET "
        "status=excluded.status, "
        "last_message_id=excluded.last_message_id, "
        "last_dsn_status=excluded.last_dsn_status, "
        "last_dsn_diag=excluded.last_dsn_diag, "
        "updated_at=excluded.updated_at",
        (
            str(payload.get("job_id") or ""),
            str(payload.get("rcpt") or ""),
            str(payload.get("status") or ""),
            str(payload.get("message_id") or ""),
            str(payload.get("dsn_status") or ""),
            str(payload.get("dsn_diag") or ""),
            str(payload.get("updated_at") or now_iso()),
        ),
        "UPDATE job_outcomes SET status=?, last_message_id=?, last_dsn_status=?, last_dsn_diag=?, updated_at=? WHERE job_id=? AND rcpt=?",
        (
            str(payload.get("status") or ""),
            str(payload.get("message_id") or ""),
            str(payload.get("dsn_status") or ""),
            str(payload.get("dsn_diag") or ""),
            str(payload.get("updated_at") or now_iso()),
            str(payload.get("job_id") or ""),
            str(payload.get("rcpt") or ""),
        ),
        "INSERT INTO job_outcomes(job_id, rcpt, status, last_message_id, last_dsn_status, last_dsn_diag, updated_at) VALUES(?,?,?,?,?,?,?)",
        (
            str(payload.get("job_id") or ""),
            str(payload.get("rcpt") or ""),
            str(payload.get("status") or ""),
            str(payload.get("message_id") or ""),
            str(payload.get("dsn_status") or ""),
            str(payload.get("dsn_diag") or ""),
            str(payload.get("updated_at") or now_iso()),
        ),
    )


def _db_insert_accounting_event_payload(conn: sqlite3.Connection, event: Dict[str, Any]) -> bool:
    try:
        conn.execute(
            "INSERT INTO accounting_events(event_id, job_id, rcpt, outcome, time_logged, message_id, dsn_status, dsn_diag, "
            "source_file, source_offset_or_line, created_at, raw_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(event.get("event_id") or ""),
                str(event.get("job_id") or ""),
                str(event.get("rcpt") or ""),
                str(event.get("outcome") or ""),
                str(event.get("time_logged") or ""),
                str(event.get("message_id") or ""),
                str(event.get("dsn_status") or ""),
                str(event.get("dsn_diag") or ""),
                str(event.get("source_file") or ""),
                str(event.get("source_offset_or_line") or ""),
                now_iso(),
                event.get("raw_json"),
            ),
        )
        return True
    except sqlite3.IntegrityError:
        return False


def _db_writer_thread() -> None:
    _DB_WRITER_LOCAL.active = True
    while True:
        batch: List[Dict[str, Any]] = []
        if _DB_WRITE_RETRY:
            batch.extend(_DB_WRITE_RETRY[:DB_WRITE_BATCH_SIZE])
            del _DB_WRITE_RETRY[: len(batch)]
        try:
            item = _DB_WRITE_QUEUE.get(timeout=0.4)
            batch.append(item)
        except queue.Empty:
            if not batch:
                continue

        while len(batch) < DB_WRITE_BATCH_SIZE:
            try:
                batch.append(_DB_WRITE_QUEUE.get_nowait())
            except queue.Empty:
                break

        try:
            with DB_LOCK:
                conn = _db_conn()
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    for item in batch:
                        kind = str(item.get("kind") or "")
                        if kind == "job_snapshot":
                            _db_upsert_job_payload(conn, dict(item.get("payload") or {}))
                        elif kind == "job_outcome":
                            _db_set_outcome_payload(conn, dict(item.get("payload") or {}))
                        elif kind == "accounting_event":
                            _db_insert_accounting_event_payload(conn, dict(item.get("payload") or {}))
                    conn.commit()
                finally:
                    conn.close()
            with _DB_WRITE_LOCK:
                _DB_WRITER_STATUS["written"] = int(_DB_WRITER_STATUS.get("written", 0) or 0) + len(batch)
        except Exception as e:
            with _DB_WRITE_LOCK:
                _DB_WRITER_STATUS["failed"] = int(_DB_WRITER_STATUS.get("failed", 0) or 0) + len(batch)
                _DB_WRITER_STATUS["last_error"] = str(e)[:500]
                _DB_WRITER_STATUS["last_error_ts"] = now_iso()
            for item in batch:
                item["attempts"] = int(item.get("attempts", 0) or 0) + 1
                _DB_WRITE_RETRY.append(item)
            time.sleep(0.2)


def start_db_writer_if_needed() -> None:
    global _DB_WRITER_STARTED
    with _DB_WRITE_LOCK:
        if _DB_WRITER_STARTED:
            return
        t = threading.Thread(target=_db_writer_thread, daemon=True, name="db-writer")
        t.start()
        _DB_WRITER_STARTED = True


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
                       last_message_id TEXT NOT NULL DEFAULT '',
                       last_dsn_status TEXT NOT NULL DEFAULT '',
                       last_dsn_diag TEXT NOT NULL DEFAULT '',
                       updated_at TEXT NOT NULL,
                       PRIMARY KEY(job_id, rcpt)
                   )"""
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_job_outcomes_job ON job_outcomes(job_id)")

            # Append-only accounting event ledger (idempotent ingestion)
            conn.execute(
                """CREATE TABLE IF NOT EXISTS accounting_events(
                       event_id TEXT PRIMARY KEY,
                       job_id TEXT NOT NULL,
                       rcpt TEXT NOT NULL,
                       outcome TEXT NOT NULL,
                       time_logged TEXT NOT NULL,
                       message_id TEXT NOT NULL,
                       dsn_status TEXT NOT NULL,
                       dsn_diag TEXT NOT NULL,
                       source_file TEXT NOT NULL,
                       source_offset_or_line TEXT NOT NULL,
                       created_at TEXT NOT NULL,
                       raw_json TEXT
                   )"""
            )

            # Backward-compatible migrations for old DB files.
            cols = {str(r[1] or "") for r in conn.execute("PRAGMA table_info(job_outcomes)").fetchall()}
            if "last_message_id" not in cols:
                conn.execute("ALTER TABLE job_outcomes ADD COLUMN last_message_id TEXT NOT NULL DEFAULT ''")
            if "last_dsn_status" not in cols:
                conn.execute("ALTER TABLE job_outcomes ADD COLUMN last_dsn_status TEXT NOT NULL DEFAULT ''")
            if "last_dsn_diag" not in cols:
                conn.execute("ALTER TABLE job_outcomes ADD COLUMN last_dsn_diag TEXT NOT NULL DEFAULT ''")

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


            conn.execute(
                """CREATE TABLE IF NOT EXISTS bridge_pull_state(
                       key TEXT PRIMARY KEY,
                       value TEXT NOT NULL,
                       updated_at TEXT NOT NULL
                   )"""
            )

            # Attempt-level delivery learning ledger.
            conn.execute(
                """CREATE TABLE IF NOT EXISTS email_attempt_logs(
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       series_id TEXT NOT NULL,
                       job_id TEXT NOT NULL,
                       campaign_id TEXT NOT NULL,
                       chunk_idx INTEGER NOT NULL,
                       sender_domain TEXT NOT NULL,
                       provider_domain TEXT NOT NULL,
                       attempt_number INTEGER NOT NULL,
                       outcome TEXT NOT NULL,
                       attempt_ts TEXT NOT NULL,
                       created_at TEXT NOT NULL
                   )"""
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_attempt_logs_series ON email_attempt_logs(series_id, attempt_number)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_attempt_logs_pair ON email_attempt_logs(sender_domain, provider_domain, attempt_ts)")

            conn.execute(
                """CREATE TABLE IF NOT EXISTS email_attempt_learning(
                       series_id TEXT PRIMARY KEY,
                       job_id TEXT NOT NULL,
                       campaign_id TEXT NOT NULL,
                       chunk_idx INTEGER NOT NULL,
                       sender_domain TEXT NOT NULL,
                       provider_domain TEXT NOT NULL,
                       attempts_taken INTEGER NOT NULL,
                       outcome TEXT NOT NULL,
                       first_attempt_ts TEXT NOT NULL,
                       last_attempt_ts TEXT NOT NULL,
                       duration_seconds REAL NOT NULL,
                       created_at TEXT NOT NULL,
                       updated_at TEXT NOT NULL
                   )"""
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_attempt_learning_pair ON email_attempt_learning(sender_domain, provider_domain, last_attempt_ts)")

            conn.execute(
                """CREATE TABLE IF NOT EXISTS sender_provider_stats(
                       sender_domain TEXT NOT NULL,
                       provider_domain TEXT NOT NULL,
                       total_series INTEGER NOT NULL,
                       success_series INTEGER NOT NULL,
                       failure_series INTEGER NOT NULL,
                       total_attempts INTEGER NOT NULL,
                       total_duration_seconds REAL NOT NULL,
                       last_outcome TEXT NOT NULL,
                       last_seen_ts TEXT NOT NULL,
                       updated_at TEXT NOT NULL,
                       PRIMARY KEY(sender_domain, provider_domain)
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
                conn.execute("DELETE FROM accounting_events")
                conn.execute("DELETE FROM email_attempt_logs")
                conn.execute("DELETE FROM email_attempt_learning")
                conn.execute("DELETE FROM sender_provider_stats")
                conn.commit()
        finally:
            conn.close()



def _sanitize_form_data(data: dict) -> dict:
    if not isinstance(data, dict):
        return {}
    # Keep recipient lists large enough for real campaigns while preserving a soft-guard
    # against unbounded payload growth.
    default_field_cap = max(10000, int(get_env_int("SHIVA_FORM_FIELD_MAX_CHARS", 400000) or 400000))
    recipients_field_cap = max(default_field_cap, int(get_env_int("SHIVA_FORM_RECIPIENTS_MAX_CHARS", 12000000) or 12000000))
    field_caps = {
        "recipients": recipients_field_cap,
        "maillist_safe": recipients_field_cap,
    }
    out: Dict[str, Any] = {}
    for k, v in data.items():
        if k not in _ALLOWED_FORM_FIELDS:
            continue
        if isinstance(v, bool):
            out[k] = v
        elif v is None:
            out[k] = ""
        else:
            s = str(v)
            cap = int(field_caps.get(k, default_field_cap) or default_field_cap)
            if len(s) > cap:
                s = s[:cap]
            out[k] = s
    return out


def _fit_form_payload(clean: Dict[str, Any]) -> Dict[str, Any]:
    """Best-effort payload guard that keeps JSON valid and prioritizes recipients.

    Old behavior truncated the serialized JSON string, which could corrupt JSON and lose all
    restored form data. This helper keeps payload valid and only trims large free-text fields
    (recipients last) when absolutely necessary.
    """
    data = dict(clean or {})
    payload_max_bytes = max(500000, int(get_env_int("SHIVA_FORM_PAYLOAD_MAX_BYTES", 25000000) or 25000000))
    if len(json.dumps(data, ensure_ascii=False).encode("utf-8")) <= payload_max_bytes:
        return data

    trim_order = ["body", "src_list", "urls_list", "subject", "from_name", "from_email", "maillist_safe", "recipients"]
    for key in trim_order:
        val = data.get(key)
        if not isinstance(val, str) or not val:
            continue
        target = val
        while target:
            target = target[: max(1, int(len(target) * 0.85))]
            data[key] = target
            if len(json.dumps(data, ensure_ascii=False).encode("utf-8")) <= payload_max_bytes:
                return data
        data[key] = ""
        if len(json.dumps(data, ensure_ascii=False).encode("utf-8")) <= payload_max_bytes:
            return data
    return data


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
    clean = _fit_form_payload(_sanitize_form_data(data))
    payload = json.dumps(clean, ensure_ascii=False)

    with DB_LOCK:
        conn = _db_conn()
        try:
            ts = now_iso()
            _exec_upsert_compat(
                conn,
                "INSERT INTO form_state(browser_id, data, updated_at) VALUES(?, ?, ?) "
                "ON CONFLICT(browser_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
                (browser_id, payload, ts),
                "UPDATE form_state SET data=?, updated_at=? WHERE browser_id=?",
                (payload, ts, browser_id),
                "INSERT INTO form_state(browser_id, data, updated_at) VALUES(?, ?, ?)",
                (browser_id, payload, ts),
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
            conn.execute("DELETE FROM accounting_events")
            conn.execute("DELETE FROM email_attempt_logs")
            conn.execute("DELETE FROM email_attempt_learning")
            conn.execute("DELETE FROM sender_provider_stats")
            conn.commit()
        finally:
            conn.close()


# =========================
# Jobs DB helpers (persistence)
# =========================

def _job_snapshot_dict(job: 'SendJob') -> dict:
    """Create a JSON-serializable snapshot of the job (bounded lists)."""
    unique_done = int(job.chunks_done or 0)
    unique_total = int(job.chunks_total or 0)
    if unique_done < 0:
        unique_done = 0
    if unique_total < unique_done:
        unique_total = unique_done

    attempts_total = None
    try:
        attempts_total = int(unique_done + int(job.chunks_backoff or 0))
        if attempts_total < unique_done:
            attempts_total = unique_done
    except Exception:
        attempts_total = None

    return {
        "id": job.id,
        "campaign_id": job.campaign_id,
        "pmta_job_id": job.pmta_job_id or "",
        "bridge_mode": str(job.bridge_mode or ""),
        "smtp_host": job.smtp_host or "",
        "pmta_live": job.pmta_live or {},
        "pmta_live_ts": job.pmta_live_ts or "",
        "pmta_domains": job.pmta_domains or {},
        "pmta_domains_ts": job.pmta_domains_ts or "",
        "pmta_pressure": job.pmta_pressure or {},
        "pmta_pressure_ts": job.pmta_pressure_ts or "",
        "debug_baseline_report": job.debug_baseline_report or {},
        "lane_metrics": job.debug_lane_metrics_snapshot or {},
        "lane_states": job.debug_lane_states_snapshot or {},
        "debug_probe_status": job.debug_probe_status or {},
        "debug_budget_status": job.debug_budget_status or {},
        "debug_lane_executor": job.debug_lane_executor or {},
        "debug_resource_governor": job.debug_resource_governor or {},
        "debug_fallback": job.debug_fallback or {},
        "debug_provider_canon": job.debug_provider_canon or {},
        "debug_backoff_jitter": (job.debug_backoff_jitter or [])[-50:],
        "debug_rollout": job.debug_rollout or {},
        "debug_effective_plan": job.debug_effective_plan or {},
        "debug_wave_status": job.debug_wave_status or {},
        "debug_policy_pack": job.debug_policy_pack or {},
        "debug_learning_policy": job.debug_learning_policy or {},
        "debug_last_lane_pick": job.debug_last_lane_pick or {},
        "debug_last_caps_resolve": job.debug_last_caps_resolve or {},
        "debug_shadow_events": (job.debug_shadow_events or [])[-50:],
        "debug_lane_accounting": job.debug_lane_accounting or {},
        "debug_guardrails": job.debug_guardrails or {},
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
        "chunk_unique_done": unique_done,
        "chunk_unique_total": unique_total,
        "chunk_attempts_total": attempts_total,
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
        "internal_error_counts": job.internal_error_counts or {},
        "internal_last_errors": (job.internal_last_errors or [])[-50:],
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
    if not job or not job.id or job.deleted:
        return

    snap = _job_snapshot_dict(job)
    snapshot = json.dumps(snap, ensure_ascii=False)
    if len(snapshot) > 900000:
        snapshot = snapshot[:900000]

    payload = {
        "id": str(job.id or ""),
        "campaign_id": str(job.campaign_id or ""),
        "created_at": str(job.created_at or now_iso()),
        "updated_at": str(job.updated_at or now_iso()),
        "status": str(job.status or ""),
        "snapshot": snapshot,
    }

    if _db_writer_active():
        with DB_LOCK:
            conn = _db_conn()
            try:
                _db_upsert_job_payload(conn, payload)
                conn.commit()
            finally:
                conn.close()
        return

    if not _db_writer_enqueue({"kind": "job_snapshot", "payload": payload}):
        with DB_LOCK:
            conn = _db_conn()
            try:
                _db_upsert_job_payload(conn, payload)
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

def db_get_outcome(job_id: str, rcpt: str) -> Optional[Dict[str, str]]:
    jid = (job_id or "").strip()
    r = (rcpt or "").strip().lower()
    if not jid or not r:
        return None
    with DB_LOCK:
        conn = _db_conn()
        try:
            row = conn.execute(
                "SELECT status, last_message_id, last_dsn_status, last_dsn_diag "
                "FROM job_outcomes WHERE job_id=? AND rcpt=?",
                (jid, r),
            ).fetchone()
            if not row:
                return None
            return {
                "status": str(row[0] or "").strip().lower(),
                "last_message_id": str(row[1] or ""),
                "last_dsn_status": str(row[2] or ""),
                "last_dsn_diag": str(row[3] or ""),
            }
        finally:
            conn.close()


def db_set_outcome(job_id: str, rcpt: str, status: str, message_id: str = "", dsn_status: str = "", dsn_diag: str = "") -> None:
    jid = (job_id or "").strip()
    r = (rcpt or "").strip().lower()
    st = (status or "").strip().lower()
    if not jid or not r or not st:
        return

    payload = {
        "job_id": jid,
        "rcpt": r,
        "status": st,
        "message_id": str(message_id or ""),
        "dsn_status": str(dsn_status or ""),
        "dsn_diag": str(dsn_diag or ""),
        "updated_at": now_iso(),
    }

    # Keep outcome writes synchronous so job counters remain immediately consistent
    # with /api/job reads (source of truth is SQLite).
    with DB_LOCK:
        conn = _db_conn()
        try:
            _db_set_outcome_payload(conn, payload)
            conn.commit()
        finally:
            conn.close()


def db_get_job_outcome_counts(job_id: str) -> Dict[str, int]:
    """Return persisted outcome counters for a job from SQLite."""
    jid = (job_id or "").strip()
    empty = {"delivered": 0, "bounced": 0, "deferred": 0, "complained": 0}
    if not jid:
        return empty

    with DB_LOCK:
        conn = _db_conn()
        try:
            row = conn.execute(
                "SELECT "
                "SUM(CASE WHEN status='delivered' THEN 1 ELSE 0 END) AS delivered, "
                "SUM(CASE WHEN status='bounced' THEN 1 ELSE 0 END) AS bounced, "
                "SUM(CASE WHEN status='deferred' THEN 1 ELSE 0 END) AS deferred, "
                "SUM(CASE WHEN status='complained' THEN 1 ELSE 0 END) AS complained "
                "FROM job_outcomes WHERE job_id=?",
                (jid,),
            ).fetchone()
        finally:
            conn.close()

    if not row:
        return empty
    return {
        "delivered": int(row[0] or 0),
        "bounced": int(row[1] or 0),
        "deferred": int(row[2] or 0),
        "complained": int(row[3] or 0),
    }


def _sync_job_outcome_counters_from_db(job: 'SendJob') -> None:
    """Refresh in-memory outcome counters from SQLite for consistency after restarts."""
    if not job or not job.id:
        return
    counts = db_get_job_outcome_counts(job.id)
    job.delivered = int(counts.get("delivered") or 0)
    job.bounced = int(counts.get("bounced") or 0)
    job.deferred = int(counts.get("deferred") or 0)
    job.complained = int(counts.get("complained") or 0)


def _email_domain(raw_email: Any) -> str:
    s = str(raw_email or "").strip().lower()
    if "@" not in s:
        return ""
    dom = s.rsplit("@", 1)[-1].strip().lower()
    if not dom or "." not in dom:
        return ""
    return dom


def normalize_accounting_event(line_or_json: Any, default_job_id: str = "") -> Optional[dict]:
    payload = line_or_json if isinstance(line_or_json, dict) else {}

    def _pick(*keys: str) -> str:
        for k in keys:
            v = payload.get(k)
            if isinstance(v, (str, int, float)) and str(v).strip():
                return str(v).strip()
        return ""

    raw_outcome = _pick("outcome", "status", "result", "event")
    key = raw_outcome.strip().upper()
    mapped = {
        "D": "DELIVERED", "DELIVERED": "DELIVERED", "SUCCESS": "DELIVERED",
        "B": "BOUNCED", "BOUNCED": "BOUNCED", "HARD_BOUNCE": "BOUNCED",
        "R": "DEFERRED", "DEFERRED": "DEFERRED", "TEMPFAIL": "DEFERRED",
        "C": "COMPLAINED", "COMPLAINED": "COMPLAINED", "COMPLAINT": "COMPLAINED",
    }.get(key, "")
    if not mapped:
        return None

    rcpt = _pick("rcpt", "recipient", "email", "recipient_email", "to")
    rcpt = rcpt.lower()
    rcpt_domain = _email_domain(rcpt)
    sender_identity = _pick("sender", "sender_email", "mail_from", "from", "sender_domain") or "unknown_sender"
    sender_identity = sender_identity.strip().lower()
    if "@" in sender_identity:
        sender_identity = sender_identity

    return {
        "job_id": (_pick("job_id", "campaign_id", "x_job_id", "x_campaign_id") or str(default_job_id or "").strip().lower()),
        "sender_identity": sender_identity,
        "rcpt_email": rcpt,
        "rcpt_domain": rcpt_domain,
        "outcome": mapped,
        "ts": _pick("time_logged", "ts", "timestamp", "created_at") or now_iso(),
        "raw_reason": _pick("dsn_diag", "response", "reason", "detail", "dsn_status"),
    }


class AccountingReconEngine:
    def __init__(self, *, job_id: str, lane_metrics: Optional[LaneMetrics], lane_registry: Optional[LaneRegistry], provider_canon: Any = None,
                 sender_idx_by_rcpt: Optional[Dict[str, int]] = None, lock: Optional[threading.RLock] = None,
                 debug: bool = False, export: bool = False, dedupe_max_ids: int = 200000):
        self.job_id = str(job_id or "").strip().lower()
        self.lane_metrics = lane_metrics
        self.lane_registry = lane_registry
        self.provider_canon = provider_canon
        self.sender_idx_by_rcpt = sender_idx_by_rcpt if isinstance(sender_idx_by_rcpt, dict) else {}
        self.lock = lock
        self.debug = bool(debug)
        self.export = bool(export)
        self._dedupe_max_ids = max(1000, int(dedupe_max_ids or 200000))
        self._seen_ids: Set[str] = set()
        self._seen_fifo: deque = deque(maxlen=self._dedupe_max_ids)
        self._cursor_rowid = 0
        self.lines_processed_total = 0
        self.lines_processed_delta = 0
        self.last_recon_ts = ""
        self._lane_totals: Dict[str, dict] = {}
        self._provider_totals: Dict[str, dict] = {}

    def _event_id(self, ev: dict) -> str:
        payload = "|".join([
            str(ev.get("job_id") or ""),
            str(ev.get("ts") or ""),
            str(ev.get("rcpt_email") or ""),
            str(ev.get("outcome") or ""),
            str(ev.get("sender_identity") or ""),
            str(ev.get("raw_reason") or ""),
        ])
        return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()

    def _remember(self, eid: str) -> bool:
        if eid in self._seen_ids:
            return False
        if len(self._seen_fifo) >= self._dedupe_max_ids:
            old = self._seen_fifo.popleft()
            self._seen_ids.discard(old)
        self._seen_fifo.append(eid)
        self._seen_ids.add(eid)
        return True

    def _fetch_rows(self, limit: int = 4000) -> List[dict]:
        rows: List[dict] = []
        with DB_LOCK:
            conn = _db_conn()
            try:
                rs = conn.execute(
                    "SELECT rowid, job_id, rcpt, outcome, time_logged, dsn_diag, raw_json FROM accounting_events WHERE job_id=? AND rowid>? ORDER BY rowid ASC LIMIT ?",
                    (self.job_id, int(self._cursor_rowid), int(limit)),
                ).fetchall()
            finally:
                conn.close()
        for r in rs:
            raw_obj = {}
            raw_json = str(r[6] or "")
            if raw_json:
                try:
                    raw_obj = json.loads(raw_json)
                except Exception:
                    raw_obj = {}
            raw_obj.update({
                "job_id": str(r[1] or ""),
                "rcpt": str(r[2] or ""),
                "outcome": str(r[3] or ""),
                "time_logged": str(r[4] or ""),
                "dsn_diag": str(r[5] or ""),
                "rowid": int(r[0] or 0),
            })
            rows.append(raw_obj)
        return rows

    def _resolve_lane(self, ev: dict) -> Tuple[Tuple[int, str], str]:
        rcpt = str(ev.get("rcpt_email") or "").strip().lower()
        sender_idx = int(self.sender_idx_by_rcpt.get(rcpt, 0) or 0)
        provider_domain = str(ev.get("rcpt_domain") or "").strip().lower()
        provider_key = provider_domain
        if getattr(self.provider_canon, "enforce", False):
            provider_key = str(self.provider_canon.group_for_domain(provider_domain) or provider_domain)
        lane_key = (sender_idx, provider_key)
        return lane_key, provider_key

    def poll_and_update(self, job: Any, now_ts: float) -> dict:
        delta = {"delivered": 0, "bounced": 0, "deferred": 0, "complained": 0, "lanes": 0}
        lane_delta: Dict[str, dict] = {}
        processed = 0
        while True:
            rows = self._fetch_rows()
            if not rows:
                break
            for row in rows:
                processed += 1
                self._cursor_rowid = max(self._cursor_rowid, int(row.get("rowid") or 0))
                ev = normalize_accounting_event(row, default_job_id=self.job_id)
                if not ev or str(ev.get("job_id") or "").strip().lower() != self.job_id:
                    continue
                eid = self._event_id(ev)
                if not self._remember(eid):
                    continue
                lane_key, provider_key = self._resolve_lane(ev)
                lane_id = f"{lane_key[0]}|{lane_key[1]}"
                if lane_id not in lane_delta:
                    lane_delta[lane_id] = {"lane_key": lane_key, "delivered": 0, "bounced": 0, "deferred": 0, "complained": 0}
                out = str(ev.get("outcome") or "")
                if out == "DELIVERED":
                    lane_delta[lane_id]["delivered"] += 1
                    delta["delivered"] += 1
                elif out == "BOUNCED":
                    lane_delta[lane_id]["bounced"] += 1
                    delta["bounced"] += 1
                elif out == "DEFERRED":
                    lane_delta[lane_id]["deferred"] += 1
                    delta["deferred"] += 1
                elif out == "COMPLAINED":
                    lane_delta[lane_id]["complained"] += 1
                    delta["complained"] += 1

                p = self._provider_totals.setdefault(provider_key or "unknown_provider", {"delivered": 0, "bounced": 0, "deferred": 0, "complained": 0})
                k = out.lower()
                if k in p:
                    p[k] += 1

            if len(rows) < 4000:
                break

        delta["lanes"] = len(lane_delta)
        for lane_id, c in lane_delta.items():
            lk = c["lane_key"]
            if self.lane_metrics:
                self.lane_metrics.on_accounting_delta(lk, delivered=c["delivered"], bounced=c["bounced"], deferred=c["deferred"], complained=c["complained"])
            lane_tot = self._lane_totals.setdefault(lane_id, {"sender_idx": int(lk[0]), "provider_key": str(lk[1]), "delivered": 0, "bounced": 0, "deferred": 0, "complained": 0})
            for kk in ("delivered", "bounced", "deferred", "complained"):
                lane_tot[kk] = int(lane_tot.get(kk) or 0) + int(c[kk] or 0)
            if self.lane_registry and self.lane_metrics:
                snap = (self.lane_metrics.snapshot().get("lanes") or {}).get(lane_id) or {}
                self.lane_registry.update_from_metrics(now_ts, lk, snap)

        self.lines_processed_total += processed
        self.lines_processed_delta = processed
        self.last_recon_ts = now_iso()
        if self.export and hasattr(job, "debug_lane_accounting"):
            job.debug_lane_accounting = self.snapshot()
        return delta

    def snapshot(self, max_lanes: int = 25) -> dict:
        lanes = list(self._lane_totals.values())
        lanes.sort(key=lambda x: (int(x.get("deferred") or 0), int(x.get("delivered") or 0)), reverse=True)
        lane_rows = []
        for item in lanes[:max(1, int(max_lanes))]:
            total = int(item.get("delivered") or 0) + int(item.get("bounced") or 0) + int(item.get("deferred") or 0) + int(item.get("complained") or 0)
            lane_rows.append({
                **item,
                "total": total,
                "deferred_rate": float(int(item.get("deferred") or 0) / max(1, total)),
                "bounce_rate": float(int(item.get("bounced") or 0) / max(1, total)),
                "complaint_rate": float(int(item.get("complained") or 0) / max(1, total)),
            })
        provider_rows = []
        for k, v in sorted(self._provider_totals.items(), key=lambda kv: sum(int(kv[1].get(x) or 0) for x in ("delivered", "bounced", "deferred", "complained")), reverse=True):
            t = sum(int(v.get(x) or 0) for x in ("delivered", "bounced", "deferred", "complained"))
            provider_rows.append({"provider": k, **v, "total": t, "deferred_rate": float(int(v.get("deferred") or 0) / max(1, t))})
        return {
            "last_recon_ts": self.last_recon_ts,
            "lines_processed_total": int(self.lines_processed_total),
            "lines_processed_delta": int(self.lines_processed_delta),
            "providers": provider_rows[:20],
            "lanes": lane_rows,
        }


def _learning_series_id(job_id: str, chunk_idx: int, provider_domain: str) -> str:
    return f"{str(job_id or '').strip()}:{int(chunk_idx or 0)}:{str(provider_domain or '').strip().lower()}"


def db_log_email_attempt(*, job_id: str, campaign_id: str, chunk_idx: int, sender_domain: str, provider_domain: str, attempt_number: int, outcome: str) -> None:
    series_id = _learning_series_id(job_id, chunk_idx, provider_domain)
    payload = (
        series_id,
        str(job_id or "").strip(),
        str(campaign_id or "").strip(),
        int(chunk_idx or 0),
        str(sender_domain or "").strip().lower(),
        str(provider_domain or "").strip().lower(),
        max(1, int(attempt_number or 1)),
        str(outcome or "unknown").strip().lower(),
        now_iso(),
        now_iso(),
    )
    with DB_LOCK:
        conn = _db_conn()
        try:
            conn.execute(
                "INSERT INTO email_attempt_logs(series_id, job_id, campaign_id, chunk_idx, sender_domain, provider_domain, attempt_number, outcome, attempt_ts, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                payload,
            )
            conn.commit()
        finally:
            conn.close()


def db_finalize_email_learning(*, job_id: str, campaign_id: str, chunk_idx: int, sender_domain: str, provider_domain: str, attempts_taken: int, outcome: str) -> None:
    series_id = _learning_series_id(job_id, chunk_idx, provider_domain)
    sender_dom = str(sender_domain or "").strip().lower()
    provider_dom = str(provider_domain or "").strip().lower()
    final_outcome = "success" if str(outcome or "").strip().lower() == "success" else "failure"
    attempts_n = max(1, int(attempts_taken or 1))
    now_ts = now_iso()

    with DB_LOCK:
        conn = _db_conn()
        try:
            first_last = conn.execute(
                "SELECT MIN(attempt_ts), MAX(attempt_ts) FROM email_attempt_logs WHERE series_id=?",
                (series_id,),
            ).fetchone()
            first_attempt_ts = str((first_last[0] if first_last and first_last[0] else now_ts) or now_ts)
            last_attempt_ts = str((first_last[1] if first_last and first_last[1] else now_ts) or now_ts)

            duration_s = 0.0
            try:
                dt0 = datetime.fromisoformat(first_attempt_ts.replace("Z", "+00:00"))
                dt1 = datetime.fromisoformat(last_attempt_ts.replace("Z", "+00:00"))
                duration_s = max(0.0, (dt1 - dt0).total_seconds())
            except Exception:
                duration_s = 0.0

            existing = conn.execute(
                "SELECT outcome FROM email_attempt_learning WHERE series_id=?",
                (series_id,),
            ).fetchone()
            already_finalized = bool(existing and str(existing[0] or "").strip())

            _exec_upsert_compat(
                conn,
                "INSERT INTO email_attempt_learning(series_id, job_id, campaign_id, chunk_idx, sender_domain, provider_domain, attempts_taken, outcome, first_attempt_ts, last_attempt_ts, duration_seconds, created_at, updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(series_id) DO UPDATE SET sender_domain=excluded.sender_domain, provider_domain=excluded.provider_domain, attempts_taken=excluded.attempts_taken, outcome=excluded.outcome, first_attempt_ts=excluded.first_attempt_ts, last_attempt_ts=excluded.last_attempt_ts, duration_seconds=excluded.duration_seconds, updated_at=excluded.updated_at",
                (series_id, str(job_id or ""), str(campaign_id or ""), int(chunk_idx or 0), sender_dom, provider_dom, attempts_n, final_outcome, first_attempt_ts, last_attempt_ts, float(duration_s), now_ts, now_ts),
                "UPDATE email_attempt_learning SET sender_domain=?, provider_domain=?, attempts_taken=?, outcome=?, first_attempt_ts=?, last_attempt_ts=?, duration_seconds=?, updated_at=? WHERE series_id=?",
                (sender_dom, provider_dom, attempts_n, final_outcome, first_attempt_ts, last_attempt_ts, float(duration_s), now_ts, series_id),
                "INSERT INTO email_attempt_learning(series_id, job_id, campaign_id, chunk_idx, sender_domain, provider_domain, attempts_taken, outcome, first_attempt_ts, last_attempt_ts, duration_seconds, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (series_id, str(job_id or ""), str(campaign_id or ""), int(chunk_idx or 0), sender_dom, provider_dom, attempts_n, final_outcome, first_attempt_ts, last_attempt_ts, float(duration_s), now_ts, now_ts),
            )

            if not already_finalized and sender_dom and provider_dom:
                prev = conn.execute(
                    "SELECT total_series, success_series, failure_series, total_attempts, total_duration_seconds FROM sender_provider_stats WHERE sender_domain=? AND provider_domain=?",
                    (sender_dom, provider_dom),
                ).fetchone()
                t = int(prev[0] or 0) if prev else 0
                s = int(prev[1] or 0) if prev else 0
                f = int(prev[2] or 0) if prev else 0
                a = int(prev[3] or 0) if prev else 0
                d = float(prev[4] or 0.0) if prev else 0.0
                t += 1
                if final_outcome == "success":
                    s += 1
                else:
                    f += 1
                a += attempts_n
                d += float(duration_s)
                _exec_upsert_compat(
                    conn,
                    "INSERT INTO sender_provider_stats(sender_domain, provider_domain, total_series, success_series, failure_series, total_attempts, total_duration_seconds, last_outcome, last_seen_ts, updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(sender_domain, provider_domain) DO UPDATE SET total_series=excluded.total_series, success_series=excluded.success_series, failure_series=excluded.failure_series, total_attempts=excluded.total_attempts, total_duration_seconds=excluded.total_duration_seconds, last_outcome=excluded.last_outcome, last_seen_ts=excluded.last_seen_ts, updated_at=excluded.updated_at",
                    (sender_dom, provider_dom, t, s, f, a, d, final_outcome, last_attempt_ts, now_ts),
                    "UPDATE sender_provider_stats SET total_series=?, success_series=?, failure_series=?, total_attempts=?, total_duration_seconds=?, last_outcome=?, last_seen_ts=?, updated_at=? WHERE sender_domain=? AND provider_domain=?",
                    (t, s, f, a, d, final_outcome, last_attempt_ts, now_ts, sender_dom, provider_dom),
                    "INSERT INTO sender_provider_stats(sender_domain, provider_domain, total_series, success_series, failure_series, total_attempts, total_duration_seconds, last_outcome, last_seen_ts, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (sender_dom, provider_dom, t, s, f, a, d, final_outcome, last_attempt_ts, now_ts),
                )

            conn.commit()
        finally:
            conn.close()


def _provider_dynamic_backoff_policy(provider_domain: str, base_backoff_s: float, max_backoff_s: float, max_retry_cap: int) -> Dict[str, Any]:
    """Return provider-level adaptive retry/backoff policy using recency-weighted history.

    Policy goals:
    - Fast + reliable provider behavior => fewer retries + shorter waits.
    - Slow / failure-prone behavior => more retries + longer waits.
    - Continuous adaptation via exponential recency weighting.
    """
    provider = str(provider_domain or "").strip().lower()
    base_wait = max(1.0, float(base_backoff_s or 1.0))
    max_wait = max(base_wait, float(max_backoff_s or base_wait))
    retry_cap = max(0, int(max_retry_cap or 0))
    if not provider:
        return {
            "retry_cap": retry_cap,
            "backoff_base_s": base_wait,
            "backoff_max_s": max_wait,
            "sample_size": 0,
            "trend": "unknown",
        }

    with DB_LOCK:
        conn = _db_conn()
        try:
            rows = conn.execute(
                "SELECT outcome, attempts_taken, duration_seconds FROM email_attempt_learning WHERE provider_domain=? ORDER BY last_attempt_ts DESC LIMIT 120",
                (provider,),
            ).fetchall()
        finally:
            conn.close()

    if not rows:
        return {
            "retry_cap": retry_cap,
            "backoff_base_s": base_wait,
            "backoff_max_s": max_wait,
            "sample_size": 0,
            "trend": "unknown",
        }

    weighted_success = 0.0
    weighted_failure = 0.0
    weighted_attempts = 0.0
    weighted_duration = 0.0
    weight_sum = 0.0
    decay = 0.965

    for idx, row in enumerate(rows):
        w = decay ** idx
        outcome = str(row[0] or "").strip().lower()
        attempts_taken = max(1.0, float(row[1] or 1.0))
        duration_s = max(0.0, float(row[2] or 0.0))
        is_success = 1.0 if outcome == "success" else 0.0

        weighted_success += w * is_success
        weighted_failure += w * (1.0 - is_success)
        weighted_attempts += w * attempts_taken
        weighted_duration += w * duration_s
        weight_sum += w

    if weight_sum <= 0.0:
        return {
            "retry_cap": retry_cap,
            "backoff_base_s": base_wait,
            "backoff_max_s": max_wait,
            "sample_size": len(rows),
            "trend": "unknown",
        }

    success_rate = weighted_success / weight_sum
    failure_rate = weighted_failure / weight_sum
    avg_attempts = weighted_attempts / weight_sum
    avg_duration = weighted_duration / weight_sum

    # Baselines from current global defaults to infer "fast" vs "slow".
    duration_ratio = avg_duration / max(base_wait, 1.0)
    attempts_ratio = avg_attempts / max(retry_cap + 1.0, 1.0)

    # Quality score > 0 means healthier provider recently.
    quality = (success_rate - failure_rate) - 0.30 * max(0.0, attempts_ratio - 1.0) - 0.20 * max(0.0, duration_ratio - 1.0)

    if quality >= 0.25:
        retry_factor = 0.55
        wait_factor = 0.65
        trend = "fast_success"
    elif quality >= 0.05:
        retry_factor = 0.80
        wait_factor = 0.85
        trend = "stable"
    elif quality <= -0.30:
        retry_factor = 1.40
        wait_factor = 1.55
        trend = "slow_or_failing"
    elif quality <= -0.10:
        retry_factor = 1.20
        wait_factor = 1.25
        trend = "degrading"
    else:
        retry_factor = 1.0
        wait_factor = 1.0
        trend = "mixed"

    tuned_retry_cap = min(10, max(0, int(round(max(retry_cap, 1) * retry_factor))))
    if retry_cap == 0:
        tuned_retry_cap = 0

    tuned_base = max(5.0, base_wait * wait_factor)
    tuned_max = max(tuned_base, min(max_wait * 3.0, max_wait * wait_factor))

    return {
        "retry_cap": tuned_retry_cap,
        "backoff_base_s": float(tuned_base),
        "backoff_max_s": float(tuned_max),
        "sample_size": len(rows),
        "trend": trend,
        "success_rate": float(success_rate),
        "avg_attempts": float(avg_attempts),
        "avg_duration_s": float(avg_duration),
    }


def learning_recommendation(provider_domain: str, sender_domains: List[str], max_retry_cap: int, *, base_backoff_s: float = 60.0, max_backoff_s: float = 1800.0) -> Dict[str, Any]:
    provider = str(provider_domain or "").strip().lower()
    if not provider or not sender_domains:
        return {"sender_domains": list(sender_domains or []), "retry_cap": max(0, int(max_retry_cap or 0))}
    ordered = list(dict.fromkeys([str(x or "").strip().lower() for x in sender_domains if str(x or "").strip()]))
    if not ordered:
        return {"sender_domains": [], "retry_cap": max(0, int(max_retry_cap or 0))}

    stats: Dict[str, Dict[str, float]] = {}
    with DB_LOCK:
        conn = _db_conn()
        try:
            placeholders = ",".join(["?"] * len(ordered))
            rows = conn.execute(
                f"SELECT sender_domain, total_series, success_series FROM sender_provider_stats WHERE provider_domain=? AND sender_domain IN ({placeholders})",
                [provider] + ordered,
            ).fetchall()
        finally:
            conn.close()

    for row in rows:
        dom = str(row[0] or "").strip().lower()
        total = int(row[1] or 0)
        succ = int(row[2] or 0)
        rate = (succ + 1.0) / (total + 2.0)  # smoothed score for online adaptation
        stats[dom] = {"total": total, "success": succ, "rate": rate}

    ordered.sort(key=lambda d: (float(stats.get(d, {}).get("rate", 0.5)), float(stats.get(d, {}).get("total", 0))), reverse=True)

    provider_policy = _provider_dynamic_backoff_policy(provider, base_backoff_s, max_backoff_s, max_retry_cap)
    retry_cap = max(0, int(provider_policy.get("retry_cap", max_retry_cap) or max_retry_cap))
    top = stats.get(ordered[0]) if ordered else None
    provider_trend = str(provider_policy.get("trend") or "unknown")
    if top and int(top.get("total", 0)) >= 12 and provider_trend not in {"slow_or_failing", "degrading"}:
        r = float(top.get("rate", 0.5))
        if r < 0.35:
            retry_cap = min(retry_cap, 1)
        elif r < 0.5:
            retry_cap = min(retry_cap, 2)

    return {
        "sender_domains": ordered,
        "retry_cap": retry_cap,
        "top_sender_success_rate": float(top.get("rate", 0.0)) if top else 0.0,
        "top_sender_samples": int(top.get("total", 0)) if top else 0,
        "provider_backoff_base_s": float(provider_policy.get("backoff_base_s", base_backoff_s) or base_backoff_s),
        "provider_backoff_max_s": float(provider_policy.get("backoff_max_s", max_backoff_s) or max_backoff_s),
        "provider_trend": provider_trend,
        "provider_samples": int(provider_policy.get("sample_size") or 0),
        "provider_success_rate": float(provider_policy.get("success_rate", 0.0) or 0.0),
        # additive export for richer policy consumers (backward compatible)
        "policy": {
            "tier": str(provider_trend or "unknown").upper(),
            "confidence": min(1.0, float(provider_policy.get("sample_size") or 0) / 200.0),
            "provider_backoff": {
                "base_s": float(provider_policy.get("backoff_base_s", base_backoff_s) or base_backoff_s),
                "max_s": float(provider_policy.get("backoff_max_s", max_backoff_s) or max_backoff_s),
            },
        },
    }


def db_learning_summary(limit: int = 25) -> Dict[str, Any]:
    lim = max(1, min(100, int(limit or 25)))
    out: Dict[str, Any] = {"providers": [], "senders": [], "pairs": [], "attempts_to_success": {}, "generated_at": now_iso()}
    with DB_LOCK:
        conn = _db_conn()
        try:
            pair_rows = conn.execute(
                "SELECT sender_domain, provider_domain, total_series, success_series, failure_series, total_attempts, total_duration_seconds, last_seen_ts "
                "FROM sender_provider_stats ORDER BY total_series DESC, success_series DESC LIMIT ?",
                (lim,),
            ).fetchall()
            provider_rows = conn.execute(
                "SELECT provider_domain, COUNT(*) AS pair_count, SUM(total_series), SUM(success_series), SUM(total_attempts), SUM(total_duration_seconds) "
                "FROM sender_provider_stats GROUP BY provider_domain ORDER BY SUM(total_series) DESC LIMIT ?",
                (lim,),
            ).fetchall()
            sender_rows = conn.execute(
                "SELECT sender_domain, COUNT(*) AS pair_count, SUM(total_series), SUM(success_series), SUM(total_attempts), SUM(total_duration_seconds) "
                "FROM sender_provider_stats GROUP BY sender_domain ORDER BY SUM(total_series) DESC LIMIT ?",
                (lim,),
            ).fetchall()
            succ_row = conn.execute(
                "SELECT AVG(attempts_taken), AVG(duration_seconds) FROM email_attempt_learning WHERE outcome='success'",
            ).fetchone()
        finally:
            conn.close()

    for r in pair_rows:
        total = int(r[2] or 0)
        succ = int(r[3] or 0)
        out["pairs"].append({
            "sender_domain": str(r[0] or ""),
            "provider_domain": str(r[1] or ""),
            "total_series": total,
            "success_series": succ,
            "failure_series": int(r[4] or 0),
            "success_rate": (float(succ) / float(total)) if total > 0 else 0.0,
            "avg_attempts": (float(r[5] or 0.0) / float(total)) if total > 0 else 0.0,
            "avg_duration_seconds": (float(r[6] or 0.0) / float(total)) if total > 0 else 0.0,
            "last_seen_ts": str(r[7] or ""),
        })

    for rows, key in ((provider_rows, "providers"), (sender_rows, "senders")):
        for r in rows:
            total = int(r[2] or 0)
            succ = int(r[3] or 0)
            out[key].append({
                "domain": str(r[0] or ""),
                "pair_count": int(r[1] or 0),
                "total_series": total,
                "success_rate": (float(succ) / float(total)) if total > 0 else 0.0,
                "avg_attempts": (float(r[4] or 0.0) / float(total)) if total > 0 else 0.0,
                "avg_duration_seconds": (float(r[5] or 0.0) / float(total)) if total > 0 else 0.0,
            })

    out["attempts_to_success"] = {
        "avg_attempts": float((succ_row[0] if succ_row and succ_row[0] is not None else 0.0) or 0.0),
        "avg_duration_seconds": float((succ_row[1] if succ_row and succ_row[1] is not None else 0.0) or 0.0),
    }
    return out


def _job_provider_breakdown(job_id: str, limit: int = 6) -> List[dict]:
    """Best-effort provider/domain breakdown from recent accounting ledger rows."""
    jid = str(job_id or "").strip().lower()
    if not jid:
        return []
    by_domain: Dict[str, Dict[str, int]] = {}
    try:
        with DB_LOCK:
            conn = _db_conn()
            try:
                rows = conn.execute(
                    "SELECT rcpt, outcome FROM accounting_events "
                    "WHERE job_id=? ORDER BY created_at DESC LIMIT 1200",
                    (jid,),
                ).fetchall()
            finally:
                conn.close()
    except Exception:
        return []

    for row in rows:
        rcpt = str((row[0] if row else "") or "")
        outcome = str((row[1] if row else "") or "").strip().lower()
        if outcome not in {"delivered", "deferred", "bounced", "complained"}:
            continue
        dom = _email_domain(rcpt)
        if not dom:
            continue
        if dom not in by_domain:
            by_domain[dom] = {"delivered": 0, "deferred": 0, "bounced": 0, "complained": 0, "total": 0}
        by_domain[dom][outcome] = int(by_domain[dom].get(outcome, 0) or 0) + 1
        by_domain[dom]["total"] = int(by_domain[dom].get("total", 0) or 0) + 1

    out: List[dict] = []
    for dom, counts in by_domain.items():
        total = int(counts.get("total") or 0)
        if total <= 0:
            continue
        out.append(
            {
                "domain": dom,
                "total": total,
                "delivered": int(counts.get("delivered") or 0),
                "deferred": int(counts.get("deferred") or 0),
                "bounced": int(counts.get("bounced") or 0),
                "complained": int(counts.get("complained") or 0),
            }
        )
    out.sort(key=lambda x: (int(x.get("total") or 0), str(x.get("domain") or "")), reverse=True)
    return out[: max(1, int(limit or 6))]


def db_insert_accounting_event(event: Dict[str, Any]) -> bool:
    eid = str((event or {}).get("event_id") or "").strip()
    if not eid:
        return False

    payload = dict(event or {})
    # Insert synchronously to guarantee deduplication decisions are made against
    # the current DB state before we update in-memory job counters.
    with DB_LOCK:
        conn = _db_conn()
        try:
            ok = _db_insert_accounting_event_payload(conn, payload)
            conn.commit()
            return ok
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


def db_set_app_config(key: str, value: str) -> bool:
    k = (key or "").strip()
    if not k:
        return False
    v = "" if value is None else str(value)
    if len(v) > 20000:
        v = v[:20000]
    upsert_sql = "INSERT INTO app_config(key, value, updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at"
    for attempt in range(3):
        try:
            with DB_LOCK:
                conn = _db_conn()
                try:
                    ts = now_iso()
                    _exec_upsert_compat(
                        conn,
                        upsert_sql,
                        (k, v, ts),
                        "UPDATE app_config SET value=?, updated_at=? WHERE key=?",
                        (v, ts, k),
                        "INSERT INTO app_config(key, value, updated_at) VALUES(?,?,?)",
                        (k, v, ts),
                    )
                    conn.commit()
                finally:
                    conn.close()
            return True
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() and attempt < 2:
                time.sleep(0.15 * (attempt + 1))
                continue
            app.logger.exception("db_set_app_config failed for key=%s", k)
            return False
        except Exception:
            app.logger.exception("db_set_app_config failed for key=%s", k)
            return False
    return False


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
        job.pmta_job_id = str(s.get("pmta_job_id") or jid)
        job.bridge_mode = str(s.get("bridge_mode") or "")
        job.smtp_host = str(s.get("smtp_host") or "")
        job.pmta_live = (s.get("pmta_live") if isinstance(s.get("pmta_live"), dict) else {}) or {}
        job.pmta_live_ts = str(s.get("pmta_live_ts") or "")
        job.pmta_domains = (s.get("pmta_domains") if isinstance(s.get("pmta_domains"), dict) else {}) or {}
        job.pmta_domains_ts = str(s.get("pmta_domains_ts") or "")
        job.pmta_pressure = (s.get("pmta_pressure") if isinstance(s.get("pmta_pressure"), dict) else {}) or {}
        job.pmta_pressure_ts = str(s.get("pmta_pressure_ts") or "")
        job.debug_baseline_report = (s.get("debug_baseline_report") if isinstance(s.get("debug_baseline_report"), dict) else {}) or {}
        job.debug_lane_metrics_snapshot = (s.get("lane_metrics") if isinstance(s.get("lane_metrics"), dict) else {}) or {}
        job.debug_lane_states_snapshot = (s.get("lane_states") if isinstance(s.get("lane_states"), dict) else {}) or {}
        job.debug_probe_status = (s.get("debug_probe_status") if isinstance(s.get("debug_probe_status"), dict) else {}) or {}
        job.debug_budget_status = (s.get("debug_budget_status") if isinstance(s.get("debug_budget_status"), dict) else {}) or {}
        job.debug_lane_executor = (s.get("debug_lane_executor") if isinstance(s.get("debug_lane_executor"), dict) else {}) or {}
        job.debug_resource_governor = (s.get("debug_resource_governor") if isinstance(s.get("debug_resource_governor"), dict) else {}) or {}
        job.debug_fallback = (s.get("debug_fallback") if isinstance(s.get("debug_fallback"), dict) else {}) or {}
        job.debug_provider_canon = (s.get("debug_provider_canon") if isinstance(s.get("debug_provider_canon"), dict) else {}) or {}
        job.debug_backoff_jitter = list(s.get("debug_backoff_jitter") or [])
        job.debug_rollout = (s.get("debug_rollout") if isinstance(s.get("debug_rollout"), dict) else {}) or {}
        job.debug_effective_plan = (s.get("debug_effective_plan") if isinstance(s.get("debug_effective_plan"), dict) else {}) or {}
        job.debug_wave_status = (s.get("debug_wave_status") if isinstance(s.get("debug_wave_status"), dict) else {}) or {}
        job.debug_policy_pack = (s.get("debug_policy_pack") if isinstance(s.get("debug_policy_pack"), dict) else {}) or {}
        job.debug_learning_policy = (s.get("debug_learning_policy") if isinstance(s.get("debug_learning_policy"), dict) else {}) or {}
        job.debug_last_lane_pick = (s.get("debug_last_lane_pick") if isinstance(s.get("debug_last_lane_pick"), dict) else {}) or {}
        job.debug_last_caps_resolve = (s.get("debug_last_caps_resolve") if isinstance(s.get("debug_last_caps_resolve"), dict) else {}) or {}
        job.debug_shadow_events = list(s.get("debug_shadow_events") or [])
        job.debug_lane_accounting = (s.get("debug_lane_accounting") if isinstance(s.get("debug_lane_accounting"), dict) else {}) or {}
        job.debug_guardrails = (s.get("debug_guardrails") if isinstance(s.get("debug_guardrails"), dict) else {}) or {}
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
        job.internal_error_counts = dict(s.get("internal_error_counts") or {})
        job.internal_last_errors = list(s.get("internal_last_errors") or [])

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
            _sync_job_outcome_counters_from_db(job)
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

    clean = _fit_form_payload(_sanitize_form_data(data))
    payload = json.dumps(clean, ensure_ascii=False)

    ts = now_iso()
    with DB_LOCK:
        conn = _db_conn()
        try:
            _exec_upsert_compat(
                conn,
                "INSERT INTO campaign_form(campaign_id, data, updated_at) VALUES(?,?,?) "
                "ON CONFLICT(campaign_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
                (campaign_id, payload, ts),
                "UPDATE campaign_form SET data=?, updated_at=? WHERE campaign_id=?",
                (payload, ts, campaign_id),
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
start_db_writer_if_needed()
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
    - Preserves placeholders: [URL], [SRC], [EMAIL], [MAIL] exactly.
    - Keeps meaning, does not add new claims.
    """
    if not token:
        raise ValueError("AI token is required")

    subj_in = subjects[:30] if subjects else ["(no subject)"]
    body_in = body[:12000]

    sys = (
        "You rewrite email subject lines and body for clarity and professionalism, "
        "keeping the same meaning. Do NOT add new claims, promotions, or calls to action. "
        "Preserve these placeholders exactly (do not remove/rename them): [URL], [SRC], [EMAIL], [MAIL]. "
        "Keep the output language the same as input. "
        "Return ONLY valid JSON with keys: subjects (array of strings), body (string)."
    )

    user = {
        "subject_lines": subj_in,
        "body_format": body_format,
        "body": body_in,
        "constraints": {
            "preserve_placeholders": ["[URL]", "[SRC]", "[EMAIL]", "[MAIL]"],
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

    .info-wrap{ position:relative; display:inline-flex; align-items:center; margin-inline-start:6px; vertical-align:middle; }
    .info-dot{
      width:17px;
      height:17px;
      border-radius:999px;
      border:1px solid rgba(122,167,255,.55);
      background: rgba(122,167,255,.18);
      color: rgba(255,255,255,.95);
      font-size:11px;
      font-weight:800;
      display:inline-flex;
      align-items:center;
      justify-content:center;
      cursor:help;
      line-height:1;
      user-select:none;
    }
    .info-tip{
      position:absolute;
      bottom: calc(100% + 8px);
      left: 50%;
      transform: translateX(-50%) translateY(4px);
      min-width: 220px;
      max-width: min(340px, 75vw);
      padding: 9px 10px;
      border-radius: 10px;
      border: 1px solid rgba(255,255,255,.2);
      background: rgba(3,7,17,.96);
      color: rgba(255,255,255,.92);
      font-size: 12px;
      line-height: 1.5;
      box-shadow: 0 12px 30px rgba(0,0,0,.35);
      opacity: 0;
      pointer-events: none;
      transition: opacity .12s ease, transform .12s ease;
      z-index: 30;
      white-space: normal;
    }
    .info-wrap:hover .info-tip,
    .info-wrap:focus-within .info-tip{
      opacity: 1;
      transform: translateX(-50%) translateY(0);
    }
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
          <div class="mini">Use <code>[URL]</code> in subject/body. Replaced per chunk in line order (cycles back to first line after the last).</div>
        </div>
        <div>
          <label>SRC list (one per line)</label>
          <textarea name="src_list" placeholder="https://cdn.example.com/img1.png
https://cdn.example.com/img2.png" style="min-height:90px"></textarea>
          <div class="mini">Use <code>[SRC]</code> in subject/body. Replaced per chunk in line order (cycles back to first line after the last). Use <code>[MAIL]</code> or <code>[EMAIL]</code> for recipient email.</div>
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
    <h2>Save Domains</h2>

    <div class="actions" style="margin-top:12px">
      <input id="domQ" placeholder="Search domain..." style="max-width:320px" />
      <button class="btn secondary" type="button" id="btnDomains">🌐 Refresh</button>
      <div class="mini" id="domStatus">—</div>
    </div>

    <div class="hint" style="margin-top:12px">
      <div class="mini"><b>Safe domains:</b> <span id="domSafeTotals">—</span></div>
    </div>

    <div style="overflow:auto; margin-top:12px">
      <table>
        <thead>
          <tr>
            <th>Sender domain</th>
            <th>Emails</th>
            <th>MX</th>
            <th>MX hosts</th>
            <th>Mail IP(s)</th>
            <th>Listed</th>
            <th>SPF</th>
            <th>DKIM</th>
            <th>DMARC</th>
          </tr>
        </thead>
        <tbody id="domTblSafe">
          <tr><td colspan="9" class="muted">—</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<div class="toast-wrap" id="toastWrap"></div>

<script>
  function q(name){ return document.querySelector(`[name="${name}"]`); }

  function labelForElement(el){
    if(!el) return '';
    const raw = (el.textContent || '').replace(/\s+/g, ' ').trim();
    return raw.replace(/^[-•\s]+/, '');
  }

  function helpTextForElement(el){
    const txt = labelForElement(el).toLowerCase();
    const name = (el.getAttribute('name') || '').toLowerCase();
    const id = (el.id || '').toLowerCase();

    if(id === 'btnstart') return 'يبدأ إنشاء Job جديدة ويرسل الرسائل حسب الإعدادات الحالية.';
    if(id === 'btntest') return 'يتحقق من الاتصال بخادم SMTP وبيانات الدخول قبل الإرسال الفعلي.';
    if(id === 'btnpreflight') return 'يفحص الرسالة والإعدادات (DNS/Headers/Spam) قبل البدء.';
    if(id === 'btnairewrite') return 'يعيد كتابة Subject وBody باستخدام الذكاء الاصطناعي ثم يملأ الحقول.';
    if(id === 'btndomains') return 'يجلب أحدث حالة للدومينات (MX/SPF/DKIM/DMARC/Blacklist).';
    if(id === 'domq') return 'ابحث باسم الدومين لتصفية جدول Save Domains بسرعة.';

    if(name === 'smtp_host') return 'عنوان السيرفر SMTP الذي سيتم إرسال الرسائل من خلاله.';
    if(name === 'smtp_port') return 'رقم منفذ SMTP. اختر المنفذ المتوافق مع نوع التشفير.';
    if(name === 'smtp_security') return 'يحدد طريقة تشفير الاتصال: STARTTLS أو SSL/TLS أو بدون تشفير.';
    if(name === 'smtp_timeout') return 'أقصى مدة انتظار قبل اعتبار اتصال SMTP فاشلاً.';
    if(name === 'smtp_user' || name === 'smtp_pass') return 'بيانات المصادقة لخادم SMTP إذا كان يتطلب تسجيل دخول.';
    if(name === 'rotate_every' || name === 'chunk_size') return 'التحكم في عدد الرسائل قبل تدوير المرسل أو الروابط.';
    if(name === 'delay_seconds') return 'فاصل زمني بين الرسائل لتقليل الضغط وتحسين التسليم.';
    if(name === 'from_name' || name === 'from_email') return 'المرسل الظاهر للمستلم (يمكن إدخال أكثر من قيمة للتدوير).';
    if(name === 'subject') return 'عنوان الرسالة (يمكن وضع عدة أسطر للتدوير بين الرسائل).';
    if(name === 'body') return 'محتوى الرسالة الأساسي. يمكنك استخدام المتغيرات مثل [URL] و [SRC].';
    if(name === 'body_format') return 'تحديد ما إذا كان المحتوى Text عادي أو HTML.';
    if(name === 'reply_to') return 'العنوان الذي تصل إليه ردود المستلمين عند الضغط على Reply.';
    if(name === 'score_range') return 'الحد الأعلى لنقاط السبام؛ إذا تجاوزه المحتوى يتم إيقاف الإرسال.';
    if(name === 'urls_list' || name === 'src_list') return 'قوائم ديناميكية تُستبدل داخل الرسالة لكل Chunk أثناء الإرسال.';
    if(name === 'recipients' || name === 'recipients_file') return 'قائمة المستلمين أو ملف الاستيراد الذي سيتم الإرسال إليه.';
    if(name === 'maillist_safe') return 'Whitelist اختيارية: يتم الإرسال فقط للعناوين الموجودة داخلها.';
    if(name === 'ai_token') return 'مفتاح OpenRouter المطلوب لتفعيل ميزة إعادة الصياغة بالذكاء الاصطناعي.';

    if(txt.includes('jobs')) return 'يفتح صفحة الوظائف السابقة والحالية لهذه الحملة.';
    if(txt.includes('config')) return 'يفتح صفحة إعدادات الحملة التفصيلية.';
    if(txt.includes('save domains')) return 'قسم تحليل سمعة الدومينات الخاصة بالمرسلين.';
    if(txt.includes('recipients')) return 'قسم إدارة وتنظيف مستلمي الحملة.';

    const clean = labelForElement(el);
    if(!clean) return '';
    return `شرح سريع: ${clean} — هذا العنصر يتحكم في هذا الجزء من عملية الإرسال.`;
  }

  function addHelpIcons(){
    const targets = document.querySelectorAll(
      '#mainForm label, #mainForm .btn, #mainForm .mini, #domainsCard h2, #domainsCard th, #domainsCard .mini, #domainsCard .btn, #domainsCard #domQ, .top h1, .top .badge'
    );
    targets.forEach((el) => {
      if(el.classList.contains('info-processed')) return;
      const tip = helpTextForElement(el);
      if(!tip) return;

      const wrap = document.createElement('span');
      wrap.className = 'info-wrap';
      const dot = document.createElement('span');
      dot.className = 'info-dot';
      dot.setAttribute('tabindex', '0');
      dot.setAttribute('role', 'button');
      dot.setAttribute('aria-label', `معلومة: ${tip}`);
      dot.textContent = 'i';
      const bubble = document.createElement('span');
      bubble.className = 'info-tip';
      bubble.textContent = tip;
      wrap.appendChild(dot);
      wrap.appendChild(bubble);

      if(el.matches('input, textarea, select')){
        el.insertAdjacentElement('afterend', wrap);
      } else {
        el.appendChild(wrap);
      }
      el.classList.add('info-processed');
    });
  }

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
  // Save domains stats (in-page)
  // -------------------------
  let _domCache = null;

  function domStatusBadge(mx){
    if(mx === 'mx') return '<span style="color:var(--good); font-weight:800">MX</span>';
    if(mx === 'a_fallback') return '<span style="color:var(--warn); font-weight:800">A</span>';
    if(mx === 'none') return '<span style="color:var(--bad); font-weight:800">NONE</span>';
    return '<span style="color:var(--warn); font-weight:800">UNKNOWN</span>';
  }

  function domListedBadge(v){
    return v ? '<span style="color:var(--bad); font-weight:800">Listed</span>' : '<span style="color:var(--good); font-weight:800">Not listed</span>';
  }

  function domPolicyBadge(v){
    const st = (v || '').toString().toLowerCase();
    if(st === 'pass') return '<span style="color:var(--good); font-weight:800">PASS</span>';
    if(st === 'missing') return '<span style="color:var(--warn); font-weight:800">MISSING</span>';
    if(st === 'unknown_selector') return '<span style="color:var(--warn); font-weight:800">UNKNOWN SELECTOR</span>';
    return '<span style="color:var(--warn); font-weight:800">UNKNOWN</span>';
  }

  function renderDomainsTables(){
    const qv = (document.getElementById('domQ')?.value || '').trim().toLowerCase();
    const safeBody = document.getElementById('domTblSafe');
    const safeTotals = document.getElementById('domSafeTotals');

    if(!_domCache || !_domCache.ok){
      if(safeBody) safeBody.innerHTML = `<tr><td colspan="9" class="muted">—</td></tr>`;
      if(safeTotals) safeTotals.textContent = '—';
      return;
    }

    const safe = _domCache.safe || {};
    if(safeTotals){
      safeTotals.textContent = `${safe.total_emails || 0} emails · ${safe.unique_domains || 0} domains · invalid=${safe.invalid_emails || 0}`;
    }
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
            `<td>${domListedBadge(!!(it.listed ?? it.any_listed))}</td>`+
            `<td>${domPolicyBadge((it.spf || {}).status)}</td>`+
            `<td>${domPolicyBadge((it.dkim || {}).status)}</td>`+
            `<td>${domPolicyBadge((it.dmarc || {}).status)}</td>`+
          `</tr>`
        );
      }
      return out.join('') || `<tr><td colspan="9" class="muted">No results.</td></tr>`;
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
        toast('Save Domains', 'Updated safe domains.', 'good');
      } else {
        const msg = (j && (j.error || j.detail)) ? (j.error || j.detail) : ('HTTP ' + r.status);
        if(status) status.textContent = 'Failed';
        toast('Save Domains failed', msg, 'bad');
      }
    }catch(e){
      if(status) status.textContent = 'Failed';
      toast('Domains stats failed', (e?.toString?.() || 'Unknown error'), 'bad');
    }finally{
      if(btn) btn.disabled = false;
    }
  }

  const domBtn = document.getElementById('btnDomains');
  if(domBtn){ domBtn.addEventListener('click', refreshDomainsStats); }
  const domQ = document.getElementById('domQ');
  if(domQ){ domQ.addEventListener('input', renderDomainsTables); }

  // auto-load safe domains stats once
  refreshDomainsStats();

  // Range value UI
  const scoreEl = document.getElementById('score_range');
  const scoreVal = document.getElementById('score_range_val');
  if(scoreEl && scoreVal){
    const sync = () => { scoreVal.textContent = Number(scoreEl.value).toFixed(1); };
    sync();
    scoreEl.addEventListener('input', sync);
  }

  addHelpIcons();
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

    .filterBar{
      background: linear-gradient(180deg, var(--card), var(--card2));
      border:1px solid var(--border);
      border-radius: 14px;
      padding: 10px 12px;
      margin-bottom: 12px;
      display:grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap:8px;
      align-items:end;
    }
    .filterCell label{
      display:block;
      font-size:11px;
      color:var(--muted);
      margin-bottom:5px;
      font-weight:700;
      text-transform:uppercase;
      letter-spacing:.3px;
    }
    .filterCell select{
      width:100%;
      border:1px solid rgba(255,255,255,.16);
      background: rgba(255,255,255,.06);
      color: rgba(255,255,255,.9);
      border-radius:10px;
      font: inherit;
      font-size:13px;
      padding:8px 9px;
    }
    .filterCell option{ background:#0b1020; color:#fff; }
    .filterMeta{ grid-column:1 / -1; font-size:12px; color:var(--muted); }

    .jobTop{display:flex; gap:12px; flex-wrap:wrap; align-items:flex-start; justify-content:space-between;}
    .titleRow{display:flex; gap:10px; flex-wrap:wrap; align-items:center}
    .mini{color:var(--muted); font-size:12px; line-height:1.55}
    code{background:rgba(255,255,255,.08); padding:2px 6px; border-radius:8px;}

    .pill{padding:6px 10px; border-radius:999px; border:1px solid rgba(255,255,255,.14); background:rgba(255,255,255,.06); font-size:12px;}
    .pill.good{border-color: rgba(53,228,154,.35); color: var(--good); font-weight:900}
    .pill.bad{border-color: rgba(255,94,115,.35); color: var(--bad); font-weight:900}
    .pill.warn{border-color: rgba(255,193,77,.35); color: var(--warn); font-weight:900}

    .triageRow{display:flex; gap:6px; flex-wrap:wrap; align-items:center; margin-top:8px; max-width:100%;}
    .triageBadge{
      display:inline-flex;
      align-items:center;
      gap:6px;
      max-width:100%;
      border:1px solid rgba(255,255,255,.14);
      background:rgba(255,255,255,.06);
      border-radius:999px;
      padding:4px 9px;
      font-size:11px;
      font-weight:800;
      line-height:1.2;
      color:rgba(255,255,255,.88);
      white-space:nowrap;
      overflow:visible;
      min-width:0;
    }
    .triageBadge .badgeLabel{
      min-width:0;
      overflow:hidden;
      text-overflow:ellipsis;
      white-space:nowrap;
    }
    .triageBadge.good{border-color: rgba(53,228,154,.35); color: var(--good);}
    .triageBadge.warn{border-color: rgba(255,193,77,.35); color: var(--warn);}
    .triageBadge.bad{border-color: rgba(255,94,115,.35); color: var(--bad);}
    .bridgeConnBadge{gap:7px;}
    .statusDot{
      width:9px;
      height:9px;
      border-radius:50%;
      display:inline-block;
      box-shadow:0 0 0 2px rgba(255,255,255,.12);
      flex:0 0 auto;
    }
    .statusDot.good{background: var(--good);}
    .statusDot.bad{background: var(--bad);}

    .kpiWrap{margin-top:12px; border:1px solid rgba(255,255,255,.10); background: rgba(0,0,0,.10); border-radius: 14px; padding: 10px 12px;}
    .kpiRow{display:grid; grid-template-columns: repeat(6, minmax(0,1fr)); gap:8px;}
    .kpiCell{border:1px solid rgba(255,255,255,.08); background: rgba(255,255,255,.03); border-radius:10px; padding:7px 9px;}
    .kpiCell .k{font-size:11px; color: rgba(255,255,255,.62); text-transform:uppercase; letter-spacing:.3px;}
    .kpiCell .v{font-size:16px; font-weight:900; margin-top:2px; display:flex; align-items:center; gap:6px;}
    .kpiWarn{font-size:12px; color:var(--warn); cursor:help;}
    .ratesRow{display:grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap:8px; margin-top:8px;}
    .rateCell{border:1px solid rgba(255,255,255,.08); background: rgba(255,255,255,.02); border-radius:10px; padding:6px 9px;}
    .rateCell .k{font-size:11px; color: rgba(255,255,255,.62); text-transform:uppercase; letter-spacing:.3px;}
    .rateCell .v{font-size:13px; font-weight:800; margin-top:2px;}
    .qualityMini{margin-top:8px;}
    .qualityMini summary{cursor:pointer; color:rgba(255,255,255,.78); font-size:12px; user-select:none;}
    .qualityLine{margin-top:6px; font-size:12px; color:rgba(255,255,255,.72);}
    @media (max-width: 980px){ .kpiRow{grid-template-columns: repeat(3, minmax(0,1fr));} }
    @media (max-width: 620px){ .kpiRow{grid-template-columns: repeat(2, minmax(0,1fr));} .ratesRow{grid-template-columns: 1fr;} }

    .bars{display:grid; grid-template-columns: 1fr; gap:10px; margin-top: 12px;}
    .barWrap{display:flex; gap:10px; flex-wrap:wrap; align-items:center; justify-content:space-between;}
    .bar{height: 10px; background: rgba(255,255,255,.10); border:1px solid rgba(255,255,255,.14); border-radius:999px; overflow:hidden; width:100%;}
    .bar > div{height:100%; width:0%; background: rgba(122,167,255,.65);} 

    .twoCol{display:grid; grid-template-columns: 1fr 1fr; gap:10px; margin-top:12px;}
    @media (max-width: 980px){ .twoCol{grid-template-columns: 1fr;} }
    .panel{border:1px solid rgba(255,255,255,.10); background: rgba(0,0,0,.10); border-radius: 14px; padding: 10px 12px;}
    .panel h4{margin:0 0 8px; font-size: 13px; color: rgba(255,255,255,.86)}

    .quickIssues{margin-top:10px; font-size:12px; color:var(--warn);}
    .quickIssues:empty{display:none;}
    .more{margin-top:10px;}
    .more > summary{cursor:pointer; user-select:none; font-weight:800; color:rgba(255,255,255,.88);}
    .moreBlock{margin-top:10px;}
    .errorFold{margin-top:8px;}
    .errorFold summary{cursor:pointer; color:rgba(255,255,255,.75); font-size:12px;}

    /* PMTA Live Panel (Jobs) — clearer layout */
    .pmtaLive{ margin-top:10px; }
    .pmtaCompact{
      margin-top:10px;
      font-size:12px;
      color:rgba(255,255,255,.86);
      border:1px solid rgba(255,255,255,.14);
      background:rgba(0,0,0,.14);
      border-radius:10px;
      padding:8px 10px;
      font-weight:800;
      line-height:1.45;
      overflow-wrap:anywhere;
    }
    .pmtaToggle{ margin-top:8px; }
    .pmtaToggle > summary{ cursor:pointer; user-select:none; color:rgba(255,255,255,.88); font-weight:800; }
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
    .pmtaHint{ margin-top:6px; font-size: 11px; color: rgba(255,255,255,.52); line-height: 1.35; }

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

    .labelTip{ display:inline-flex; align-items:center; gap:6px; }
    .tip{display:inline-flex; align-items:center; justify-content:center; width:18px; height:18px; border-radius:999px;
      border:1px solid rgba(255,255,255,.18); background: rgba(0,0,0,.18); color: rgba(255,255,255,.86);
      font-size: 12px; cursor: help; position: relative; user-select:none}
    .triageBadge .tip{ width:14px; height:14px; font-size:10px; }
    .tip:hover::after{
      content: attr(data-tip);
      position: absolute;
      left: 0;
      top: 24px;
      min-width: 240px;
      max-width: 420px;
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

    <div class="filterBar" id="jobsFilterBar">
      <div class="filterCell">
        <label for="fltStatus" class="labelTip">Status <span class="tip" data-tip="Filter jobs by current execution state (running/done/paused/backoff).">ⓘ</span></label>
        <select id="fltStatus">
          <option value="all">All</option>
          <option value="running">running</option>
          <option value="done">done</option>
          <option value="paused">paused</option>
          <option value="backoff">backoff</option>
        </select>
      </div>
      <div class="filterCell">
        <label for="fltMode" class="labelTip">Mode <span class="tip" data-tip="Show jobs by bridge polling mode: counts or legacy.">ⓘ</span></label>
        <select id="fltMode">
          <option value="all">All</option>
          <option value="counts">counts</option>
          <option value="legacy">legacy</option>
        </select>
      </div>
      <div class="filterCell">
        <label for="fltRisk" class="labelTip">Risk <span class="tip" data-tip="Highlight jobs with health/risk signals such as stale updates or degraded internals.">ⓘ</span></label>
        <select id="fltRisk">
          <option value="all">All</option>
          <option value="internal_degraded">internal degraded</option>
          <option value="deliverability_high">deliverability high</option>
          <option value="stale">stale</option>
        </select>
      </div>
      <div class="filterCell">
        <label for="fltProvider" class="labelTip">Provider <span class="tip" data-tip="Filter by recipient provider bucket (gmail/yahoo/outlook/icloud/other).">ⓘ</span></label>
        <select id="fltProvider">
          <option value="all">All</option>
          <option value="gmail">gmail</option>
          <option value="yahoo">yahoo</option>
          <option value="outlook">outlook</option>
          <option value="icloud">icloud</option>
          <option value="other">other</option>
        </select>
      </div>
      <div class="filterCell">
        <label for="fltSort" class="labelTip">Sort <span class="tip" data-tip="Control card order: newest first, highest risk first, or stalest first.">ⓘ</span></label>
        <select id="fltSort">
          <option value="newest">newest first</option>
          <option value="highest_risk">highest risk first</option>
          <option value="stalest">stalest first</option>
        </select>
      </div>
      <div class="filterMeta" id="filterMeta">Showing all jobs.</div>
    </div>

    {% for j in jobs %}
      <div class="job" data-jobid="{{j.id}}" data-created="{{j.created_at}}">
        <div class="jobTop">
          <div>
            <div class="titleRow">
              <div style="font-weight:900">Job <code>{{j.id}}</code></div>
              <div class="pill" data-k="status">{{j.status}}</div>
              <div class="pill" data-k="speed">0 epm</div>
              <div class="pill" data-k="eta">ETA —</div>
            </div>
            <div class="triageRow">
              <div class="triageBadge" data-k="badgeMode">—</div>
              <div class="triageBadge" data-k="badgeFreshness">—</div>
              <div class="triageBadge" data-k="badgeHealth">—</div>
              <div class="triageBadge" data-k="badgeRisk">—</div>
              <div class="triageBadge bridgeConnBadge" data-k="badgeBridgeConn">—</div>
              <div class="triageBadge" data-k="badgeIntegrity" style="display:none">INTEGRITY</div>
            </div>
            <div class="mini">Created: <span class="muted">{{j.created_at}}</span></div>
            <div class="mini" data-k="alerts">—</div>
          </div>

          <div class="nav" style="margin-top:0">
            <a class="btn secondary" href="/job/{{j.id}}">Open</a>
            <button class="btn secondary" type="button" data-action="pause">⏸ Pause</button>
            <button class="btn secondary" type="button" data-action="resume">▶ Resume</button>
            <button class="btn danger" type="button" data-action="stop">⛔ Stop</button>
            <button class="btn danger" type="button" data-action="delete">🗑 Delete</button>
          </div>
        </div>

        <!-- 1) Compact KPI + rates -->
        <div class="kpiWrap">
          <div class="kpiRow">
            <div class="kpiCell"><div class="k">Sent</div><div class="v"><span data-k="sent">—</span></div></div>
            <div class="kpiCell"><div class="k">Pending</div><div class="v"><span data-k="pending">—</span><span class="kpiWarn" data-k="pendingWarn" style="display:none" title="Pending was clamped to 0 because Sent is lower than PMTA outcomes.">⚠</span></div></div>
            <div class="kpiCell"><div class="k">Del</div><div class="v"><span data-k="delivered">—</span></div></div>
            <div class="kpiCell"><div class="k">Bnc</div><div class="v"><span data-k="bounced">—</span></div></div>
            <div class="kpiCell"><div class="k">Def</div><div class="v"><span data-k="deferred">—</span></div></div>
            <div class="kpiCell"><div class="k">Cmp</div><div class="v"><span data-k="complained">—</span></div></div>
          </div>
          <div class="ratesRow">
            <div class="rateCell"><div class="k">Bounce %</div><div class="v" data-k="rateBounce">—</div></div>
            <div class="rateCell"><div class="k">Complaint %</div><div class="v" data-k="rateComplaint">—</div></div>
            <div class="rateCell"><div class="k">Deferred %</div><div class="v" data-k="rateDeferred">—</div></div>
          </div>
          <details class="qualityMini">
            <summary>Quality</summary>
            <div class="qualityLine">Final-fail: <span data-k="failed">—</span> · Skipped: <span data-k="skipped">—</span> · Invalid: <span data-k="invalid">—</span> · Total: <span data-k="total">—</span></div>
          </details>
        </div>

        <!-- 4) Progress bars -->
        <div class="bars">
          <div class="panel">
            <h4>Progress</h4>
            <div class="mini" data-k="progressText">—</div>
            <div class="bar"><div data-k="barSend"></div></div>
            <div class="mini" style="margin-top:8px" data-k="chunksText">—</div>
            <div class="mini" data-k="attemptsText" style="display:none">—</div>
            <div class="bar"><div data-k="barChunks"></div></div>
            <div class="mini" style="margin-top:8px" data-k="domainsText">—</div>
            <div class="bar"><div data-k="barDomains"></div></div>
          </div>
        </div>

        <div class="quickIssues" data-k="quickIssues"></div>

        <details class="more">
          <summary>More details</summary>
          <div class="moreBlock twoCol">
            <!-- 2) Current chunk + 3) backoff info -->
            <div class="panel">
              <h4>Current chunk</h4>
              <div class="mini">Current send settings + top active domains in this running chunk.</div>
              <div class="mini" data-k="chunkLine">—</div>
              <div class="mini" data-k="chunkDomains">—</div>
            </div>
            <div class="panel">
              <h4>Backoff</h4>
              <div class="mini">Latest retry event when PMTA/provider pressure slows delivery.</div>
              <div class="mini" data-k="backoffLine">—</div>
            </div>
          </div>

          <div class="panel moreBlock">
            <h4>PMTA Live Panel</h4>
            <div class="pmtaCompact" data-k="pmtaCompact">PMTA: —</div>
            <details class="pmtaToggle">
              <summary>Show PMTA panel</summary>
              <div class="pmtaLive" data-k="pmtaLine">—</div>
              <div class="mini" style="margin-top:6px" data-k="pmtaNote">Note: <b>sent</b> = accepted by PMTA (client-side). Delivery may still be queued/deferred.</div>
              <div class="mini" style="margin-top:6px" data-k="pmtaDiag">Diag: —</div>
              <div class="mini" style="margin-top:8px"><b>Outcomes (PMTA accounting)</b></div>
              <div class="outcomesWrap" data-k="outcomes">—</div>
              <div class="outTrend" data-k="outcomeTrend">—</div>
            </details>
          </div>

          <div class="moreGrid moreBlock">

            <!-- 5) Top domains -->
            <div class="panel">
              <h4 data-k="domainsPanelTitle">Top domains (Top 10)</h4>
              <div class="mini" data-k="topDomains">—</div>
              <div class="mini" style="margin-top:10px"><b>Domain progress (bars)</b></div>
              <div data-k="topDomainsBars"></div>
            </div>

            <div class="panel">
              <h4>System / Provider / Integrity</h4>

              <div class="mini"><b>System / Internal</b></div>
              <div class="mini" data-k="systemSummary">—</div>
              <details class="errorFold">
                <summary>View details</summary>
                <div class="mini" style="margin-top:8px" data-k="systemDetails">—</div>
              </details>

              <div style="height:10px"></div>

              <div class="mini"><b>Provider / Deliverability</b></div>
              <div class="mini" data-k="providerSummary">—</div>
              <div class="mini" style="margin-top:6px" data-k="providerBreakdown">—</div>
              <div class="mini" style="margin-top:6px" data-k="providerReasons">—</div>
              <details class="errorFold">
                <summary>View details</summary>
                <div class="mini" style="margin-top:8px" data-k="providerDetails">—</div>
              </details>

              <div style="height:10px"></div>

              <div class="mini"><b>Data Integrity / Mapping</b></div>
              <div class="mini" data-k="integritySummary">—</div>
              <details class="errorFold">
                <summary>View details</summary>
                <div class="mini" style="margin-top:8px" data-k="integrityDetails">—</div>
              </details>

              <details class="errorFold" style="margin-top:8px">
                <summary>Legacy quality + errors (unchanged data)</summary>
                <div class="mini" style="margin-top:8px" data-k="counters">—</div>
                <div class="mini" style="margin-top:8px"><b>Error type</b></div>
                <div class="mini" data-k="errorTypes">—</div>
                <div class="mini" style="margin-top:8px"><b>Error summary</b></div>
                <div class="mini" data-k="lastErrors">—</div>
                <div class="mini" style="margin-top:8px" data-k="lastErrors2">—</div>
                <div class="mini" style="margin-top:8px" data-k="internalErrors">—</div>
                <div class="mini" style="margin-top:8px" data-k="bridgeReceiver">—</div>
              </details>
            </div>

          </div>

          <!-- 8) Preflight history per chunk -->
          <div class="panel" style="margin-top:10px">
            <h4>Chunk preflight history (last 12)</h4>
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

    <div class="job" id="jobsFilteredEmpty" style="display:none">
      <div class="mini">No jobs match the selected filters.</div>
    </div>

    {% if jobs|length == 0 %}
      <div class="job">
        <div class="mini">No jobs yet.</div>
      </div>
    {% endif %}

  </div>

  <div class="toast-wrap" id="toastWrap"></div>

<script>
  const esc = (s) => (s ?? '').toString().replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
  const escAttr = (s) => esc(s).replaceAll('"','&quot;');

  function badgeWithTip(label, tip){
    const safeLabel = esc(label || '—');
    const safeTip = escAttr(tip || '—');
    return `<span class="badgeLabel">${safeLabel}</span><span class="tip" data-tip="${safeTip}">ⓘ</span>`;
  }

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

  function tsToMs(ts){
    const s = (ts || '').toString().trim();
    if(!s) return null;
    const n = Date.parse(s);
    return Number.isFinite(n) ? n : null;
  }

  function ageMin(ts){
    const ms = tsToMs(ts);
    if(ms === null) return null;
    return Math.max(0, Math.floor((Date.now() - ms) / 60000));
  }

  function riskBadgeClass(level){
    const lv = (level || '').toString().toLowerCase();
    if(lv === 'low') return 'triageBadge good';
    if(lv === 'med') return 'triageBadge warn';
    if(lv === 'high') return 'triageBadge bad';
    return 'triageBadge';
  }

  function healthBadgeClass(ok){
    if(ok === true) return 'triageBadge good';
    if(ok === false) return 'triageBadge bad';
    return 'triageBadge';
  }

  function computeDeliverabilityRisk(j){
    const sent = Number(j.sent || 0);
    const delivered = Number(j.delivered || 0);
    const bounced = Number(j.bounced || 0);
    const complained = Number(j.complained || 0);
    const deferred = Number(j.deferred || 0);
    if(sent <= 0) return '—';
    const bRate = bounced / sent;
    const cRate = complained / sent;
    const dRate = deferred / sent;
    if(bRate >= 0.12 || cRate >= 0.01 || (delivered <= 0 && sent >= 30)) return 'HIGH';
    if(bRate >= 0.05 || cRate >= 0.003 || dRate >= 0.2) return 'MED';
    return 'LOW';
  }


  function normalizeJobStatus(j){
    const raw = (j && j.status ? j.status : '').toString().trim().toLowerCase();
    if(raw === 'running' || raw === 'done' || raw === 'paused' || raw === 'backoff') return raw;
    return 'other';
  }

  function normalizeBridgeMode(j){
    const raw = (j && j.bridge_mode ? j.bridge_mode : 'counts').toString().trim().toLowerCase();
    if(raw === 'legacy') return 'legacy';
    if(raw === 'counts') return 'counts';
    return 'counts';
  }

  function freshnessMinutes(j){
    const mode = normalizeBridgeMode(j);
    if(mode === 'counts'){
      return ageMin(j.accounting_last_update_ts || j.accounting_last_ts);
    }
    const lagSecRaw = Number(j && j.ingestion_lag_seconds);
    if(Number.isFinite(lagSecRaw) && lagSecRaw >= 0){
      return Math.floor(lagSecRaw / 60);
    }
    return ageMin(j.ingestion_last_event_ts || j.accounting_last_ts);
  }

  function hasInternalDegraded(j){
    const failureCount = Number(j && j.bridge_failure_count);
    const failN = Number.isFinite(failureCount) ? failureCount : Number(j && j.internal_health_failures || 0);
    return Number.isFinite(failN) && failN > 0;
  }

  function hasDeliverabilityHigh(j){
    return computeDeliverabilityRisk(j) === 'HIGH';
  }

  function isStaleJob(j){
    const mode = normalizeBridgeMode(j);
    const mins = freshnessMinutes(j);
    if(mins === null || !Number.isFinite(mins)) return false;
    return mode === 'legacy' ? mins > 15 : mins > 10;
  }

  function providerBucketFromDomain(domain){
    const d = (domain || '').toString().trim().toLowerCase();
    if(!d) return 'other';
    if(d.includes('gmail.') || d.includes('googlemail.')) return 'gmail';
    if(d.includes('yahoo.') || d.includes('ymail.') || d.includes('rocketmail.')) return 'yahoo';
    if(d.includes('outlook.') || d.includes('hotmail.') || d.includes('live.') || d.includes('msn.')) return 'outlook';
    if(d.includes('icloud.') || d.includes('me.com') || d.includes('mac.com')) return 'icloud';
    return 'other';
  }

  function detectProviderBucket(j){
    const weighted = {};
    const add = (dom, w) => {
      const b = providerBucketFromDomain(dom);
      weighted[b] = Number(weighted[b] || 0) + Math.max(0, Number(w || 0));
    };
    const plan = (j && j.domain_plan) || {};
    for(const [dom, count] of Object.entries(plan)) add(dom, count);
    if(!Object.keys(plan).length){
      const host = (j && j.smtp_host ? j.smtp_host : '').toString().trim().toLowerCase();
      if(host) add(host, 1);
    }
    let best = 'other';
    let bestW = -1;
    for(const [k,v] of Object.entries(weighted)){
      if(v > bestW){
        best = k;
        bestW = v;
      }
    }
    return best;
  }

  function riskRank(j){
    if(hasInternalDegraded(j)) return 3;
    if(hasDeliverabilityHigh(j)) return 2;
    if(isStaleJob(j)) return 1;
    return 0;
  }

  function renderTriageBadges(card, j){
    const modeRaw = (j.bridge_mode || '—').toString().trim().toLowerCase();
    const isCounts = modeRaw === 'counts';
    const isLegacy = modeRaw === 'legacy';

    const modeEl = qk(card, 'badgeMode');
    if(modeEl){
      const modeLabel = isCounts ? 'COUNTS' : (isLegacy ? 'LEGACY' : '—');
      const modeTip = isCounts
        ? 'Bridge polling mode uses aggregated accounting counters (fast/low overhead).'
        : (isLegacy
          ? 'Bridge polling mode uses legacy event stream with ingestion lag tracking.'
          : 'Bridge mode not available yet for this job.');
      modeEl.innerHTML = badgeWithTip(modeLabel, modeTip);
      modeEl.className = 'triageBadge';
    }

    const freshEl = qk(card, 'badgeFreshness');
    if(freshEl){
      let txt = '—';
      let cls = 'triageBadge';
      if(isCounts){
        const mins = ageMin(j.accounting_last_update_ts || j.accounting_last_ts);
        if(mins === null){
          txt = 'acct: —';
        }else if(mins > 10){
          txt = `STALE: ${mins}m`;
          cls = 'triageBadge warn';
        }else{
          txt = `acct: ${mins}m ago`;
          cls = 'triageBadge good';
        }
      }else if(isLegacy){
        const lagSecRaw = Number(j.ingestion_lag_seconds);
        const mins = Number.isFinite(lagSecRaw) && lagSecRaw >= 0
          ? Math.floor(lagSecRaw / 60)
          : ageMin(j.ingestion_last_event_ts || j.accounting_last_ts);
        if(mins === null){
          txt = 'lag: —';
        }else if(mins <= 1){
          txt = 'caught up';
          cls = 'triageBadge good';
        }else{
          txt = `lag: ${mins}m`;
          cls = mins > 15 ? 'triageBadge warn' : 'triageBadge';
        }
      }
      freshEl.innerHTML = badgeWithTip(txt, 'Freshness signal: how recent accounting or legacy ingestion updates are for this job.');
      freshEl.className = cls;
    }

    const failureCount = Number(j.bridge_failure_count);
    const failN = Number.isFinite(failureCount) ? failureCount : Number(j.internal_health_failures || 0);
    const healthEl = qk(card, 'badgeHealth');
    if(healthEl){
      const known = Number.isFinite(failN);
      const ok = known ? failN <= 0 : null;
      healthEl.className = healthBadgeClass(ok);
      if(known){
        const failures = Math.max(0, Math.floor(failN));
        const label = ok ? 'OK (0)' : `DEGRADED (${failures})`;
        const tip = ok
          ? 'Internal health checks are clean (no bridge/runtime failure counters).'
          : `Internal health degraded: ${failures} bridge/runtime failures were detected.`;
        healthEl.innerHTML = badgeWithTip(label, tip);
      }else{
        healthEl.innerHTML = badgeWithTip('—', 'Internal health state is not available yet.');
      }
    }

    const risk = computeDeliverabilityRisk(j);
    const riskEl = qk(card, 'badgeRisk');
    if(riskEl){
      riskEl.className = riskBadgeClass(risk);
      riskEl.innerHTML = badgeWithTip(`RISK ${risk}`, 'Deliverability risk derived from bounce, complaint, and deferred rates.');
    }

    renderBridgeConnectionBadge(card, state.latestBridgeState);

    const dup = Number(j.duplicates_dropped || 0);
    const jnf = Number(j.job_not_found || 0);
    const dbf = Number(j.db_write_failures || 0);
    const miss = Number(j.missing_fields || 0);
    const hasIntegrity = (dup + jnf + dbf + miss) > 0;
    const intEl = qk(card, 'badgeIntegrity');
    if(intEl){
      intEl.style.display = hasIntegrity ? 'inline-flex' : 'none';
      intEl.className = hasIntegrity ? 'triageBadge bad' : 'triageBadge';
      const integrityTotal = dup + jnf + dbf + miss;
      const integrityTip = hasIntegrity
        ? `Data integrity issues found: duplicates=${dup}, job_not_found=${jnf}, missing_fields=${miss}, db_write_failures=${dbf}.`
        : 'Data integrity counters are clean.';
      intEl.innerHTML = badgeWithTip(hasIntegrity ? `INTEGRITY (${integrityTotal})` : 'INTEGRITY', integrityTip);
    }
  }

  function renderBridgeConnectionBadge(card, bridgeState){
    const bridgeEl = qk(card, 'badgeBridgeConn');
    if(!bridgeEl) return;
    const connected = !!(bridgeState && bridgeState.connected === true);
    const label = connected ? 'Bridge↔Shiva connected' : 'Bridge↔Shiva disconnected';
    bridgeEl.className = `triageBadge bridgeConnBadge ${connected ? 'good' : 'bad'}`;
    bridgeEl.innerHTML = `<span class="statusDot ${connected ? 'good' : 'bad'}" aria-hidden="true"></span><span>${esc(label)}</span><span class="tip" data-tip="Real-time bridge transport status between PMTA accounting bridge and Shiva receiver.">ⓘ</span>`;
    bridgeEl.title = label;
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
    lastJobPayload: {},
    latestBridgeState: null,
    filters: {
      status: 'all',
      mode: 'all',
      risk: 'all',
      provider: 'all',
      sort: 'newest',
    },
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
        cards = cards.filter(x => x !== card);
        applyFiltersAndSort();
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

    const entries = Object.entries(plan).map(([dom, p]) => {
      const pp = Number(p||0);
      const ss = Number(sent[dom]||0);
      const ff = Number(failed[dom]||0);
      const done = ss + ff;
      return {dom, pp, ss, ff, done, pct: pct(done, pp), active: (dom in currDom)};
    }).sort((a,b)=>b.pp - a.pp).slice(0,10);

    const totalRecipients = Number(j.total || 0);
    const domainsCount = Object.keys(plan).length;
    const showProviders = (totalRecipients <= 50) || (domainsCount <= 5);

    const titleEl = qk(card, 'domainsPanelTitle');
    const elLine = qk(card,'topDomains');
    const elBars = qk(card,'topDomainsBars');
    const barsLabelEl = elBars ? elBars.previousElementSibling : null;

    function providerForDomain(dom){
      const d = (dom || '').toString().trim().toLowerCase();
      if(!d) return 'Other';

      if(
        d === 'gmail.com' || d.endsWith('.gmail.com') ||
        d === 'googlemail.com' || d.endsWith('.googlemail.com')
      ) return 'Gmail';

      if(
        d === 'yahoo.com' || d.endsWith('.yahoo.com') ||
        d.endsWith('.yahoo.co.jp') ||
        d === 'ymail.com' || d.endsWith('.ymail.com') ||
        d === 'rocketmail.com' || d.endsWith('.rocketmail.com') ||
        d === 'yahoo.co.jp'
      ) return 'Yahoo';

      if(
        d === 'outlook.com' || d.endsWith('.outlook.com') ||
        d === 'hotmail.com' || d.endsWith('.hotmail.com') ||
        d === 'live.com' || d.endsWith('.live.com') ||
        d === 'msn.com' || d.endsWith('.msn.com') ||
        d === 'passport.com' || d.endsWith('.passport.com')
      ) return 'Outlook';

      if(
        d === 'icloud.com' || d.endsWith('.icloud.com') ||
        d === 'me.com' || d.endsWith('.me.com') ||
        d === 'mac.com' || d.endsWith('.mac.com')
      ) return 'iCloud';

      return 'Other';
    }

    function renderProviderBreakdown(){
      const buckets = {Gmail: 0, Yahoo: 0, Outlook: 0, iCloud: 0, Other: 0};
      const hasPlan = Object.keys(plan).length > 0;
      if(!hasPlan){
        if(elLine) elLine.textContent = '—';
        if(elBars) elBars.innerHTML = '';
        if(titleEl) titleEl.textContent = 'Top providers';
        if(barsLabelEl) barsLabelEl.style.display = 'none';
        return;
      }

      for(const [dom, rawCount] of Object.entries(plan)){
        const cnt = Number(rawCount || 0);
        const provider = providerForDomain(dom);
        buckets[provider] = Number(buckets[provider] || 0) + Math.max(0, cnt);
      }
      const ordered = ['Gmail', 'Yahoo', 'Outlook', 'iCloud', 'Other'].map(name => ({
        name,
        count: Number(buckets[name] || 0)
      }));

      if(titleEl) titleEl.textContent = 'Top providers';
      if(barsLabelEl) barsLabelEl.style.display = 'none';

      if(elLine){
        elLine.innerHTML = ordered.map(x => `${x.name}: <b>${x.count}</b>`).join(' · ');
      }
      if(elBars){
        const maxCount = Math.max(1, ...ordered.map(x => x.count));
        elBars.innerHTML = ordered.map(x => {
          const width = Math.round((x.count / maxCount) * 100);
          return `<div style="margin-top:10px">`+
            `<div class="mini"><b>${x.name}</b> · ${x.count}</div>`+
            `<div class="smallBar"><div style="width:${width}%"></div></div>`+
          `</div>`;
        }).join('');
      }
    }

    if(!entries.length){
      if(elLine) elLine.textContent = '—';
      if(elBars) elBars.innerHTML = '';
      if(titleEl) titleEl.textContent = showProviders ? 'Top providers' : 'Top domains (Top 10)';
      if(barsLabelEl) barsLabelEl.style.display = showProviders ? 'none' : '';
      return;
    }

    if(showProviders){
      renderProviderBreakdown();
      return;
    }

    if(titleEl) titleEl.textContent = 'Top domains (Top 10)';
    if(barsLabelEl) barsLabelEl.style.display = '';

    if(elLine){
      elLine.innerHTML = entries.map(x => {
        const flag = x.active ? ' 🔥' : '';
        const pm = pmtaMap[x.dom] || {};
        const q = (pm && pm.queued !== undefined && pm.queued !== null) ? pm.queued : '—';
        const d = (pm && pm.deferred !== undefined && pm.deferred !== null) ? pm.deferred : '—';
        const a = (pm && pm.active !== undefined && pm.active !== null) ? pm.active : '—';
        const pmInfo = (pmtaOk && (x.dom in pmtaMap)) ? ` · pmta(q=${q} def=${d} act=${a})` : '';
        return `${esc(x.dom)}: <span class="ok">${x.ss}</span>/<b>${x.pp}</b> (final-fail <span class="no">${x.ff}</span>)${flag}${pmInfo}`;
      }).join('<br>');
    }

    if(elBars){
      elBars.innerHTML = entries.map(x => {
        const bar = `<div class="smallBar"><div style="width:${x.pct}%"></div></div>`;
        return `<div style="margin-top:10px">`+
          `<div class="mini"><b>${esc(x.dom)}</b> · ${x.done}/${x.pp} (${x.pct}%)${x.active ? ' · active' : ''}</div>`+
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
    const latestError = onlyErrors.length ? onlyErrors[onlyErrors.length - 1] : null;
    const bouncedN = Number(j.bounced || 0);
    const deferredN = Number(j.deferred || 0);
    const complainedN = Number(j.complained || 0);
    const hasOutcomeFailures = (bouncedN + deferredN + complainedN) > 0;

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

    if(!entries.length && !topSig && !latestError){
      if(hasOutcomeFailures){
        const estBlocked = Math.max(0, bouncedN + complainedN);
        const estTemp = Math.max(0, deferredN);
        const parts = [];
        parts.push(`Latest code: <b>${estBlocked > 0 ? '5XX*' : '4XX*'}</b>`);
        parts.push('Most common error: <b>Outcome-only snapshot</b> · <b>1</b>');
        parts.push('Example: Bridge snapshot provides aggregate outcomes only (no SMTP response text).');
        parts.push([
          `4XX temporary: <b>${estTemp}</b>`,
          `5XX blocked: <b>${estBlocked}</b>`
        ].join(' · '));
        el.innerHTML = parts.join('<br>');
      }else{
        el.textContent = '—';
      }
    }else{
      const parts = [];
      if(latestError){
        const latestCode = pickErrorCode(latestError.detail || '') || '—';
        parts.push(`Latest code: <b>${esc(latestCode)}</b>`);
      }
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

    function shortWords(txt, maxWords){
      const words = (txt || '').toString().replace(/\s+/g, ' ').trim().split(' ').filter(Boolean);
      return words.slice(0, Math.max(1, Number(maxWords || 4))).join(' ');
    }

    function pickErrorCode(txt){
      const s = (txt || '').toString();
      let m = s.match(/\b([245]\.\d\.\d{1,3})\b/i);
      if(m) return (m[1] || '').trim();
      m = s.match(/\b([245]\d\d)\b/);
      if(m) return (m[1] || '').trim();
      return '';
    }

    function pickErrorSummary(x){
      if(!x) return '';
      const typ = (x.type || '').toString().trim().toLowerCase();
      const kind = (x.kind || '').toString().trim().toLowerCase();
      if(typ) return typ;
      if(kind === 'temporary_error') return 'deferred';
      if(kind === 'blocked') return 'blocked';
      if(kind === 'accepted') return 'accepted';
      return kind || 'unknown';
    }

    // Error 1 (summary): latest status keyword from PMTA (bounced/deferred/complained/blocked/backoff...)
    const el2 = qk(card,'lastErrors');
    if(el2){
      if(!latestError){
        if(hasOutcomeFailures){
          if(bouncedN + complainedN > 0){
            el2.innerHTML = `• [5XX*] bounced/complained · count=${esc(String(bouncedN + complainedN))}`;
          }else{
            el2.innerHTML = `• [4XX*] deferred · count=${esc(String(deferredN))}`;
          }
        }else{
          el2.textContent = '—';
        }
      }
      else{
        const detail = (latestError.detail || '').toString();
        const code = pickErrorCode(detail) || ((latestError.kind === 'temporary_error') ? '4XX' : '5XX');
        const summary = pickErrorSummary(latestError) || shortWords(detail, 4) || 'unknown';
        el2.innerHTML = `• [${esc(code)}] ${esc(summary)}`;
      }
    }

    // Error 2 (details): latest full PowerMTA response detail
    const el3 = qk(card,'lastErrors2');
    if(el3){
      if(!latestError){
        if(hasOutcomeFailures){
          const mode = ((j.bridge_mode || '').toString().toLowerCase() || 'counts');
          const src = (mode === 'legacy') ? 'event ingestion' : 'bridge snapshot';
          el3.innerHTML = `• aggregate outcomes present (bounced=${esc(String(bouncedN))} · deferred=${esc(String(deferredN))} · complained=${esc(String(complainedN))}) · source=${esc(src)} · no per-recipient SMTP detail in this mode`;
        }else{
          el3.textContent = '—';
        }
      }
      else{
        const typ = (latestError.type || '').toString();
        const kind = (latestError.kind || '').toString();
        const code = pickErrorCode(latestError.detail || '');
        const codePart = code ? ` · code=${esc(code)}` : '';
        el3.innerHTML = `• ${esc(latestError.email || '—')} · type=${esc(typ || 'unknown')} · kind=${esc(kind || 'unknown')}${codePart} · ${esc(latestError.detail || '')}`;
      }
    }

    function isNetworkInternalError(x){
      if(!x) return false;
      const t = (x.type || '').toString().toLowerCase();
      const d = (x.detail || '').toString().toLowerCase();
      const bag = `${t} ${d}`;
      return (
        bag.includes('network') ||
        bag.includes('socket') ||
        bag.includes('timeout') ||
        bag.includes('timed out') ||
        bag.includes('connection refused') ||
        bag.includes('connection reset') ||
        bag.includes('name or service not known') ||
        bag.includes('temporary failure in name resolution') ||
        bag.includes('host unreachable') ||
        bag.includes('no route to host') ||
        bag.includes('broken pipe') ||
        bag.includes('ssl') ||
        bag.includes('tls')
      );
    }

    const allInternalRows = Array.isArray(j.internal_last_errors) ? j.internal_last_errors : [];
    const netInternalRows = allInternalRows.filter(isNetworkInternalError);
    const ieRows = netInternalRows.slice().reverse().slice(0,10);
    const ieAgg = {};
    for(const row of netInternalRows){
      const k = (row && row.type) ? row.type.toString() : 'network_error';
      ieAgg[k] = Number(ieAgg[k] || 0) + 1;
    }
    const ie = qk(card,'internalErrors');
    if(ie){
      const topFixed = Object.entries(ieAgg).sort((a,b)=>Number(b[1]||0)-Number(a[1]||0));
      const countLine = topFixed.length
        ? topFixed.map(([k,v]) => `${esc(k)}: <b>${Number(v||0)}</b>`).join(' · ')
        : '';

      if(!countLine && !ieRows.length){
        ie.textContent = '—';
      }else{
        const lines = [];
        if(countLine) lines.push(countLine);
        if(ieRows.length){
          lines.push(ieRows.map(x => {
            const jid = (x.job_id || '').toString();
            const em = (x.email || '').toString();
            const ts = (x.ts || '').toString();
            const extra = [jid ? `job=${jid}` : '', em ? `email=${em}` : ''].filter(Boolean).join(' · ');
            return `• ${esc(ts)} · [${esc(x.type || 'other')}] ${esc(x.detail || '')}${extra ? ` · ${esc(extra)}` : ''}`;
          }).join('<br>'));
        }
        ie.innerHTML = lines.join('<br>');
      }
    }
  }



  function renderIssueBlocks(card, j){
    const asNum = (v) => {
      const n = Number(v);
      return Number.isFinite(n) ? n : null;
    };
    const fmtRate = (n, d) => {
      if(n === null || d === null || d <= 0) return '—';
      return `${((n/d)*100).toFixed(1)}%`;
    };

    const bridgeFail = asNum(j.bridge_failure_count);
    const bridgeErr = (j.bridge_last_error_message || '').toString().trim();
    const bridgeAge = ageMin(j.bridge_last_success_ts);
    const internalCounts = j.internal_error_counts || {};
    const runtimeErr = Object.values(internalCounts).reduce((a,v)=>a+Number(v||0),0);
    const dbFail = asNum(j.db_write_failures);

    const sys = qk(card,'systemSummary');
    if(sys){
      const bits = [
        `Bridge failures: <b>${bridgeFail === null ? '—' : bridgeFail}</b>`,
        `Bridge last success: <b>${bridgeAge === null ? '—' : (bridgeAge + 'm ago')}</b>`,
        `Runtime internal errors: <b>${runtimeErr || 0}</b>`,
        `DB write failures: <b>${dbFail === null ? '—' : dbFail}</b>`,
      ];
      if(bridgeErr) bits.push(`Bridge last error: ${esc(bridgeErr.slice(0,140))}`);
      sys.innerHTML = bits.join(' · ');
    }

    const sysRows = [];
    const irows = Array.isArray(j.internal_last_samples) ? j.internal_last_samples : (Array.isArray(j.internal_last_errors) ? j.internal_last_errors : []);
    for(const x of irows.slice().reverse().slice(0,8)){
      sysRows.push(`• ${esc(x.ts || '—')} · [${esc(x.type || 'internal')}] ${esc((x.detail || '').toString().slice(0,180))}`);
    }
    const sysDet = qk(card,'systemDetails');
    if(sysDet) sysDet.innerHTML = sysRows.length ? sysRows.join('<br>') : '—';

    const sent = asNum(j.sent);
    const delivered = asNum(j.delivered);
    const deferred = asNum(j.deferred);
    const bounced = asNum(j.bounced);
    const complained = asNum(j.complained);

    const prov = qk(card,'providerSummary');
    if(prov){
      prov.innerHTML = [
        `Delivered: <b>${delivered ?? '—'}</b> (${fmtRate(delivered, sent)})`,
        `Deferred: <b>${deferred ?? '—'}</b> (${fmtRate(deferred, sent)})`,
        `Bounced: <b>${bounced ?? '—'}</b> (${fmtRate(bounced, sent)})`,
        `Complained: <b>${complained ?? '—'}</b> (${fmtRate(complained, sent)})`,
      ].join(' · ');
    }

    const pb = qk(card,'providerBreakdown');
    const breakdown = Array.isArray(j.provider_breakdown) ? j.provider_breakdown : [];
    if(pb){
      pb.innerHTML = breakdown.length
        ? ('Provider/domain breakdown: ' + breakdown.slice(0,6).map(x => `${esc(x.domain || '—')} D=${Number(x.delivered||0)} Def=${Number(x.deferred||0)} B=${Number(x.bounced||0)} C=${Number(x.complained||0)}`).join(' · '))
        : 'Provider/domain breakdown: —';
    }

    const pr = qk(card,'providerReasons');
    const reasons = j.provider_reason_buckets || {};
    const reasonEntries = Object.entries(reasons).sort((a,b)=>Number(b[1]||0)-Number(a[1]||0)).slice(0,4);
    if(pr){
      pr.innerHTML = reasonEntries.length
        ? ('Top reason buckets: ' + reasonEntries.map(([k,v]) => `${esc(k)}=<b>${Number(v||0)}</b>`).join(' · '))
        : 'Top reason buckets: —';
    }

    const provDet = qk(card,'providerDetails');
    if(provDet){
      const samples = (Array.isArray(j.accounting_last_errors) ? j.accounting_last_errors : []).filter(x => x && x.kind !== 'accepted').slice().reverse().slice(0,8);
      provDet.innerHTML = samples.length
        ? samples.map(x => `• ${esc(x.ts || '—')} · ${esc(x.email || '—')} · ${esc(x.type || '—')} · ${esc((x.detail || '').toString().slice(0,180))}`).join('<br>')
        : '—';
    }

    const dup = asNum(j.duplicates_dropped) || 0;
    const jnf = asNum(j.job_not_found) || 0;
    const miss = asNum(j.missing_fields) || 0;
    const dbwf = asNum(j.db_write_failures) || 0;
    const integ = qk(card,'integritySummary');
    if(integ){
      integ.innerHTML = `duplicates_dropped: <b>${dup}</b> · job_not_found: <b>${jnf}</b> · missing_fields: <b>${miss}</b> · db_write_failures: <b>${dbwf}</b>`;
    }

    const integDet = qk(card,'integrityDetails');
    const integRows = Array.isArray(j.integrity_last_samples) ? j.integrity_last_samples : [];
    if(integDet){
      integDet.innerHTML = integRows.length
        ? integRows.slice().reverse().slice(0,8).map(x => `• ${esc(x.ts || '—')} · ${esc(x.kind || 'integrity')} · job=${esc(x.job_id || '—')} · rcpt=${esc(x.rcpt || '—')}`).join('<br>')
        : '—';
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

    // Header pills
    const st = (j.status || '').toString();
    const stEl = qk(card,'status');
    if(stEl){
      stEl.className = statusPillClass(st);
      stEl.textContent = `Status: ${st}`;
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

    renderTriageBadges(card, j);

    // Core counters + compact KPI values
    const asNum = (v) => {
      if(v === null || v === undefined || v === '') return null;
      const n = Number(v);
      return Number.isFinite(n) ? n : null;
    };
    const fmtNum = (n) => (n === null ? '—' : String(n));
    const fmtRate = (num, den) => {
      if(num === null || den === null || den <= 0) return '—';
      const r = (num / den) * 100;
      return `${r.toFixed(2)}%`;
    };

    const totalN = asNum(j.total);
    const sentN = asNum(j.sent);
    const failedN = asNum(j.failed);
    const skippedN = asNum(j.skipped);
    const invalidN = asNum(j.invalid);
    const deliveredN = asNum(j.delivered);
    const bouncedN = asNum(j.bounced);
    const deferredN = asNum(j.deferred);
    const complainedN = asNum(j.complained);

    qk(card,'total').textContent = fmtNum(totalN);
    qk(card,'sent').textContent = fmtNum(sentN);
    qk(card,'failed').textContent = fmtNum(failedN);
    qk(card,'skipped').textContent = fmtNum(skippedN);
    qk(card,'invalid').textContent = fmtNum(invalidN);

    const elDel = qk(card,'delivered'); if(elDel) elDel.textContent = fmtNum(deliveredN);
    const elBnc = qk(card,'bounced'); if(elBnc) elBnc.textContent = fmtNum(bouncedN);
    const elDef = qk(card,'deferred'); if(elDef) elDef.textContent = fmtNum(deferredN);
    const elCmp = qk(card,'complained'); if(elCmp) elCmp.textContent = fmtNum(complainedN);

    let pendingValue = null;
    let pendingClamped = false;
    if(sentN !== null && deliveredN !== null && bouncedN !== null && deferredN !== null && complainedN !== null){
      pendingValue = sentN - (deliveredN + bouncedN + deferredN + complainedN);
      if(pendingValue < 0){
        pendingValue = 0;
        pendingClamped = true;
      }
    }
    qk(card,'pending').textContent = fmtNum(pendingValue);
    const pendingWarnEl = qk(card,'pendingWarn');
    if(pendingWarnEl) pendingWarnEl.style.display = pendingClamped ? '' : 'none';

    const rateBounceEl = qk(card,'rateBounce');
    const rateComplaintEl = qk(card,'rateComplaint');
    const rateDeferredEl = qk(card,'rateDeferred');
    if(rateBounceEl) rateBounceEl.textContent = fmtRate(bouncedN, sentN);
    if(rateComplaintEl) rateComplaintEl.textContent = fmtRate(complainedN, sentN);
    if(rateDeferredEl) rateDeferredEl.textContent = fmtRate(deferredN, sentN);

    // Progress bars
    const total = Number(j.total||0);
    const sent = Number(j.sent||0);
    const failed = Number(j.failed||0);
    const skipped = Number(j.skipped||0);
    const done = sent + failed + skipped;

    const pSend = pct(done, total);
    qk(card,'barSend').style.width = pSend + '%';
    qk(card,'progressText').textContent = `Send progress: ${pSend}% (${done}/${total})`; 

    const legacyDone = Number(j.chunks_done||0);
    const legacyTotal = Number(j.chunks_total||0);
    let chunkUniqueDone = Number(j.chunk_unique_done);
    if(!Number.isFinite(chunkUniqueDone)) chunkUniqueDone = legacyDone;
    if(!Number.isFinite(chunkUniqueDone) || chunkUniqueDone < 0) chunkUniqueDone = 0;

    let chunkUniqueTotal = Number(j.chunk_unique_total);
    if(!Number.isFinite(chunkUniqueTotal)) chunkUniqueTotal = legacyTotal;
    if(!Number.isFinite(chunkUniqueTotal) || chunkUniqueTotal < 0) chunkUniqueTotal = 0;
    if(chunkUniqueTotal < chunkUniqueDone) chunkUniqueTotal = chunkUniqueDone;

    const pChunks = pct(chunkUniqueDone, chunkUniqueTotal);
    qk(card,'barChunks').style.width = pChunks + '%';
    qk(card,'chunksText').textContent = `Chunks: ${chunkUniqueDone}/${chunkUniqueTotal} done · backoff_events=${Number(j.chunks_backoff||0)} · abandoned=${Number(j.chunks_abandoned||0)}`;
    const attemptsEl = qk(card,'attemptsText');
    if(attemptsEl){
      let attemptsTotal = Number(j.chunk_attempts_total);
      if(!Number.isFinite(attemptsTotal)) attemptsTotal = null;
      if(attemptsTotal !== null && attemptsTotal < 0) attemptsTotal = null;
      if(attemptsTotal !== null && attemptsTotal < chunkUniqueDone) attemptsTotal = chunkUniqueDone;
      const hasRetries = attemptsTotal !== null && attemptsTotal > chunkUniqueDone;
      if(hasRetries){
        attemptsEl.style.display = '';
        attemptsEl.textContent = `Attempts: ${attemptsTotal}`;
      }else{
        attemptsEl.style.display = 'none';
      }
    }

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
    const cs = (j.chunk_states || []).slice().reverse();
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
    const pmCompactEl = qk(card,'pmtaCompact');
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

    function _box(title, tagTone, tagLabel, hint, inner){
      return `<div class="pmtaBox">`+
        `<div class="pmtaTitle"><span>${esc(title)}</span>${tagLabel ? _tagHtml(tagTone, tagLabel) : ''}</div>`+
        (hint ? `<div class="pmtaHint">${esc(hint)}</div>` : '')+
        (inner || '')+
      `</div>`;
    }

    function _kv(k, v, tone, big){
      const cls = 'pmtaVal' + (tone ? (' ' + tone) : '') + (big ? ' pmtaBig' : '');
      return `<div class="pmtaRow"><span class="pmtaKey">${esc(k)}</span><span class="${cls}">${esc(String(v))}</span></div>`;
    }

    function _renderPmtaPanel(pm, pr){
      if(!pm || !pm.enabled){
        const why = (pm && pm.reason) ? String(pm.reason) : '';
        return `<div class="pmtaBanner warn">PMTA: disabled${why ? (`<br><span class="muted">${esc(why)}</span>`) : ''}</div>`;
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
          ${_box('Spool', toneSp, 'rcpt', 'Total recipients/messages currently held by PMTA spool.', _kv('RCPT', spR, toneSp, true) + _kv('MSG', spM, toneSp, false))}
          ${_box('Queue', toneQ, 'rcpt', 'Recipients/messages still queued to be delivered.', _kv('RCPT', qR, toneQ, true) + _kv('MSG', qM, toneQ, false))}
          ${_box('Connections', toneC, '', 'Live SMTP sessions used for inbound/outbound traffic.', _kv('SMTP In', conIn, toneC, true) + _kv('SMTP Out', conOut, toneC, true) + _kv('Total', con, toneC, false))}
          ${_box('Last minute', toneMin, '', 'Recent PMTA throughput over the last 60 seconds.', _kv('In', minIn, toneMin, true) + _kv('Out', minOut, toneMin, true) + `<div class="pmtaSub">traffic recipients / minute</div>`)}
          ${_box('Last hour', toneHr, '', 'Rolling traffic totals for the previous 60 minutes.', _kv('In', hrIn, toneHr, true) + _kv('Out', hrOut, toneHr, true) + `<div class="pmtaSub">traffic recipients / hour</div>`)}
          ${_box('Top queues', (topTxt === '—' ? 'good' : 'warn'), '', 'Queues with the highest recipient backlog and latest queue errors.', `<div class="pmtaSub">${esc(topTxt)}</div>`)}
          ${_box('Time', 'good', '', 'Timestamp of the latest PMTA snapshot used for this panel.', `<div class="pmtaSub">${esc(ts || '—')}</div>`)}
        </div>
      `;
      return html;
    }

    function _renderPmtaCompact(pm){
      if(!pm || !pm.enabled || !pm.ok) return 'PMTA: —';
      const queue = _pmNum(pm.queued_recipients);
      const minOut = _pmNum(pm.traffic_last_min_out);
      const hrOut = _pmNum(pm.traffic_last_hr_out);
      if(queue === null && minOut === null && hrOut === null) return 'PMTA: —';
      return `Queue: ${_pmFmt(queue)} | last min out: ${_pmFmt(minOut)} | last hour out: ${_pmFmt(hrOut)}`;
    }

    if(pmEl){
      const pm = j.pmta_live || null;
      const pr = j.pmta_pressure || null;
      pmEl.innerHTML = _renderPmtaPanel(pm, pr);
    }
    if(pmCompactEl){
      const pm = j.pmta_live || null;
      pmCompactEl.textContent = _renderPmtaCompact(pm);
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
          `<span class="trendHead">Trend</span>`,
          `<span class="trendSeg del"><span class="lbl">DEL</span><span class="spark">${esc(spark(delV))}</span></span>`,
          `<span class="trendSeg bnc"><span class="lbl">BNC</span><span class="spark">${esc(spark(bncV))}</span></span>`,
          `<span class="trendSeg def"><span class="lbl">DEF</span><span class="spark">${esc(spark(defV))}</span></span>`,
          `<span class="trendSeg cmp"><span class="lbl">CMP</span><span class="spark">${esc(spark(cmpV))}</span></span>`
        ].join(' ');
      } else {
        trEl.textContent = 'Trend · —';
      }
    }

    // 5) Top domains
    renderTopDomains(card, j);

    // 7) Error types + last errors (legacy section)
    renderErrorTypes(card, j);

    // Structured issue blocks
    renderIssueBlocks(card, j);

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

    const quickEl = qk(card,'quickIssues');
    if(alerts.length){
      const txt = 'Quick issues: ' + alerts.join(' · ');
      alertsEl.textContent = txt;
      alertsEl.style.display = '';
      if(quickEl) quickEl.textContent = txt;
    }else{
      alertsEl.textContent = '';
      alertsEl.style.display = 'none';
      if(quickEl) quickEl.textContent = '';
    }

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

    state.lastJobPayload[jobId] = j;
    renderBridgeReceiver(card, j, state.latestBridgeState);
    applyFiltersAndSort();
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

  function bindDetailState(card){
    const jobId = card.dataset.jobid;
    const more = card.querySelector('details.more');
    if(!jobId || !more) return;
    const storageKey = `jobs-more-${jobId}`;
    try{
      if(sessionStorage.getItem(storageKey) === '1'){
        more.open = true;
      }
    }catch(e){ /* ignore */ }
    more.addEventListener('toggle', () => {
      try{
        sessionStorage.setItem(storageKey, more.open ? '1' : '0');
      }catch(e){ /* ignore */ }
    });
  }

  function updateFilterUrl(){
    try{
      const u = new URL(window.location.href);
      const keep = (key, val) => {
        if(!val || val === 'all' || (key === 'sort' && val === 'newest')) u.searchParams.delete(key);
        else u.searchParams.set(key, val);
      };
      keep('status', state.filters.status);
      keep('mode', state.filters.mode);
      keep('risk', state.filters.risk);
      keep('provider', state.filters.provider);
      keep('sort', state.filters.sort);
      history.replaceState(null, '', `${u.pathname}?${u.searchParams.toString()}`.replace(/\?$/, ''));
    }catch(e){ /* ignore */ }
  }

  function restoreFiltersFromQuery(){
    try{
      const p = new URLSearchParams(window.location.search || '');
      const get = (k, d) => (p.get(k) || d).toString().trim().toLowerCase();
      const status = get('status', 'all');
      const mode = get('mode', 'all');
      const risk = get('risk', 'all');
      const provider = get('provider', 'all');
      const sort = get('sort', 'newest');
      state.filters.status = ['all','running','done','paused','backoff'].includes(status) ? status : 'all';
      state.filters.mode = ['all','counts','legacy'].includes(mode) ? mode : 'all';
      state.filters.risk = ['all','internal_degraded','deliverability_high','stale'].includes(risk) ? risk : 'all';
      state.filters.provider = ['all','gmail','yahoo','outlook','icloud','other'].includes(provider) ? provider : 'all';
      state.filters.sort = ['newest','highest_risk','stalest'].includes(sort) ? sort : 'newest';
    }catch(e){ /* ignore */ }
  }

  function syncFilterInputs(){
    const bind = (id, key) => {
      const el = document.getElementById(id);
      if(!el) return;
      el.value = state.filters[key];
      el.addEventListener('change', () => {
        state.filters[key] = (el.value || 'all').toString().trim().toLowerCase();
        applyFiltersAndSort();
        updateFilterUrl();
      });
    };
    bind('fltStatus', 'status');
    bind('fltMode', 'mode');
    bind('fltRisk', 'risk');
    bind('fltProvider', 'provider');
    bind('fltSort', 'sort');
  }

  function passesRiskFilter(j){
    if(state.filters.risk === 'all') return true;
    if(state.filters.risk === 'internal_degraded') return hasInternalDegraded(j);
    if(state.filters.risk === 'deliverability_high') return hasDeliverabilityHigh(j);
    if(state.filters.risk === 'stale') return isStaleJob(j);
    return true;
  }

  function applyFiltersAndSort(){
    const rows = cards.map((card, idx) => {
      const jobId = (card.dataset.jobid || '').toString();
      const fallbackStatus = ((qk(card, 'status') && qk(card, 'status').textContent) || '').toString().trim().toLowerCase();
      const j = state.lastJobPayload[jobId] || { status: fallbackStatus, created_at: card.dataset.created || '' };
      return { card, idx, job: j };
    });

    const visible = [];
    for(const row of rows){
      const j = row.job || {};
      const statusOk = state.filters.status === 'all' || normalizeJobStatus(j) === state.filters.status;
      const modeOk = state.filters.mode === 'all' || normalizeBridgeMode(j) === state.filters.mode;
      const riskOk = passesRiskFilter(j);
      const providerOk = state.filters.provider === 'all' || detectProviderBucket(j) === state.filters.provider;
      const keep = statusOk && modeOk && riskOk && providerOk;
      row.card.style.display = keep ? '' : 'none';
      if(keep) visible.push(row);
    }

    const createdMs = (row) => {
      const ms = tsToMs(row.job.created_at || row.card.dataset.created || '');
      return Number.isFinite(ms) ? ms : 0;
    };
    const staleMin = (row) => {
      const v = freshnessMinutes(row.job);
      return Number.isFinite(v) ? v : -1;
    };
    visible.sort((a,b) => {
      if(state.filters.sort === 'highest_risk'){
        const d = riskRank(b.job) - riskRank(a.job);
        if(d !== 0) return d;
      }else if(state.filters.sort === 'stalest'){
        const d = staleMin(b) - staleMin(a);
        if(d !== 0) return d;
      }
      const byNew = createdMs(b) - createdMs(a);
      if(byNew !== 0) return byNew;
      return a.idx - b.idx;
    });

    const parent = cards[0] ? cards[0].parentElement : null;
    if(parent){
      for(const row of visible){ parent.appendChild(row.card); }
    }

    const empty = document.getElementById('jobsFilteredEmpty');
    if(empty) empty.style.display = (cards.length > 0 && visible.length === 0) ? '' : 'none';

    const meta = document.getElementById('filterMeta');
    if(meta){
      const total = cards.length;
      const shown = visible.length;
      meta.textContent = shown === total
        ? `Showing all ${total} job${total === 1 ? '' : 's'}.`
        : `Showing ${shown} of ${total} job${total === 1 ? '' : 's'}.`;
    }
  }

  restoreFiltersFromQuery();
  syncFilterInputs();

  let cards = Array.from(document.querySelectorAll('.job[data-jobid]'));
  cards.forEach(bindControls);
  cards.forEach(bindDetailState);

  async function tickAll(){
    for(const c of cards){
      await tickCard(c);
    }
    applyFiltersAndSort();
  }

  async function bridgeDebugTick(){
    try{
      const r = await fetch('/api/accounting/bridge/status');
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && j.ok && j.bridge){
        const b = j.bridge || {};
        state.latestBridgeState = b;
        cards.forEach(card => {
          const jid = (card.dataset.jobid || "").toString();
          const snapshot = state.lastJobPayload[jid];
          renderBridgeConnectionBadge(card, b);
          if(snapshot) renderBridgeReceiver(card, snapshot, b);
        });
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
      state.latestBridgeState = null;
      cards.forEach(card => {
        const jid = (card.dataset.jobid || "").toString();
        const snapshot = state.lastJobPayload[jid] || {};
        renderBridgeConnectionBadge(card, null);
        renderBridgeReceiver(card, snapshot, null);
      });
      console.error('[Bridge↔Shiva Debug] bridge status exception', e);
    }
  }

  function _fmtTsAge(ts){
    const raw = (ts || '').toString().trim();
    if(!raw) return '—';
    const mins = ageMin(raw);
    if(mins === null) return esc(raw);
    if(mins < 1) return `${esc(raw)} (just now)`;
    if(mins < 60) return `${esc(raw)} (${mins}m ago)`;
    const h = Math.floor(mins / 60);
    const m = mins % 60;
    return `${esc(raw)} (${h}h ${m}m ago)`;
  }

  function _shortCursor(v){
    const raw = (v || '').toString().trim();
    if(!raw) return '—';
    if(raw.length <= 44) return raw;
    return `${raw.slice(0, 22)}…${raw.slice(-16)}`;
  }

  function renderBridgeReceiver(card, j, b){
    const el = qk(card, 'bridgeReceiver');
    if(!el){ return; }

    const modeRaw = (j && j.bridge_mode ? j.bridge_mode : (b && b.bridge_mode ? b.bridge_mode : 'counts')).toString().trim().toLowerCase();
    const isLegacy = modeRaw === 'legacy';
    const isCounts = !isLegacy;

    const pollSuccessTs = (j && j.bridge_last_success_ts) || (b && b.last_success_ts) || '';
    const accountingTs = (j && j.accounting_last_update_ts) || (j && j.accounting_last_ts) || '';

    if(isCounts){
      el.innerHTML = [
        'Data source: <b>Bridge snapshot</b>',
        `Last poll success: <b>${_fmtTsAge(pollSuccessTs)}</b>`,
        `Last accounting update: <b>${_fmtTsAge(accountingTs)}</b>`,
      ].join('<br>');
      return;
    }

    const hasMore = !!(j && j.bridge_has_more);
    const cursorShort = _shortCursor((j && j.bridge_last_cursor) || '');
    const received = Number((j && j.received) || 0);
    const ingested = Number((j && j.ingested) || 0);
    const duplicates = Number((j && j.duplicates_dropped) || 0);
    const notFound = Number((j && j.job_not_found) || 0);
    const lagSecRaw = Number(j && j.ingestion_lag_seconds);
    const lagMins = Number.isFinite(lagSecRaw) && lagSecRaw >= 0
      ? Math.floor(lagSecRaw / 60)
      : ageMin((j && j.ingestion_last_event_ts) || '');
    const lagTxt = (lagMins === null) ? '—' : (lagMins <= 1 ? 'caught up' : `${lagMins}m`);

    el.innerHTML = [
      'Data source: <b>Event ingestion</b>',
      `Cursor progress: has_more=<b>${hasMore ? 'yes' : 'no'}</b> · last_cursor=<code>${esc(cursorShort)}</code>`,
      `Ingestion stats: received=<b>${received}</b> · ingested=<b>${ingested}</b> · duplicates=<b>${duplicates}</b> · job_not_found=<b>${notFound}</b>`,
      `Ingestion last event: <b>${_fmtTsAge((j && j.ingestion_last_event_ts) || '')}</b> · lag: <b>${esc(lagTxt)}</b>`,
    ].join('<br>');
  }


  document.getElementById('btnRefreshAll')?.addEventListener('click', tickAll);

  applyFiltersAndSort();
  tickAll();
  bridgeDebugTick();
  setInterval(tickAll, 1200);
  setInterval(bridgeDebugTick, 5000);
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

    .titleTip{ display:inline-flex; align-items:center; gap:6px; }
    .tip{display:inline-flex; align-items:center; justify-content:center; width:18px; height:18px; border-radius:999px;
      border:1px solid rgba(255,255,255,.18); background: rgba(0,0,0,.18); color: rgba(255,255,255,.86);
      font-size: 12px; cursor: help; position: relative; user-select:none}
    .tip:hover::after{
      content: attr(data-tip);
      position: absolute;
      left: 0;
      top: 24px;
      min-width: 240px;
      max-width: 420px;
      background: rgba(0,0,0,.72);
      border: 1px solid rgba(255,255,255,.18);
      box-shadow: 0 18px 55px rgba(0,0,0,.35);
      color: rgba(255,255,255,.92);
      padding: 10px 12px;
      border-radius: 14px;
      z-index: 999;
      white-space: normal;
    }
  </style>
</head>
<body>
  <div class="wrap">

    <div class="top">
      <div>
        <h1 class="titleTip">Campaigns <span class="tip" data-tip="Manage saved campaigns. Each campaign keeps its own SMTP/message/recipient settings.">ⓘ</span></h1>
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
          <span class="tip" data-tip="Open this campaign to edit settings and start a new job.">ⓘ</span>

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
      <table>
        <thead>
          <tr>
            <th style="min-width:310px">Key</th>
            <th style="min-width:260px">Value</th>
            <th style="min-width:190px">Info</th>
            <th style="min-width:320px">Default / ENV / UI</th>
            <th style="min-width:160px">Actions</th>
          </tr>
        </thead>
        <tbody id="tb">
          <tr><td colspan="5" class="mini">Loading…</td></tr>
        </tbody>
      </table>
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
    const tb = document.getElementById('tb');
    const q = (document.getElementById('q')?.value || '').trim().toLowerCase();

    const rows = [];
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

      rows.push(`<tr data-key="${esc(key)}">`+
        `<td>`+
          `<div><code>${esc(key)}</code>`+
            `<span class="tip" data-tip="${esc(desc)}">ⓘ</span>`+
          `</div>`+
          `<div class="mini">Group: <b>${esc(group)}</b></div>`+
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
      `</tr>`);
    }

    tb.innerHTML = rows.join('') || `<tr><td colspan="5" class="mini">No matches.</td></tr>`;

    // bind input changes
    tb.querySelectorAll('input[data-k], textarea[data-k]').forEach(el => {
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
    tb.querySelectorAll('button[data-act]').forEach(btn => {
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
  <title>Domain States</title>
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
        <h2 style="margin:0">Domain States</h2>
        <div class="muted"><a href="/campaigns" id="backLink">← Back</a> · This page analyzes <b>Sender Emails</b> domains for the selected campaign (SQLite).</div>
      </div>
      <div class="row">
        <input id="q" placeholder="Search domain..." />
        <a href="#" id="btnReload">Reload</a>
      </div>
    </div>

    <div class="card">
      <div class="row">
        <div><b>Sender emails:</b> <span id="rTotals" class="muted">—</span></div>
        <div><b>Safe domains:</b> <span id="sTotals" class="muted">—</span></div>
        <div class="muted">Checks: MX + blacklist + SPF/DKIM/DMARC (best-effort DNS).</div>
      </div>
    </div>

    <div class="card">
      <h3 style="margin:0 0 10px">Sender domains</h3>
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
            <th>SPF</th>
            <th>DKIM</th>
            <th>DMARC</th>
            </tr>
          </thead>
          <tbody id="tblR"></tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h3 style="margin:0 0 10px">Safe domains</h3>
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
            <th>SPF</th>
            <th>DKIM</th>
            <th>DMARC</th>
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
    document.getElementById('tblR').innerHTML = `<tr><td colspan="9" class="bad">Missing campaign id. Open Domains from a campaign.</td></tr>`;
    document.getElementById('tblS').innerHTML = `<tr><td colspan="9" class="bad">Missing campaign id. Open Domains from a campaign.</td></tr>`;
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

  function policyBadge(v){
    const st = (v || '').toString().toLowerCase();
    if(st === 'pass') return '<span class="good">PASS</span>';
    if(st === 'missing') return '<span class="warn">MISSING</span>';
    if(st === 'unknown_selector') return '<span class="warn">UNKNOWN SELECTOR</span>';
    return '<span class="warn">UNKNOWN</span>';
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
      from_email: saved.from_email || ''
    };

    const r = await fetch('/api/domains_stats', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const j = await r.json();

    if(!j.ok){
      document.getElementById('tblR').innerHTML = `<tr><td colspan="9" class="bad">${esc(j.error || 'error')}</td></tr>`;
      document.getElementById('tblS').innerHTML = `<tr><td colspan="9" class="bad">${esc(j.error || 'error')}</td></tr>`;
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
          `<td>${listedBadge(!!(it.listed ?? it.any_listed))}</td>`+
          `<td>${policyBadge((it.spf || {}).status)}</td>`+
          `<td>${policyBadge((it.dkim || {}).status)}</td>`+
          `<td>${policyBadge((it.dmarc || {}).status)}</td>`+
        `</tr>`);
      }
      return rows.join('') || `<tr><td colspan="9" class="muted">No results.</td></tr>`;
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

    .titleTip{display:inline-flex; align-items:center; gap:6px}
    .tip{display:inline-flex; align-items:center; justify-content:center; width:18px; height:18px; border-radius:999px;
      border:1px solid rgba(255,255,255,.18); background: rgba(0,0,0,.18); color: rgba(255,255,255,.86);
      font-size: 12px; cursor: help; position: relative; user-select:none}
    .tip:hover::after{
      content: attr(data-tip);
      position: absolute;
      left: 0;
      top: 24px;
      min-width: 240px;
      max-width: 420px;
      background: rgba(0,0,0,.72);
      border: 1px solid rgba(255,255,255,.18);
      box-shadow: 0 18px 55px rgba(0,0,0,.35);
      color: rgba(255,255,255,.92);
      padding: 10px 12px;
      border-radius: 14px;
      z-index: 999;
      white-space: normal;
    }
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
      <h3 style="margin:0 0 10px" class="titleTip">Recent Results <span class="tip" data-tip="Browse job results in pages. Use Prev/Next to navigate the latest processed recipients.">ⓘ</span></h3>
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

    <div class="card" id="schedulerTelemetryCard" style="display:none;">
      <details open>
        <summary style="cursor:pointer; font-weight:700; margin-bottom:8px">Scheduler + Lanes Telemetry</summary>
        <div class="muted" id="telemetryHeader">—</div>
        <div style="margin-top:8px" id="telemetryProviderGroups" class="muted"></div>
        <div style="overflow:auto; max-height:260px; margin-top:10px">
          <table>
            <thead>
              <tr>
                <th>Lane + Provider</th>
                <th>State</th>
                <th>Def/HF/TO</th>
                <th>Next allowed</th>
                <th>Inflight</th>
                <th>Last reason/error</th>
                <th>Suggested caps</th>
              </tr>
            </thead>
            <tbody id="telemetryLanes"></tbody>
          </table>
        </div>
        <div style="margin-top:10px" class="muted" id="telemetryEvents">—</div>
      </details>
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

  function fmtRate(v){ return (Number(v||0) * 100).toFixed(1) + '%'; }

  function renderSchedulerTelemetry(t){
    const card = document.getElementById('schedulerTelemetryCard');
    if(!card) return;
    if(!t){ card.style.display = 'none'; return; }
    card.style.display = '';

    const rollout = t.rollout || {};
    const scheduler = t.scheduler || {};
    const fallback = t.fallback || {};
    const hdr = `mode=${esc(scheduler.mode || 'legacy')} · rollout=${esc(rollout.effective_mode || 'off')} · concurrency=${scheduler.concurrency_enabled ? 'on' : 'off'} (${Number(scheduler.max_parallel_lanes||1)}) · fallback=${fallback.active ? 'ACTIVE' : 'inactive'}`;
    const h = document.getElementById('telemetryHeader');
    if(h) h.textContent = hdr;

    const groups = ((t.provider_canonicalization || {}).groups || {});
    const gtxt = Object.entries(groups).map(([k,v]) => `${k}:${v}`).join(' · ');
    const gp = document.getElementById('telemetryProviderGroups');
    if(gp) gp.textContent = gtxt ? (`Provider groups: ${gtxt}`) : 'Provider groups: —';

    const lanes = (t.lanes || []);
    const tbody = document.getElementById('telemetryLanes');
    if(tbody){
      tbody.innerHTML = lanes.map((ln) => {
        const next = Number(ln.seconds_remaining || 0) > 0 ? `${Number(ln.seconds_remaining).toFixed(0)}s` : 'now';
        const err = (ln.last_denial_reason || ln.last_reason || (ln.last_error_samples||[])[0] || '').toString();
        const laneCaps = ((ln.recommended_caps||{}).lane || {});
        const learnCaps = ((ln.recommended_caps||{}).learning || {});
        const compactCaps = `C:${laneCaps.chunk_size_cap ?? '-'} W:${laneCaps.workers_cap ?? '-'} D:${laneCaps.delay_floor ?? '-'} · L:C${learnCaps.chunk_size_cap ?? '-'} W${learnCaps.workers_cap ?? '-'}`;
        return `<tr>`+
          `<td>${esc(ln.sender_label || ('sender#' + Number(ln.sender_idx||0)))} · ${esc(ln.provider_domain || '')}</td>`+
          `<td>${esc(ln.state || 'HEALTHY')}</td>`+
          `<td>${fmtRate(ln.deferral_rate)} / ${fmtRate(ln.hardfail_rate)} / ${fmtRate(ln.timeout_rate)}</td>`+
          `<td>${esc(next)}</td>`+
          `<td>${ln.inflight ? 'yes' : 'no'}</td>`+
          `<td title="${esc((ln.last_error_samples||[]).join(' | '))}">${esc(err.slice(0, 80))}</td>`+
          `<td>${esc(compactCaps)}</td>`+
        `</tr>`;
      }).join('') || `<tr><td colspan="7" class="muted">No scheduler lanes telemetry.</td></tr>`;
    }

    const ev = document.getElementById('telemetryEvents');
    if(ev){
      const fReasons = (fallback.reasons || []).map(x => esc(String(x))).join(' | ') || 'none';
      const completions = (t.executor || {}).recent_completions || [];
      const lastExec = completions.slice(-5).map(x => `${x.lane}:${x.status}`).join(' | ') || 'none';
      ev.textContent = `Fallback reasons: ${fReasons} · Executor recent: ${lastExec}`;
    }
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

    document.getElementById("statusPill").textContent = `Status: ${j.status}`;
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

    const domBody = document.getElementById('domState');
    if(domBody){
      domBody.innerHTML = rows.map(x => {
        const bar = `<div class="smallBar"><div style="width:${x.pct}%"></div></div>`;
        return `<tr>`+
          `<td>${esc(x.dom)}</td>`+
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
    const cs = (j.chunk_states || []).slice().reverse();
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

    renderSchedulerTelemetry(j.scheduler_telemetry || null);

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
            context = _create_default_ssl_context()
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=smtp_timeout, context=context)
        else:
            steps.append("connect:plain")
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=smtp_timeout)
            server.ehlo()
            steps.append("ehlo")
            if smtp_security == "starttls":
                steps.append("starttls")
                context = _create_default_ssl_context()
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
_SHIVA_DISABLE_BLACKLIST_RAW = os.getenv("SHIVA_DISABLE_BLACKLIST")
if _SHIVA_DISABLE_BLACKLIST_RAW is None:
    _SHIVA_DISABLE_BLACKLIST_RAW = os.getenv("DISABLE_BLACKLIST")
SHIVA_DISABLE_BLACKLIST = (_SHIVA_DISABLE_BLACKLIST_RAW or "0").strip().lower() in {"1", "true", "yes", "on"}
_BLACKLIST_DISABLE_LOGGED = False


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


def _log_blacklist_disabled_once() -> None:
    global _BLACKLIST_DISABLE_LOGGED
    if SHIVA_DISABLE_BLACKLIST and not _BLACKLIST_DISABLE_LOGGED:
        _BLACKLIST_DISABLE_LOGGED = True
        logging.getLogger("shiva").warning("Blacklist checks are disabled via SHIVA_DISABLE_BLACKLIST=1")


if SHIVA_DISABLE_BLACKLIST:
    _log_blacklist_disabled_once()


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
    with _MX_CACHE_LOCK:
        exp = float(_MX_CACHE_EXPIRES_AT.get(d, 0.0) or 0.0)
        if d in _MX_CACHE and exp > now_ts:
            return _MX_CACHE[d]
        if d in _MX_CACHE and exp <= now_ts:
            _MX_CACHE.pop(d, None)
            _MX_CACHE_EXPIRES_AT.pop(d, None)

    def _cache_and_return(out: dict) -> dict:
        ttl = MX_CACHE_TTL_OK if out.get("status") in {"mx", "a_fallback"} else MX_CACHE_TTL_SOFT_FAIL
        with _MX_CACHE_LOCK:
            _MX_CACHE[d] = out
            _MX_CACHE_EXPIRES_AT[d] = time.time() + float(ttl)
        return out

    mx_query = _dns_lookup(d, "MX")
    mx_hosts: List[str] = [str(x).strip().rstrip(".") for x in (mx_query.get("records") or []) if str(x).strip()]
    if mx_hosts:
        out = {"domain": d, "status": "mx", "mx_hosts": mx_hosts[:8]}
        return _cache_and_return(out)

    a_query = _dns_lookup(d, "A")
    a_records = [str(x).strip() for x in (a_query.get("records") or []) if str(x).strip()]
    if a_records:
        out = {"domain": d, "status": "a_fallback", "mx_hosts": []}
        return _cache_and_return(out)

    mx_err = str(mx_query.get("error") or "")
    a_err = str(a_query.get("error") or "")
    if _is_dns_transient_error(mx_err) or _is_dns_transient_error(a_err):
        out = {"domain": d, "status": "unknown", "mx_hosts": []}
        return _cache_and_return(out)

    out = {"domain": d, "status": "none", "mx_hosts": []}
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


def _smtp_probe_input(item: Tuple[str, dict]) -> dict:
    email, route = item
    return _smtp_rcpt_probe(email, route)


def pre_send_recipient_filter(emails: List[str], *, smtp_probe: bool = True) -> Tuple[List[str], List[str], dict]:
    """Pre-send recipient filter with syntax/domain checks + optional SMTP probes."""
    ok: List[str] = []
    bad: List[str] = []

    if not RECIPIENT_FILTER_ENABLE_ROUTE_CHECK:
        cleaned = [(e or "").strip() for e in (emails or []) if (e or "").strip()]
        report: Dict[str, Any] = {
            "enabled": True,
            "checks": ["syntax"],
            "route_check": False,
            "smtp_probe": False,
            "smtp_probe_limit": 0,
            "smtp_probe_used": 0,
            "rejected": {"no_route": 0, "smtp": 0},
            "domains": {},
            "kept": len(cleaned),
            "dropped": 0,
        }
        return cleaned, [], report

    report: Dict[str, Any] = {
        "enabled": True,
        "checks": ["syntax", "mx_or_a"],
        "route_check": True,
        "smtp_probe": bool(smtp_probe and RECIPIENT_FILTER_ENABLE_SMTP_PROBE),
        "smtp_probe_limit": int(max(0, RECIPIENT_FILTER_SMTP_PROBE_LIMIT or 0)),
        "smtp_probe_used": 0,
        "rejected": {"no_route": 0, "smtp": 0},
        "domains": {},
    }

    cleaned: List[str] = []
    email_domains: Dict[str, str] = {}
    domain_first_email: Dict[str, str] = {}
    ordered_domains: List[str] = []
    for e in emails or []:
        em = (e or "").strip()
        d = _extract_domain_from_email(em)
        if not d:
            bad.append(em)
            continue
        cleaned.append(em)
        email_domains[em] = d
        if d not in domain_first_email:
            domain_first_email[d] = em
            ordered_domains.append(d)

    route_by_domain: Dict[str, dict] = {}
    if ordered_domains:
        route_workers = min(len(ordered_domains), int(RECIPIENT_FILTER_ROUTE_THREADS or 1))
        if route_workers <= 1:
            for d in ordered_domains:
                route_by_domain[d] = domain_mail_route(d)
        else:
            with ThreadPoolExecutor(max_workers=route_workers) as pool:
                for d, route in zip(ordered_domains, pool.map(domain_mail_route, ordered_domains)):
                    route_by_domain[d] = route

    smtp_probe_by_domain: Dict[str, dict] = {}
    probe_domains: List[str] = []
    if report["smtp_probe"] and int(report["smtp_probe_limit"] or 0) > 0:
        for d in ordered_domains:
            route = route_by_domain.get(d) or {"domain": d, "status": "unknown", "mx_hosts": []}
            if route.get("status") in {"mx", "a_fallback"}:
                probe_domains.append(d)
            if len(probe_domains) >= int(report["smtp_probe_limit"] or 0):
                break

    if probe_domains:
        probe_workers = min(len(probe_domains), int(RECIPIENT_FILTER_SMTP_THREADS or 1))
        probe_inputs = [(domain_first_email[d], route_by_domain[d]) for d in probe_domains]
        if probe_workers <= 1:
            for d in probe_domains:
                smtp_probe_by_domain[d] = _smtp_rcpt_probe(domain_first_email[d], route_by_domain[d])
        else:
            with ThreadPoolExecutor(max_workers=probe_workers) as pool:
                probe_results = pool.map(_smtp_probe_input, probe_inputs)
                for d, probe in zip(probe_domains, probe_results):
                    smtp_probe_by_domain[d] = probe
        report["smtp_probe_used"] = len(smtp_probe_by_domain)

    for em in cleaned:
        d = email_domains.get(em, "")
        route = route_by_domain.get(d) or {"domain": d, "status": "unknown", "mx_hosts": []}
        status = route.get("status", "unknown")
        dom_report = route
        probe = smtp_probe_by_domain.get(d)
        if probe is not None:
            dom_report = {**route, "smtp_probe": probe}
        report["domains"][d] = dom_report

        if status == "none":
            bad.append(em)
            report["rejected"]["no_route"] += 1
            continue

        if probe is not None and (not probe.get("ok")) and int(probe.get("code") or 0) >= 500:
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
    mx_hosts = [str(x).strip().rstrip(".") for x in (_dns_lookup(d, "MX").get("records") or []) if str(x).strip()]
    for exch in mx_hosts:
        a_records = [str(x).strip() for x in (_dns_lookup(exch, "A").get("records") or []) if str(x).strip()]
        if not a_records:
            a_records = _resolve_ipv4(exch)
        for ip in a_records:
            if ip not in seen:
                seen.add(ip)
                out.append(ip)

    # 2) Common hostnames (fallback)
    for h in (d, f"mail.{d}", f"smtp.{d}"):
        a_records = [str(x).strip() for x in (_dns_lookup(h, "A").get("records") or []) if str(x).strip()]
        if not a_records:
            a_records = _resolve_ipv4(h)
        for ip in a_records:
            if ip not in seen:
                seen.add(ip)
                out.append(ip)

    return out


def sender_domain_counts(sender_emails_text: str) -> dict:
    """Parse sender emails textarea and return unique domain counts + syntax stats."""
    emails = parse_multiline(sender_emails_text or "", dedupe_lower=True)
    valid, invalid = filter_valid_emails(emails)
    counts: Dict[str, int] = {}
    for em in valid:
        d = _extract_domain_from_email(em)
        if not d:
            continue
        counts[d] = counts.get(d, 0) + 1
    return {
        "emails_total": len(emails),
        "emails_invalid": len(invalid),
        "counts": counts,
        "valid_emails": valid,
    }


def _dns_txt_lookup(name: str) -> dict:
    return _dns_lookup(name, "TXT")


def _dns_lookup(name: str, rtype: str) -> dict:
    q = (name or "").strip().lower().strip(".")
    typ = (rtype or "TXT").strip().upper()
    if not q:
        return {"ok": False, "records": [], "error": "empty"}
    resolver_error = "resolver_unavailable"
    if DNS_RESOLVER is not None:
        try:
            ans = DNS_RESOLVER.resolve(q, typ)  # type: ignore
            records: List[str] = []
            for r in ans:
                if typ == "TXT":
                    parts = getattr(r, "strings", None)
                    if parts:
                        try:
                            txt = "".join(
                                p.decode("utf-8", errors="ignore") if isinstance(p, (bytes, bytearray)) else str(p)
                                for p in parts
                            )
                        except Exception:
                            txt = str(r)
                    else:
                        txt = str(r)
                    txt = txt.strip().strip('"')
                    if txt:
                        records.append(txt)
                elif typ == "MX":
                    exch = str(getattr(r, "exchange", "") or "").rstrip(".")
                    if exch:
                        records.append(exch)
                else:
                    item = str(r).strip().strip('"')
                    if item:
                        records.append(item)
            return {"ok": True, "records": records[:12], "error": ""}
        except Exception as e:
            resolver_error = str(e)[:180]

    fallback = _dns_lookup_doh(q, typ)
    if fallback.get("ok"):
        return fallback
    fb_error = str(fallback.get("error") or "")[:180]
    combined = f"{resolver_error}; doh={fb_error}" if fb_error else resolver_error
    return {"ok": False, "records": [], "error": combined}


def _dns_lookup_doh(name: str, rtype: str = "TXT") -> dict:
    q = (name or "").strip().lower().strip(".")
    typ = (rtype or "TXT").strip().upper()
    if not q:
        return {"ok": False, "records": [], "error": "empty"}

    headers = {
        "accept": "application/dns-json, application/json",
        "user-agent": "shiva-dns-check/1.0",
    }
    last_error = ""
    for endpoint in DNS_TXT_DOH_ENDPOINTS:
        try:
            url = f"{endpoint}?name={quote_plus(q)}&type={quote_plus(typ)}"
            req = Request(url, headers=headers)
            with urlopen(req, timeout=4) as resp:
                raw = resp.read()
            payload = json.loads(raw.decode("utf-8", errors="ignore") or "{}")
            answers = payload.get("Answer") or []
            records: List[str] = []
            for item in answers:
                data = str((item or {}).get("data") or "").strip()
                if not data:
                    continue
                if typ == "TXT":
                    data = data.strip('"')
                elif typ == "MX":
                    parts = data.split()
                    data = (parts[-1] if parts else "").strip().rstrip(".")
                else:
                    data = data.strip('"')
                if data:
                    records.append(data)
            if records:
                return {"ok": True, "records": records[:12], "error": ""}

            status = int(payload.get("Status", -1)) if str(payload.get("Status", "")).isdigit() else -1
            if status in (0, 3):
                return {"ok": True, "records": [], "error": ""}
            last_error = f"doh_status_{status}"
        except Exception as e:
            last_error = str(e)[:180]
    return {"ok": False, "records": [], "error": (last_error or "doh_failed")}


def _is_dns_transient_error(error: str) -> bool:
    msg = str(error or "").lower()
    return any(x in msg for x in ("timeout", "servfail", "refused", "temporary failure", "unreachable"))


def _dkim_selectors_from_env() -> List[str]:
    raw = [
        os.getenv("DKIM_SELECTOR", "") or "",
        os.getenv("DKIM_SELECTORS", "") or "",
        os.getenv("DEFAULT_DKIM_SELECTOR", "") or "",
    ]
    out: List[str] = []
    for item in raw:
        for part in str(item).replace(";", ",").split(","):
            s = (part or "").strip().lower().strip(".")
            if s and s not in out:
                out.append(s)
    return out


def _dkim_selectors_for_domain() -> List[str]:
    configured = _dkim_selectors_from_env()
    if configured:
        return configured
    return list(COMMON_DKIM_SELECTORS)


def compute_sender_domain_states(domain_counts: Dict[str, int]) -> List[dict]:
    """Domain States = sender domains used for sending (from-address domains)."""
    out_items: List[dict] = []
    selectors = _dkim_selectors_for_domain()
    domains_sorted = sorted((domain_counts or {}).items(), key=lambda x: x[1], reverse=True)

    for dom, cnt in domains_sorted:
        route = domain_mail_route(dom)
        mx_status = str(route.get("status") or "unknown")
        mx_hosts = list(route.get("mx_hosts") or [])
        mx_host = mx_hosts[0] if mx_hosts else ""
        mail_ips = resolve_sender_domain_ips(dom)

        listing_details: List[dict] = []
        if SHIVA_DISABLE_BLACKLIST:
            _log_blacklist_disabled_once()
        else:
            for hit in check_domain_dnsbl(dom):
                listing_details.append({"target": "domain", **hit})
            if mx_host:
                for hit in check_domain_dnsbl(mx_host):
                    listing_details.append({"target": "mx_host", **hit})
            for ip in mail_ips:
                for hit in check_ip_dnsbl(ip):
                    listing_details.append({"target": f"ip:{ip}", **hit})

        spf_txt = _dns_txt_lookup(dom)
        spf_hits = [x for x in (spf_txt.get("records") or []) if str(x).lower().startswith("v=spf1")]
        spf = {
            "status": (
                "pass" if spf_hits
                else ("missing" if spf_txt.get("ok") else "unknown")
            ),
            "record": (spf_hits[0] if spf_hits else ""),
            "error": ("" if spf_txt.get("ok") else spf_txt.get("error", "")),
        }

        dmarc_txt = _dns_txt_lookup(f"_dmarc.{dom}")
        dmarc_hits = [x for x in (dmarc_txt.get("records") or []) if str(x).lower().startswith("v=dmarc1")]
        dmarc = {
            "status": (
                "pass" if dmarc_hits
                else ("missing" if dmarc_txt.get("ok") else "unknown")
            ),
            "record": (dmarc_hits[0] if dmarc_hits else ""),
            "error": ("" if dmarc_txt.get("ok") else dmarc_txt.get("error", "")),
        }

        dkim = {"status": "unknown_selector", "record": "", "selector": "", "error": ""}
        if selectors:
            found = None
            last_err = ""
            for sel in selectors:
                txt = _dns_txt_lookup(f"{sel}._domainkey.{dom}")
                hits = [x for x in (txt.get("records") or []) if str(x).lower().startswith("v=dkim1")]
                if hits:
                    found = (sel, hits[0])
                    break
                if not txt.get("ok"):
                    last_err = str(txt.get("error") or "")
            if found:
                dkim = {"status": "pass", "record": found[1], "selector": found[0], "error": ""}
            else:
                dkim = {"status": "missing", "record": "", "selector": selectors[0], "error": last_err}

        out_items.append(
            {
                "domain": dom,
                "count": cnt,
                "mx_status": mx_status,
                "mx_hosts": mx_hosts,
                "mail_ips": mail_ips,
                "any_listed": bool(listing_details),
                "mx": {"status": mx_status, "records": mx_hosts},
                "mx_host": mx_host,
                "mail_ip": mail_ips,
                "listed": bool(listing_details),
                "blacklist_details": listing_details[:30],
                "spf": spf,
                "dkim": dkim,
                "dmarc": dmarc,
            }
        )
    return out_items


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
            _exec_upsert_compat(
                conn,
                "INSERT INTO job_recipients(job_id, campaign_id, rcpt, first_seen_at, last_seen_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(job_id, rcpt) DO UPDATE SET campaign_id=excluded.campaign_id, last_seen_at=excluded.last_seen_at",
                (jid, cid, em, ts, ts),
                "UPDATE job_recipients SET campaign_id=?, last_seen_at=? WHERE job_id=? AND rcpt=?",
                (cid, ts, jid, em),
                "INSERT INTO job_recipients(job_id, campaign_id, rcpt, first_seen_at, last_seen_at) VALUES(?,?,?,?,?)",
                (jid, cid, em, ts, ts),
            )
            conn.commit()
        finally:
            conn.close()


def db_seed_job_recipient_index(job_id: str, campaign_id: str, recipients: List[str]) -> int:
    """Index recipients and initialize their status as `not_yet` before sending."""
    jid = (job_id or "").strip().lower()
    cid = (campaign_id or "").strip()
    if not jid:
        return 0

    deduped: List[str] = []
    seen: set = set()
    for raw in recipients or []:
        rcpt = str(raw or "").strip().lower()
        if not rcpt or rcpt in seen:
            continue
        seen.add(rcpt)
        deduped.append(rcpt)

    if not deduped:
        return 0

    ts = now_iso()
    inserted = 0
    with DB_LOCK:
        conn = _db_conn()
        try:
            for rcpt in deduped:
                _exec_upsert_compat(
                    conn,
                    "INSERT INTO job_recipients(job_id, campaign_id, rcpt, first_seen_at, last_seen_at) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(job_id, rcpt) DO UPDATE SET campaign_id=excluded.campaign_id, last_seen_at=excluded.last_seen_at",
                    (jid, cid, rcpt, ts, ts),
                    "UPDATE job_recipients SET campaign_id=?, last_seen_at=? WHERE job_id=? AND rcpt=?",
                    (cid, ts, jid, rcpt),
                    "INSERT INTO job_recipients(job_id, campaign_id, rcpt, first_seen_at, last_seen_at) VALUES(?,?,?,?,?)",
                    (jid, cid, rcpt, ts, ts),
                )
                _db_set_outcome_payload(conn, {
                    "job_id": jid,
                    "rcpt": rcpt,
                    "status": "not_yet",
                    "message_id": "",
                    "dsn_status": "",
                    "dsn_diag": "",
                    "updated_at": ts,
                })
                inserted += 1
            conn.commit()
        finally:
            conn.close()
    return inserted


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

    def _attempt(ctx: Optional[Any]) -> Tuple[bool, dict, str]:
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
            ctx = _create_unverified_ssl_context()
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

    def _attempt(ctx: Optional[Any]) -> Tuple[bool, str, str, dict]:
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
            ctx = _create_unverified_ssl_context()
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
SHIVA_DISABLE_BACKOFF = (os.getenv("SHIVA_DISABLE_BACKOFF", "0") or "0").strip().lower() in {"1", "true", "yes", "on"}
SHIVA_BACKOFF_JITTER = (os.getenv("SHIVA_BACKOFF_JITTER", "off") or "off").strip().lower()
if SHIVA_BACKOFF_JITTER not in {"off", "deterministic", "random"}:
    SHIVA_BACKOFF_JITTER = "off"
try:
    SHIVA_BACKOFF_JITTER_PCT = float((os.getenv("SHIVA_BACKOFF_JITTER_PCT", "0.15") or "0.15").strip())
except Exception:
    SHIVA_BACKOFF_JITTER_PCT = 0.15
try:
    SHIVA_BACKOFF_JITTER_MAX_S = float((os.getenv("SHIVA_BACKOFF_JITTER_MAX_S", "120") or "120").strip())
except Exception:
    SHIVA_BACKOFF_JITTER_MAX_S = 120.0
try:
    SHIVA_BACKOFF_JITTER_MIN_S = float((os.getenv("SHIVA_BACKOFF_JITTER_MIN_S", "0") or "0").strip())
except Exception:
    SHIVA_BACKOFF_JITTER_MIN_S = 0.0
SHIVA_BACKOFF_JITTER_EXPORT = (os.getenv("SHIVA_BACKOFF_JITTER_EXPORT", "0") or "0").strip().lower() in {"1", "true", "yes", "on"}
SHIVA_BACKOFF_JITTER_DEBUG = (os.getenv("SHIVA_BACKOFF_JITTER_DEBUG", "0") or "0").strip().lower() in {"1", "true", "yes", "on"}

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
        host_txt = (smtp_host or "").strip()
        reason = "disabled: invalid_or_missing_smtp_host" if not host_txt else "disabled: cannot_build_monitor_base"
        return {"enabled": False, "ok": True, "reason": reason, "ts": now_iso()}

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
BRIDGE_MODE = (os.getenv("BRIDGE_MODE", "counts") or "counts").strip().lower()
if BRIDGE_MODE not in {"counts", "legacy"}:
    BRIDGE_MODE = "counts"
try:
    PMTA_BRIDGE_PULL_PORT = int((os.getenv("PMTA_BRIDGE_PULL_PORT", "8090") or "8090").strip())
except Exception:
    PMTA_BRIDGE_PULL_PORT = 8090
PMTA_BRIDGE_PULL_PATH = "/api/v1/pull"
PMTA_BRIDGE_JOB_COUNT_PATH = "/api/v1/job/count"
PMTA_BRIDGE_JOB_OUTCOMES_PATH = "/api/v1/job/outcomes"
BRIDGE_BASE_URL = (os.getenv("BRIDGE_BASE_URL", "") or "").strip()
try:
    BRIDGE_TIMEOUT_S = float((os.getenv("BRIDGE_TIMEOUT_S", "20") or "20").strip())
except Exception:
    BRIDGE_TIMEOUT_S = 20.0


try:
    PMTA_BRIDGE_PULL_S = float((os.getenv("PMTA_BRIDGE_PULL_S", "5") or "5").strip())
except Exception:
    PMTA_BRIDGE_PULL_S = 5.0
try:
    BRIDGE_POLL_INTERVAL_S = float((os.getenv("BRIDGE_POLL_INTERVAL_S", str(PMTA_BRIDGE_PULL_S)) or str(PMTA_BRIDGE_PULL_S)).strip())
except Exception:
    BRIDGE_POLL_INTERVAL_S = float(PMTA_BRIDGE_PULL_S or 5.0)
_OUTCOMES_SYNC_RAW = os.getenv("OUTCOMES_SYNC")
if _OUTCOMES_SYNC_RAW is None:
    _OUTCOMES_SYNC_RAW = os.getenv("BRIDGE_POLL_FETCH_OUTCOMES", "1")
OUTCOMES_SYNC = (_OUTCOMES_SYNC_RAW or "1").strip().lower() in {"1", "true", "yes", "on"}
BRIDGE_POLL_FETCH_OUTCOMES = bool(OUTCOMES_SYNC)
try:
    PMTA_BRIDGE_PULL_MAX_LINES = int((os.getenv("PMTA_BRIDGE_PULL_MAX_LINES", "2000") or "2000").strip())
except Exception:
    PMTA_BRIDGE_PULL_MAX_LINES = 2000

_BRIDGE_DEBUG_LOCK = threading.Lock()
_BRIDGE_DEBUG_STATE: Dict[str, Any] = {
    "last_poll_time": "",
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
    "last_latency_ms": 0,
    "last_ok_ts": "",
    "last_error_message": "",
    "last_response_keys": [],
    "last_bridge_count": 0,
    "last_processed": 0,
    "last_accepted": 0,
    "last_lines_sample": [],
    "last_cursor": "",
    "has_more": False,
    "events_received": 0,
    "events_ingested": 0,
    "duplicates_dropped": 0,
    "job_not_found": 0,
    "db_write_failures": 0,
    "missing_fields": 0,
    "internal_error_samples": [],
    "integrity_samples": [],
}

_BRIDGE_POLLER_LOCK = threading.Lock()
_BRIDGE_POLLER_STARTED = False
_BRIDGE_CURSOR_COMPAT_WARNED = False
_BRIDGE_POLL_CYCLE_LOCK = threading.Lock()


def _bridge_mode_counts_enabled() -> bool:
    return str(BRIDGE_MODE or "counts").strip().lower() == "counts"


def _resolve_bridge_pull_host_from_campaign() -> str:
    """Resolve bridge host from campaign SMTP host (latest job), not server IP."""
    with JOBS_LOCK:
        jobs = [j for j in JOBS.values() if not getattr(j, "deleted", False)]

    if jobs:
        jobs.sort(key=lambda x: x.created_at, reverse=True)
        for job in jobs:
            host = (getattr(job, "smtp_host", "") or "").strip()
            if host:
                return host

    host = (os.getenv("SHIVA_HOST", "") or "").strip()
    if host and host not in {"0.0.0.0", "::"}:
        return host
    return "127.0.0.1"


def _normalize_bridge_host(raw_host: str) -> str:
    """Normalize host coming from campaign SMTP setting for HTTP bridge URL building."""
    host = str(raw_host or "").strip()
    if not host:
        return "127.0.0.1"

    # Campaign SMTP host may contain a full URL or host:port; keep only hostname.
    if "://" in host:
        try:
            parsed = urlsplit(host)
            if parsed.hostname:
                return str(parsed.hostname).strip()
        except Exception:
            pass

    # For "hostname:port" (IPv4/domain) drop the port part.
    if host.count(":") == 1 and not host.startswith("["):
        return host.split(":", 1)[0].strip() or "127.0.0.1"

    # For bracketed IPv6 like "[::1]:2525".
    if host.startswith("[") and "]" in host:
        return host[1:host.index("]")].strip() or "127.0.0.1"

    return host


def _resolve_bridge_pull_url_runtime() -> str:
    if _bridge_mode_counts_enabled():
        return ""
    host = _normalize_bridge_host(_resolve_bridge_pull_host_from_campaign())
    limit = max(1, int(PMTA_BRIDGE_PULL_MAX_LINES or 2000))
    return f"http://{host}:{PMTA_BRIDGE_PULL_PORT}{PMTA_BRIDGE_PULL_PATH}?kinds=acct&limit={limit}"


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

    p = (path or "").strip() or "/"
    if not p.startswith("/"):
        p = "/" + p
    query = urlencode(params or {}, doseq=True)
    full_url = f"{base.rstrip('/')}{p}"
    if query:
        full_url = f"{full_url}?{query}"

    parsed = urlsplit(full_url)
    if parsed.scheme.lower() != "http":
        raise ValueError("bridge client supports HTTP only")

    host = (parsed.hostname or "").strip()
    if not host:
        raise ValueError("bridge host is missing")

    port = parsed.port or 80
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"

    conn = http.client.HTTPConnection(host, port=port, timeout=float(BRIDGE_TIMEOUT_S or 20.0))
    try:
        conn.request("GET", target, headers={"Accept": "application/json"})
        resp = conn.getresponse()
        status = int(getattr(resp, "status", 0) or 0)
        raw = (resp.read() or b"").decode("utf-8", errors="replace")
    finally:
        conn.close()

    if status != 200:
        snippet = raw[:220].replace("\n", " ").replace("\r", " ")
        raise RuntimeError(f"bridge_http_status={status} body={snippet!r}")

    try:
        obj = json.loads(raw or "{}")
    except Exception as e:
        raise ValueError(f"invalid_json_response: {e}")
    if not isinstance(obj, dict):
        raise ValueError("invalid_bridge_payload")
    return obj


def _bridge_debug_update(**kwargs: Any) -> None:
    with _BRIDGE_DEBUG_LOCK:
        _BRIDGE_DEBUG_STATE.update(kwargs)


def _bridge_push_sample(key: str, entry: dict, max_keep: int = 24) -> None:
    if not key or not isinstance(entry, dict):
        return
    with _BRIDGE_DEBUG_LOCK:
        rows = _BRIDGE_DEBUG_STATE.get(key)
        if not isinstance(rows, list):
            rows = []
        rows.append(entry)
        _BRIDGE_DEBUG_STATE[key] = rows[-max(4, int(max_keep or 24)):]

_OUTCOME_CACHE_LOCK = threading.Lock()
_OUTCOME_CACHE: Dict[Tuple[str, str], str] = {}

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


def _parse_bridge_json_row(row: Any) -> Optional[dict]:
    """Parse one bridge row as JSON-only payload.

    Bridge is the source of truth and already returns normalized JSON.
    Shiva intentionally ignores legacy CSV/plaintext rows to keep this flow
    deterministic and to avoid PMTA log parsing on the Shiva side.
    """
    if isinstance(row, dict):
        return row

    s = str(row or "").strip()
    if not s or not (s.startswith("{") and s.endswith("}")):
        return None

    try:
        ev = json.loads(s)
    except Exception:
        return None
    return ev if isinstance(ev, dict) else None


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




def _transition_allowed(prev: str, new: str) -> bool:
    p = (prev or "").strip().lower()
    n = (new or "").strip().lower()
    if not p:
        return True
    if p == n:
        return True
    if p in {"not_yet", "pending", "queued", "unknown"} and n in {"delivered", "deferred", "bounced", "complained"}:
        return True
    if p == "deferred" and n in {"delivered", "bounced", "complained"}:
        return True
    if p == "delivered" and n == "complained":
        return True
    return False


def _build_accounting_event_row(ev: dict, typ: str, rcpt: str, job_id: str) -> Dict[str, str]:
    source_file = _event_value(ev, "source_file", "source", "file", "path", "filename") or "bridge"
    source_locator = _event_value(ev, "offset", "source_offset", "line", "line_number", "line_no", "lineno")
    if not source_locator:
        source_locator = "line:unknown"
    time_logged = _event_value(ev, "time_logged", "log_time", "logged_at", "timestamp", "ts", "time", "date")
    message_id = _event_value(ev, "msgid", "message-id", "message_id", "messageid", "header_message-id", "header_message_id")
    dsn_status = _event_value(ev, "dsnStatus", "dsn_status", "enhanced-status", "enhanced_status")
    dsn_diag = _event_value(ev, "dsnDiag", "dsn_diag", "diag", "diagnostic", "smtp-diagnostic", "response")

    stable_key = "\x1f".join([
        str(source_file or ""),
        str(source_locator or ""),
        str((rcpt or "").strip().lower()),
        str((typ or "").strip().lower()),
        str(time_logged or ""),
        str(message_id or ""),
    ])
    event_id = hashlib.sha256(stable_key.encode("utf-8", "ignore")).hexdigest()

    raw_json = ""
    try:
        raw_json = json.dumps(ev, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    except Exception:
        raw_json = str(ev)

    return {
        "event_id": event_id,
        "job_id": str(job_id or ""),
        "rcpt": str((rcpt or "").strip().lower()),
        "outcome": str((typ or "").strip().lower()),
        "time_logged": str(time_logged or ""),
        "message_id": str(message_id or ""),
        "dsn_status": str(dsn_status or ""),
        "dsn_diag": str(dsn_diag or ""),
        "source_file": str(source_file or ""),
        "source_offset_or_line": str(source_locator or ""),
        "raw_json": raw_json,
    }


def _apply_outcome_to_job(job: SendJob, rcpt: str, kind: str, ev: Optional[dict] = None) -> None:
    """Update job counters in a 'unique per recipient' way using SQLite job_outcomes."""
    r = (rcpt or "").strip().lower()
    k = (kind or "").strip().lower()
    if not r or k not in {"delivered", "bounced", "deferred", "complained"}:
        return

    with _OUTCOME_CACHE_LOCK:
        prev = str(_OUTCOME_CACHE.get((job.id, r)) or "").strip().lower()
    if not prev:
        prev_row = db_get_outcome(job.id, r) or {}
        prev = str(prev_row.get("status") or "").strip().lower()

    message_id = _event_value(ev or {}, "msgid", "message-id", "message_id", "messageid", "header_message-id", "header_message_id")
    dsn_status = _event_value(ev or {}, "dsnStatus", "dsn_status", "enhanced-status", "enhanced_status")
    dsn_diag = _event_value(ev or {}, "dsnDiag", "dsn_diag", "diag", "diagnostic", "smtp-diagnostic", "response")

    if prev and not _transition_allowed(prev, k):
        with _OUTCOME_CACHE_LOCK:
            _OUTCOME_CACHE[(job.id, r)] = prev
        db_set_outcome(job.id, r, prev, message_id=message_id, dsn_status=dsn_status, dsn_diag=dsn_diag)
        job.accounting_last_ts = now_iso()
        return

    if prev == k:
        with _OUTCOME_CACHE_LOCK:
            _OUTCOME_CACHE[(job.id, r)] = k
        db_set_outcome(job.id, r, k, message_id=message_id, dsn_status=dsn_status, dsn_diag=dsn_diag)
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

    with _OUTCOME_CACHE_LOCK:
        _OUTCOME_CACHE[(job.id, r)] = k
    db_set_outcome(job.id, r, k, message_id=message_id, dsn_status=dsn_status, dsn_diag=dsn_diag)
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


def _classify_backoff_failure(*, spam_blocked: bool, blacklist_blocked: bool, pmta_reason: str) -> Tuple[str, str]:
    """Classify chunk preflight failures for response/backoff policy.

    Returns: (failure_type, intervention)
      - failure_type: transient_delay | block | reputation
      - intervention: short operator hint (empty for no extra action)
    """
    reason = str(pmta_reason or "").strip().lower()

    if spam_blocked or blacklist_blocked:
        return "reputation", "review sender reputation (spam score / DNSBL) before retrying"

    reputation_terms = (
        "reputation",
        "spam",
        "blacklist",
        "policy",
        "throttled due to complaints",
    )
    if any(t in reason for t in reputation_terms):
        return "reputation", "investigate domain/IP reputation and PMTA policy signals"

    transient_terms = (
        "timeout",
        "timed out",
        "temporary",
        "temporarily",
        "defer",
        "4xx",
        "try again",
        "unreachable",
        "busy",
    )
    if any(t in reason for t in transient_terms):
        return "transient_delay", ""

    return "block", ""


def _compute_backoff_wait_seconds(*, attempt: int, base_s: float, max_s: float, failure_type: str) -> float:
    """Calculate wait using failure-aware backoff strategy."""
    base_wait = max(1.0, float(base_s or 1.0)) * (2 ** max(0, int(attempt or 0) - 1))
    if failure_type == "transient_delay":
        tuned = max(5.0, base_wait * 0.5)
    elif failure_type == "reputation":
        tuned = max(base_wait, base_wait * 2.0)
    else:
        tuned = base_wait
    return min(max(float(max_s or tuned), 1.0), tuned)


def apply_backoff_jitter(
    *,
    wait_s_base: float,
    mode: str,
    pct: float,
    max_jitter_s: float,
    min_jitter_s: float,
    max_s: float,
    partition_seed: str,
    lane_key: str,
    attempt: int,
    failure_type: str,
) -> Tuple[float, float]:
    """Apply optional bounded jitter to a computed backoff wait."""
    mode2 = str(mode or "off").strip().lower()
    base_wait = max(0.0, float(wait_s_base or 0.0))
    if mode2 not in {"deterministic", "random"}:
        return min(base_wait, max(0.0, float(max_s or base_wait))), 0.0

    pct2 = max(0.0, float(pct or 0.0))
    max_jitter = max(0.0, float(max_jitter_s or 0.0))
    min_jitter = max(0.0, float(min_jitter_s or 0.0))
    jitter_amp = min(max_jitter, max(min_jitter, base_wait * pct2))

    if mode2 == "random":
        jitter_delta = random.uniform(-jitter_amp, jitter_amp)
    else:
        seed_material = f"{str(partition_seed or '').strip()}|{str(lane_key or '').strip()}|{int(attempt or 0)}|{str(failure_type or '').strip().lower()}"
        domain_seed = int(hashlib.sha256(seed_material.encode("utf-8", errors="ignore")).hexdigest()[:16], 16)
        rng = random.Random(domain_seed)
        jitter_delta = rng.uniform(-jitter_amp, jitter_amp)

    wait_final = min(max(0.0, base_wait + jitter_delta), max(0.0, float(max_s or base_wait)))
    return wait_final, jitter_delta


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

    job_id = _event_value(ev, "header_x-job-id", "x-job-id", "job-id", "job_id", "jobid").lower()
    campaign_id = _event_value(ev, "x-campaign-id", "campaign-id", "campaign_id", "cid")

    msgid = _event_value(ev, "msgid", "message-id", "message_id", "messageid", "header_message-id", "header_message_id")
    if not msgid:
        # Pick any field that looks like a Message-ID header (different acct-file schemas)
        for k, v in (ev or {}).items():
            kk = str(k or "").lower().replace("_", "-")
            if "message-id" in kk:
                msgid = v
                break

    if not job_id:
        job_id = _extract_job_id_from_text(str(msgid or ""))

    if not job_id:
        job_id = _extract_job_id_from_text(str(ev.get("raw") or ""))

    event_row = _build_accounting_event_row(ev, typ, rcpt, job_id)
    if not db_insert_accounting_event(event_row):
        _bridge_push_sample(
            "integrity_samples",
            {
                "ts": now_iso(),
                "kind": "duplicates_dropped",
                "job_id": job_id,
                "campaign_id": campaign_id,
                "rcpt": rcpt,
                "outcome": typ,
            },
        )
        return {"ok": True, "duplicate": True, "event_id": event_row.get("event_id"), "job_id": job_id, "campaign_id": campaign_id, "rcpt": rcpt, "type": typ}

    if not rcpt or typ not in {"delivered", "bounced", "deferred", "complained"}:
        _bridge_push_sample(
            "integrity_samples",
            {
                "ts": now_iso(),
                "kind": "missing_fields",
                "job_id": job_id,
                "campaign_id": campaign_id,
                "rcpt": rcpt,
                "outcome": typ,
            },
        )
        return {"ok": False, "reason": "missing_fields", "job_id": job_id, "campaign_id": campaign_id, "rcpt": rcpt, "type": typ}

    with JOBS_LOCK:
        job = JOBS.get(job_id) if job_id else None
        if not job and campaign_id:
            job = _find_job_by_campaign(campaign_id)
        if not job and rcpt:
            job = _find_job_by_recipient(rcpt)
        if not job:
            _bridge_push_sample(
                "integrity_samples",
                {
                    "ts": now_iso(),
                    "kind": "job_not_found",
                    "job_id": job_id,
                    "campaign_id": campaign_id,
                    "rcpt": rcpt,
                    "outcome": typ,
                },
            )
            return {"ok": False, "reason": "job_not_found", "job_id": job_id, "campaign_id": campaign_id, "rcpt": rcpt}

        _apply_outcome_to_job(job, rcpt, typ, ev)
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
            ev = dict(item)
            ev.setdefault("source_file", "campaign_payload")
            ev.setdefault("line", str(processed))
            event_row = _build_accounting_event_row(ev, typ, rcpt, jid)
            if not db_insert_accounting_event(event_row):
                continue

            job = JOBS.get(jid) if jid else None
            if not job or (job.campaign_id or "") != campaign_id:
                job = fallback_job
            if not job:
                continue

            _apply_outcome_to_job(job, rcpt, typ, item)
            _record_accounting_error(job, rcpt, typ, item)
            job.maybe_persist()
            accepted += 1

    return {"ok": True, "campaign_id": campaign_id, "processed": processed, "accepted": accepted}


def _db_get_bridge_cursor() -> str:
    if _bridge_mode_counts_enabled():
        return ""
    with DB_LOCK:
        conn = _db_conn()
        try:
            row = conn.execute("SELECT value FROM bridge_pull_state WHERE key='accounting_cursor'").fetchone()
            return str(row[0]).strip() if row and row[0] is not None else ""
        finally:
            conn.close()


def _db_set_bridge_cursor(cursor: str) -> None:
    if _bridge_mode_counts_enabled():
        return
    cur = (cursor or "").strip()
    if not cur:
        return
    with DB_LOCK:
        conn = _db_conn()
        try:
            ts = now_iso()
            _exec_upsert_compat(
                conn,
                "INSERT INTO bridge_pull_state(key, value, updated_at) VALUES(?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                ("accounting_cursor", cur, ts),
                "UPDATE bridge_pull_state SET value=?, updated_at=? WHERE key=?",
                (cur, ts, "accounting_cursor"),
                "INSERT INTO bridge_pull_state(key, value, updated_at) VALUES(?, ?, ?)",
                ("accounting_cursor", cur, ts),
            )
            conn.commit()
        finally:
            conn.close()


def _normalize_bridge_pull_urls(raw_url: str) -> List[str]:
    if _bridge_mode_counts_enabled():
        return []
    url = (raw_url or "").strip()
    if url and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = f"http://{url}"
    if not url:
        return []
    if "/api/v1/pull/latest" in url:
        return [url]
    if "/api/v1/pull" in url:
        latest = url.replace("/api/v1/pull", "/api/v1/pull/latest", 1)
        return [url, latest] if latest != url else [url]
    base = url.rstrip("/")
    return [f"{base}/api/v1/pull", f"{base}/api/v1/pull/latest"]


def _bridge_fetch_json(req_url: str, headers: Dict[str, str], max_request_attempts: int = 3) -> Tuple[Optional[dict], Optional[Exception]]:
    request_error: Optional[Exception] = None
    for attempt in range(1, max_request_attempts + 1):
        _bridge_debug_update(last_req_url=req_url)
        req_t0 = time.time()
        try:
            parsed = urlsplit(req_url)
            if parsed.scheme and parsed.scheme.lower() != "http":
                raise ValueError("bridge client supports HTTP only")
            if not parsed.hostname:
                raise ValueError("bridge request URL missing host")

            global BRIDGE_BASE_URL
            BRIDGE_BASE_URL = "http://{}:{}".format(parsed.hostname, parsed.port or 80)
            params: Dict[str, Any] = {}
            for k, v in parse_qsl(parsed.query, keep_blank_values=True):
                if k in params:
                    prev = params[k]
                    if isinstance(prev, list):
                        prev.append(v)
                    else:
                        params[k] = [prev, v]
                else:
                    params[k] = v
            obj = bridge_get_json(parsed.path or "/", params)
            _bridge_debug_update(
                last_http_ok=True,
                last_http_status=200,
                last_latency_ms=int((time.time() - req_t0) * 1000),
            )
            request_error = None
            return obj, None
        except Exception as e:
            request_error = e
            _bridge_debug_update(
                last_http_ok=False,
                last_error_message=str(e),
                last_error_ts=now_iso(),
            )
        if attempt < max_request_attempts:
            time.sleep(min(1.0 * attempt, 2.0))
    return None, request_error


def _bridge_outcome_emails(obj: dict, key: str) -> List[str]:
    bucket = obj.get(key)
    if not isinstance(bucket, dict):
        return []
    emails = bucket.get("emails")
    if not isinstance(emails, list):
        return []
    out: List[str] = []
    for item in emails:
        email = str(item or "").strip().lower()
        if email:
            out.append(email)
    return out


def _bridge_outcome_pairs(obj: dict) -> Dict[str, str]:
    """Flatten bridge outcomes payload into rcpt->outcome map.

    Supports canonical buckets (`delivered`, `deferred`, `bounced`, `complained`),
    dotted-key variants (`delivered.emails`, etc), and top-level `emails` entries
    when they include an explicit outcome/status.
    """
    pairs: Dict[str, str] = {}

    def _set_pair(raw_rcpt: Any, outcome: str) -> None:
        rcpt = str(raw_rcpt or "").strip().lower()
        status = str(outcome or "").strip().lower()
        if not rcpt or status not in {"delivered", "deferred", "bounced", "complained"}:
            return
        pairs[rcpt] = status

    for status in ("delivered", "deferred", "bounced", "complained"):
        for email in _bridge_outcome_emails(obj, status):
            _set_pair(email, status)

        dotted_emails = obj.get(f"{status}.emails")
        if isinstance(dotted_emails, list):
            for email in dotted_emails:
                _set_pair(email, status)

    top_level_emails = obj.get("emails")
    if isinstance(top_level_emails, list):
        for item in top_level_emails:
            if isinstance(item, str):
                # Top-level strings are ambiguous without an explicit status.
                continue
            if not isinstance(item, dict):
                continue
            _set_pair(
                item.get("rcpt") or item.get("email"),
                item.get("outcome") or item.get("status"),
            )

    return pairs


def _bridge_outcome_records(obj: dict) -> Dict[str, Dict[str, str]]:
    """Flatten bridge outcomes payload into rcpt -> detailed outcome record."""
    records: Dict[str, Dict[str, str]] = {}

    def _set_record(item: Any, fallback_status: str = "") -> None:
        if isinstance(item, str):
            rcpt = item
            status = fallback_status
            payload = {}
        elif isinstance(item, dict):
            rcpt = item.get("rcpt") or item.get("email")
            status = item.get("outcome") or item.get("status") or fallback_status
            payload = item
        else:
            return

        email = str(rcpt or "").strip().lower()
        norm_status = str(status or "").strip().lower()
        if not email or norm_status not in {"delivered", "deferred", "bounced", "complained"}:
            return

        records[email] = {
            "rcpt": email,
            "status": norm_status,
            "message_id": str(payload.get("message_id") or payload.get("msgid") or ""),
            "dsn_status": str(payload.get("dsn_status") or payload.get("dsnStatus") or ""),
            "dsn_diag": str(payload.get("dsn_diag") or payload.get("dsnDiag") or payload.get("diag") or ""),
            "response": str(payload.get("response") or payload.get("smtp_response") or payload.get("smtp-response") or ""),
        }

    for status in ("delivered", "deferred", "bounced", "complained"):
        bucket = obj.get(status)
        emails = []
        if isinstance(bucket, dict):
            emails = bucket.get("emails") if isinstance(bucket.get("emails"), list) else []
        elif isinstance(bucket, list):
            emails = bucket
        if isinstance(emails, list):
            for row in emails:
                _set_record(row, status)

        dotted_emails = obj.get(f"{status}.emails")
        if isinstance(dotted_emails, list):
            for row in dotted_emails:
                _set_record(row, status)

    top_level_emails = obj.get("emails")
    if isinstance(top_level_emails, list):
        for row in top_level_emails:
            _set_record(row)

    return records


def _bridge_sync_job_outcomes(job_id: str, obj: dict) -> Dict[str, int]:
    counts = {"delivered": 0, "deferred": 0, "bounced": 0, "complained": 0}
    normalized_job_id = (job_id or "").strip().lower()
    records = _bridge_outcome_records(obj)
    pairs = {rcpt: str(item.get("status") or "") for rcpt, item in records.items()}
    if not pairs:
        pairs = _bridge_outcome_pairs(obj)
        records = {rcpt: {"rcpt": rcpt, "status": status} for rcpt, status in pairs.items()}

    for status in pairs.values():
        if status in counts:
            counts[status] += 1

    with DB_LOCK:
        conn = _db_conn()
        try:
            for rcpt, status in pairs.items():
                rec = records.get(rcpt) or {}
                _db_set_outcome_payload(conn, {
                    "job_id": normalized_job_id,
                    "rcpt": rcpt,
                    "status": status,
                    "message_id": str(rec.get("message_id") or ""),
                    "dsn_status": str(rec.get("dsn_status") or ""),
                    "dsn_diag": str(rec.get("dsn_diag") or rec.get("response") or ""),
                    "updated_at": now_iso(),
                })
            conn.commit()
        finally:
            conn.close()
    return counts


def _bridge_apply_accounting_error_samples(job: SendJob, outcomes_obj: dict) -> None:
    records = _bridge_outcome_records(outcomes_obj)
    if not records:
        return

    errors: List[dict] = []
    for rcpt, row in records.items():
        status = str(row.get("status") or "").lower()
        if status not in {"deferred", "bounced", "complained"}:
            continue
        parts = [
            str(row.get("response") or "").strip(),
            str(row.get("dsn_status") or "").strip(),
            str(row.get("dsn_diag") or "").strip(),
        ]
        detail = " | ".join([p for p in parts if p])
        if not detail:
            continue
        kind = "temporary_error" if status == "deferred" else "blocked"
        errors.append({
            "ts": now_iso(),
            "email": rcpt,
            "type": status,
            "kind": kind,
            "detail": detail,
        })

    if not errors:
        return

    errors = errors[-40:]
    merged = list(job.accounting_last_errors or []) + errors
    job.accounting_last_errors = merged[-40:]


def _replace_job_accounting_from_bridge_count(job: SendJob, count_obj: dict) -> int:
    """Replace job accounting counters from bridge `/job/count` payload.

    Bridge count response is authoritative for Shiva's aggregate counters, so this
    method intentionally performs assignment (not increment/decrement) on each
    successful poll to avoid drift across repeated polls.

    Returns linked_emails_count from payload.
    """
    linked_count = int(count_obj.get("linked_emails_count") or 0)
    job.delivered = int(count_obj.get("delivered_count") or 0)
    job.deferred = int(count_obj.get("deferred_count") or 0)
    job.bounced = int(count_obj.get("bounced_count") or 0)
    job.complained = int(count_obj.get("complained_count") or 0)
    job.accounting_last_ts = now_iso()

    # Keep a lightweight per-minute snapshot to support trend charts while using
    # deterministic replacement semantics for the counters.
    try:
        now_min = int(time.time() // 60)
        if job.outcome_series and int(job.outcome_series[-1].get("t_min") or 0) == now_min:
            bucket = job.outcome_series[-1]
        else:
            bucket = {"t_min": now_min}
            job.outcome_series.append(bucket)
            if len(job.outcome_series) > 180:
                job.outcome_series = job.outcome_series[-140:]
        bucket["delivered"] = int(job.delivered or 0)
        bucket["deferred"] = int(job.deferred or 0)
        bucket["bounced"] = int(job.bounced or 0)
        bucket["complained"] = int(job.complained or 0)
    except Exception:
        pass

    return linked_count


def _active_jobs_for_bridge_poll() -> List['SendJob']:
    active_statuses = {"queued", "running", "backoff", "paused"}

    def _has_not_yet_resolved_recipients(job: 'SendJob') -> bool:
        total = int(getattr(job, "total", 0) or 0)
        if total <= 0:
            return False
        counts = db_get_job_outcome_counts(str(getattr(job, "id", "") or ""))
        resolved = (
            int(counts.get("delivered") or 0)
            + int(counts.get("deferred") or 0)
            + int(counts.get("bounced") or 0)
            + int(counts.get("complained") or 0)
        )
        return resolved < total

    with JOBS_LOCK:
        jobs = [
            j for j in JOBS.values()
            if not getattr(j, "deleted", False)
            and (
                str(getattr(j, "status", "") or "").strip().lower() in active_statuses
                or _has_not_yet_resolved_recipients(j)
            )
        ]
    jobs.sort(key=lambda x: str(x.created_at or ""), reverse=True)
    return jobs


def _job_pmta_job_id(job: 'SendJob') -> str:
    pmta_job_id = str(getattr(job, "pmta_job_id", "") or "").strip().lower()
    if pmta_job_id:
        return pmta_job_id
    fallback = str(getattr(job, "id", "") or "").strip().lower()
    return fallback


def _poll_accounting_bridge_once() -> dict:
    if not _BRIDGE_POLL_CYCLE_LOCK.acquire(blocking=False):
        return {
            "ok": False,
            "error": "busy",
            "reason": "busy",
            "processed": 0,
            "accepted": 0,
            "count": 0,
            "batches": 0,
            "jobs_total": 0,
            "jobs_success": 0,
            "jobs_failed": 0,
            "jobs": [],
            "cursor": "",
        }

    logger = logging.getLogger("shiva")
    try:
        t0 = time.time()
        poll_ts = now_iso()
        _bridge_debug_update(last_poll_time=poll_ts)
        base_url = _resolve_bridge_base_url_runtime()
        global BRIDGE_BASE_URL
        BRIDGE_BASE_URL = base_url
        if not base_url:
            _bridge_debug_update(
                last_attempt_ts=now_iso(),
                attempts=int(_BRIDGE_DEBUG_STATE.get("attempts", 0)) + 1,
                last_ok=False,
                connected=False,
                failure_count=int(_BRIDGE_DEBUG_STATE.get("failure_count", 0)) + 1,
                last_error_ts=now_iso(),
                last_error="bridge_base_url_not_configured",
                last_duration_ms=int((time.time() - t0) * 1000),
            )
            return {"ok": False, "error": "bridge_base_url_not_configured", "processed": 0, "accepted": 0}

        headers = {"Accept": "application/json"}
        jobs = _active_jobs_for_bridge_poll()

        total_processed = 0
        total_accepted = 0
        total_count = 0
        last_obj: Any = {}
        last_error = ""
        job_results: List[Dict[str, Any]] = []
        jobs_success = 0
        jobs_failed = 0

        for job in jobs:
            jid = _job_pmta_job_id(job)
            if not jid:
                continue

            total_processed += 1
            job_result: Dict[str, Any] = {
                "pmta_job_id": jid,
                "outcomes_sync_enabled": bool(BRIDGE_POLL_FETCH_OUTCOMES),
            }
            count_url = f"{base_url}{PMTA_BRIDGE_JOB_COUNT_PATH}?job_id={quote_plus(jid)}"
            count_obj, count_error = _bridge_fetch_json(count_url, headers)
            if count_error is not None or not isinstance(count_obj, dict):
                err_msg = f"bridge_count_failed job_id={jid} error={count_error}"
                logger.exception(err_msg) if count_error is not None else logger.error(err_msg)
                last_error = err_msg
                jobs_failed += 1
                job_result["error"] = str(count_error or "bridge_count_failed")
                job_results.append(job_result)
                continue

            outcomes_obj: Optional[dict] = None
            outcomes_error: Optional[Exception] = None
            if BRIDGE_POLL_FETCH_OUTCOMES:
                outcomes_url = f"{base_url}{PMTA_BRIDGE_JOB_OUTCOMES_PATH}?job_id={quote_plus(jid)}"
                outcomes_obj, outcomes_error = _bridge_fetch_json(outcomes_url, headers)
                if outcomes_error is not None:
                    logger.warning("Bridge outcomes fetch failed for job_id=%s: %s", jid, outcomes_error)
                    job_result["outcomes_sync_error"] = str(outcomes_error)

            if BRIDGE_POLL_FETCH_OUTCOMES and outcomes_obj and outcomes_error is None:
                try:
                    _bridge_sync_job_outcomes(jid, outcomes_obj)
                except Exception:
                    logger.exception("Bridge outcome sync failed for job_id=%s", jid)

            linked_count = int(count_obj.get("linked_emails_count") or 0)
            with JOBS_LOCK:
                live_job = JOBS.get(str(getattr(job, "id", "") or "").strip().lower())
                if live_job and not getattr(live_job, "deleted", False):
                    linked_count = _replace_job_accounting_from_bridge_count(live_job, count_obj)
                    if BRIDGE_POLL_FETCH_OUTCOMES and outcomes_obj and outcomes_error is None:
                        _bridge_apply_accounting_error_samples(live_job, outcomes_obj)
                    live_job.maybe_persist()

            total_accepted += 1
            total_count += int(linked_count)
            last_obj = count_obj
            jobs_success += 1
            job_result["counts"] = {
                "linked_emails_count": int(linked_count),
                "delivered_count": int(count_obj.get("delivered_count") or 0),
                "deferred_count": int(count_obj.get("deferred_count") or 0),
                "bounced_count": int(count_obj.get("bounced_count") or 0),
                "complained_count": int(count_obj.get("complained_count") or 0),
            }
            job_result["updated_at"] = now_iso()
            job_results.append(job_result)

        ok = (last_error == "")
        prev_state = dict(_BRIDGE_DEBUG_STATE)
        debug_payload: Dict[str, Any] = {
            "last_attempt_ts": now_iso(),
            "last_success_ts": now_iso() if ok else str(_BRIDGE_DEBUG_STATE.get("last_success_ts") or ""),
            "attempts": int(_BRIDGE_DEBUG_STATE.get("attempts", 0)) + 1,
            "success_count": int(_BRIDGE_DEBUG_STATE.get("success_count", 0)) + (1 if ok else 0),
            "failure_count": int(_BRIDGE_DEBUG_STATE.get("failure_count", 0)) + (0 if ok else 1),
            "last_ok": ok,
            "connected": ok,
            "last_error": last_error,
            "last_error_message": last_error,
            "last_error_ts": now_iso() if not ok else str(_BRIDGE_DEBUG_STATE.get("last_error_ts") or ""),
            "last_ok_ts": now_iso() if ok else str(_BRIDGE_DEBUG_STATE.get("last_ok_ts") or ""),
            "last_lines_sample": [],
            "last_duration_ms": int((time.time() - t0) * 1000),
            "last_cursor": "",
            "has_more": False,
            "events_received": int(_BRIDGE_DEBUG_STATE.get("events_received", 0) or 0) + total_processed,
            "events_ingested": int(_BRIDGE_DEBUG_STATE.get("events_ingested", 0) or 0) + total_accepted,
            "duplicates_dropped": int(_BRIDGE_DEBUG_STATE.get("duplicates_dropped", 0) or 0),
            "job_not_found": int(_BRIDGE_DEBUG_STATE.get("job_not_found", 0) or 0),
            "missing_fields": int(_BRIDGE_DEBUG_STATE.get("missing_fields", 0) or 0),
            "db_write_failures": int(_DB_WRITER_STATUS.get("failed", 0) or 0) + int(_DB_WRITER_STATUS.get("queue_full", 0) or 0),
            "internal_error_samples": list(_BRIDGE_DEBUG_STATE.get("internal_error_samples") or [])[-24:],
            "integrity_samples": list(_BRIDGE_DEBUG_STATE.get("integrity_samples") or [])[-24:],
        }
        if ok:
            debug_payload.update(
                last_bridge_count=total_count,
                last_processed=total_processed,
                last_accepted=total_accepted,
                last_response_keys=list(last_obj.keys()) if isinstance(last_obj, dict) else [],
            )
        else:
            debug_payload.update(
                last_bridge_count=int(prev_state.get("last_bridge_count", 0) or 0),
                last_processed=int(prev_state.get("last_processed", 0) or 0),
                last_accepted=int(prev_state.get("last_accepted", 0) or 0),
                last_response_keys=list(prev_state.get("last_response_keys") or []),
            )

        _bridge_debug_update(**debug_payload)
        return {
            "ok": ok,
            "processed": total_processed,
            "accepted": total_accepted,
            "count": total_count,
            "batches": len(jobs),
            "jobs_total": len(jobs),
            "jobs_success": jobs_success,
            "jobs_failed": jobs_failed,
            "jobs": job_results,
            "cursor": "",
            "error": last_error,
        }
    finally:
        _BRIDGE_POLL_CYCLE_LOCK.release()


def _accounting_bridge_poller_thread():
    logger = logging.getLogger("shiva")
    while True:
        try:
            _poll_accounting_bridge_once()
        except Exception:
            logger.exception("Bridge polling loop failed; continuing")
        time.sleep(max(1.0, float(BRIDGE_POLL_INTERVAL_S or PMTA_BRIDGE_PULL_S or 5.0)))


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
        context = _create_default_ssl_context()
        return smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=smtp_timeout, context=context)

    server = smtplib.SMTP(smtp_host, smtp_port, timeout=smtp_timeout)
    server.ehlo()
    if smtp_security == "starttls":
        context = _create_default_ssl_context()
        server.starttls(context=context)
        server.ehlo()
    return server


def _coerce_scalar_number(value: Any, *, as_type: str, default: Any) -> Any:
    """Coerce potentially list-like values into a scalar int/float safely."""
    try:
        v = value
        if isinstance(v, (list, tuple)):
            if not v:
                return default
            v = v[0]
        s = str(v).strip()
        if not s:
            return default
        if as_type == "int":
            return int(float(s)) if "." in s else int(s)
        return float(s)
    except Exception:
        return default


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

    smtp_port = _coerce_scalar_number(smtp_port, as_type="int", default=2525)
    smtp_timeout = _coerce_scalar_number(smtp_timeout, as_type="int", default=25)
    delay_s = _coerce_scalar_number(delay_s, as_type="float", default=0.0)
    chunk_size = _coerce_scalar_number(chunk_size, as_type="int", default=50)
    thread_workers = _coerce_scalar_number(thread_workers, as_type="int", default=5)
    sleep_chunks = _coerce_scalar_number(sleep_chunks, as_type="float", default=0.0)

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

    # Prime PMTA live panel with an initial snapshot regardless of adaptive/backoff toggles.
    # This keeps the UI informative (connected/unreachable/disabled reason) even when
    # PMTA_QUEUE_BACKOFF and PMTA_PRESSURE_CONTROL are both disabled.
    try:
        initial_live = pmta_live_panel(smtp_host=smtp_host)
        with JOBS_LOCK:
            job.pmta_live = initial_live
            job.pmta_live_ts = now_iso()
    except Exception:
        pass

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
    jitter_pct_runtime = float(SHIVA_BACKOFF_JITTER_PCT)
    ai_subject_chain = [str(x).strip() for x in (subjects or []) if str(x).strip()] or ["(no subject)"]
    ai_body_chain = str(body or "")

    scheduler_mode = (get_env("SHIVA_SCHEDULER_MODE", "legacy") or "legacy").strip().lower() or "legacy"
    if scheduler_mode not in {"legacy", "lane_v2"}:
        scheduler_mode = "legacy"
    rollout_mode = (get_env("SHIVA_ROLLOUT_MODE", "off") or "off").strip().lower() or "off"
    canary_percent = max(0, min(100, int(get_env_int("SHIVA_CANARY_PERCENT", 5))))
    canary_seed_mode = (get_env("SHIVA_CANARY_SEED_MODE", "job_id") or "job_id").strip().lower() or "job_id"
    canary_allowlist_campaigns_raw = str(get_env("SHIVA_CANARY_ALLOWLIST_CAMPAIGNS", "") or "")
    canary_denylist_campaigns_raw = str(get_env("SHIVA_CANARY_DENYLIST_CAMPAIGNS", "") or "")
    canary_allowlist_senders_raw = str(get_env("SHIVA_CANARY_ALLOWLIST_SENDERS", "") or "")
    canary_debug = bool(get_env_bool("SHIVA_CANARY_DEBUG", False))
    shadow_export_enabled = bool(get_env_bool("SHIVA_SHADOW_EXPORT", False))
    shadow_max_events = max(1, int(get_env_int("SHIVA_SHADOW_MAX_EVENTS", 50)))
    force_legacy = bool(get_env_bool("SHIVA_FORCE_LEGACY", False))
    force_disable_concurrency = bool(get_env_bool("SHIVA_FORCE_DISABLE_CONCURRENCY", False))
    lane_debug_enabled = bool(get_env_bool("SHIVA_LANE_DEBUG", False))
    lane_baseline_enabled = bool(get_env_bool("SHIVA_LANE_BASELINE_REPORT", False))
    lane_metrics_enabled = bool(get_env_bool("SHIVA_LANE_METRICS", False))
    lane_metrics_window = max(1, int(get_env_int("SHIVA_LANE_METRICS_WINDOW", 200)))
    lane_metrics_use_ema = bool(get_env_bool("SHIVA_LANE_METRICS_EMA", True))
    lane_metrics_export = bool(get_env_bool("SHIVA_LANE_METRICS_EXPORT", False))
    lane_registry_enabled = bool(get_env_bool("SHIVA_LANE_REGISTRY", False))
    lane_state_export = bool(get_env_bool("SHIVA_LANE_STATE_EXPORT", False))
    lane_accounting_recon_enabled = bool(get_env_bool("SHIVA_LANE_ACCOUNTING_RECON", False))
    lane_accounting_recon_interval_s = max(5, int(get_env_int("SHIVA_LANE_ACCOUNTING_RECON_INTERVAL_S", 30)))
    lane_accounting_recon_export = bool(get_env_bool("SHIVA_LANE_ACCOUNTING_RECON_EXPORT", False))
    lane_accounting_recon_debug = bool(get_env_bool("SHIVA_LANE_ACCOUNTING_RECON_DEBUG", False))
    soft_provider_budgets_enabled = bool(get_env_bool("SHIVA_SOFT_PROVIDER_BUDGETS", False))
    soft_provider_budget_debug = bool(get_env_bool("SHIVA_SOFT_BUDGET_DEBUG", False))
    provider_cooldown_s = max(1, int(get_env_int("SHIVA_PROVIDER_COOLDOWN_S", 90)))
    provider_quarantine_respect = bool(get_env_bool("SHIVA_PROVIDER_QUARANTINE_RESPECT", True))
    provider_state_bias_enabled = bool(get_env_bool("SHIVA_PROVIDER_STATE_BIAS", True))
    provider_bias_throttled = float(get_env_float("SHIVA_PROVIDER_BIAS_THROTTLED", 0.35))
    provider_bias_quarantined = float(get_env_float("SHIVA_PROVIDER_BIAS_QUAR", 0.05))
    provider_bias_infra = float(get_env_float("SHIVA_PROVIDER_BIAS_INFRA", 0.05))
    probe_mode_enabled = bool(get_env_bool("SHIVA_PROBE_MODE", False))
    probe_duration_s = max(1, int(get_env_int("SHIVA_PROBE_DURATION_S", 300)))
    probe_rounds = max(1, int(get_env_int("SHIVA_PROBE_ROUNDS", 2)))
    probe_chunk_size = max(1, int(_env_int("SHIVA_PROBE_CHUNK_SIZE", 80)))
    probe_workers = max(1, int(_env_int("SHIVA_PROBE_WORKERS", 2)))
    probe_delay_floor_s = max(0.0, float(_env_float("SHIVA_PROBE_DELAY_FLOOR_S", 0.8)))
    probe_sleep_floor_s = max(0.0, float(get_env_float("SHIVA_PROBE_SLEEP_FLOOR_S", 2)))
    probe_min_providers = max(1, int(get_env_int("SHIVA_PROBE_MIN_PROVIDERS", 3)))
    probe_export = bool(get_env_bool("SHIVA_PROBE_EXPORT", False))
    budget_manager_enabled = bool(get_env_bool("SHIVA_BUDGET_MANAGER", False))
    budget_debug = bool(get_env_bool("SHIVA_BUDGET_DEBUG", False))
    budget_provider_max_inflight_default = max(1, min(10, int(get_env_int("SHIVA_PROVIDER_MAX_INFLIGHT_DEFAULT", 1))))
    budget_provider_max_inflight_json = str(get_env("SHIVA_PROVIDER_MAX_INFLIGHT_JSON", "") or "").strip()
    budget_provider_min_gap_default = max(0.0, min(3600.0, float(get_env_float("SHIVA_PROVIDER_MIN_GAP_S_DEFAULT", 0.0))))
    budget_provider_min_gap_json = str(get_env("SHIVA_PROVIDER_MIN_GAP_S_JSON", "") or "").strip()
    budget_provider_cooldown_default = max(0.0, min(3600.0, float(get_env_float("SHIVA_PROVIDER_COOLDOWN_S_DEFAULT", 0.0))))
    budget_provider_cooldown_json = str(get_env("SHIVA_PROVIDER_COOLDOWN_S_JSON", "") or "").strip()
    budget_sender_max_inflight = max(1, min(10, int(get_env_int("SHIVA_SENDER_MAX_INFLIGHT", 1))))
    budget_apply_to_retry = bool(get_env_bool("SHIVA_BUDGET_APPLY_TO_RETRY", False))
    budget_apply_to_probe = bool(get_env_bool("SHIVA_BUDGET_APPLY_TO_PROBE", True))
    budget_export = bool(get_env_bool("SHIVA_BUDGET_EXPORT", False))
    learning_caps_enabled = bool(get_env_bool("SHIVA_LEARNING_CAPS", False))
    learning_caps_enforce = bool(get_env_bool("SHIVA_LEARNING_CAPS_ENFORCE", False))
    caps_resolver_enabled = bool(get_env_bool("SHIVA_CAPS_RESOLVER", False))
    caps_resolver_export = bool(get_env_bool("SHIVA_CAPS_RESOLVER_EXPORT", False))
    caps_resolver_debug = bool(get_env_bool("SHIVA_CAPS_RESOLVER_DEBUG", False))
    learning_refresh_s = max(30, int(get_env_int("SHIVA_LEARNING_REFRESH_S", 120)))
    learning_min_samples = max(1, int(get_env_int("SHIVA_LEARNING_MIN_SAMPLES", 200)))
    learning_recency_days = max(1, int(get_env_int("SHIVA_LEARNING_RECENCY_DAYS", 14)))
    learning_export = bool(get_env_bool("SHIVA_LEARNING_EXPORT", False))
    provider_canon_enabled = bool(get_env_bool("SHIVA_PROVIDER_CANON", False))
    provider_canon_enforce = bool(get_env_bool("SHIVA_PROVIDER_CANON_ENFORCE", False))
    provider_canon_export = bool(get_env_bool("SHIVA_PROVIDER_CANON_EXPORT", False))
    policy_packs_enabled = bool(get_env_bool("SHIVA_POLICY_PACKS", False))
    policy_packs_enforce = bool(get_env_bool("SHIVA_POLICY_PACKS_ENFORCE", False))
    policy_pack_name_default = str(get_env("SHIVA_POLICY_PACK_NAME", "default") or "default").strip().lower() or "default"
    policy_packs_json = str(get_env("SHIVA_POLICY_PACKS_JSON", "") or "")
    policy_packs_export = bool(get_env_bool("SHIVA_POLICY_PACKS_EXPORT", False))
    policy_packs_debug = bool(get_env_bool("SHIVA_POLICY_PACKS_DEBUG", False))
    guardrails_enabled = bool(get_env_bool("SHIVA_GUARDRAILS", False))
    guardrails_strict = bool(get_env_bool("SHIVA_GUARDRAILS_STRICT", False))
    guardrails_export = bool(get_env_bool("SHIVA_GUARDRAILS_EXPORT", False))
    guardrails_debug = bool(get_env_bool("SHIVA_GUARDRAILS_DEBUG", False))
    guard_limits = {
        "max_parallel_lanes": max(1, int(get_env_int("SHIVA_GUARD_MAX_PARALLEL_LANES", 8))),
        "max_total_workers": max(1, int(get_env_int("SHIVA_GUARD_MAX_TOTAL_WORKERS", 80))),
        "max_workers_per_lane": max(1, int(get_env_int("SHIVA_GUARD_MAX_WORKERS_PER_LANE", 12))),
        "max_chunk_size": max(1, int(get_env_int("SHIVA_GUARD_MAX_CHUNK_SIZE", 1000))),
        "max_delay_s": max(0.0, float(get_env_float("SHIVA_GUARD_MAX_DELAY_S", 5.0))),
        "max_min_gap_s": max(1.0, float(get_env_float("SHIVA_GUARD_MAX_MIN_GAP_S", 300))),
        "max_cooldown_s": max(1, int(get_env_int("SHIVA_GUARD_MAX_COOLDOWN_S", 3600))),
    }
    provider_alias_json = str(get_env("SHIVA_PROVIDER_ALIAS_JSON", "") or "").strip()
    provider_suffix_json = str(get_env("SHIVA_PROVIDER_SUFFIX_JSON", "") or "").strip()
    provider_mx_fingerprint = bool(get_env_bool("SHIVA_PROVIDER_MX_FINGERPRINT", False))
    provider_unknown_group = str(get_env("SHIVA_PROVIDER_UNKNOWN_GROUP", "other") or "other").strip() or "other"
    provider_canon_debug = bool(get_env_bool("SHIVA_PROVIDER_CANON_DEBUG", False))
    learning_max_lanes_provider_json = str(get_env("SHIVA_LEARNING_MAX_LANES_PROVIDER_JSON", "") or "").strip()
    learning_delay_floor_json = str(get_env("SHIVA_LEARNING_DELAY_FLOOR_JSON", "") or "").strip()
    learning_chunk_cap_json = str(get_env("SHIVA_LEARNING_CHUNK_CAP_JSON", "") or "").strip()
    lane_v2_debug = bool(get_env_bool("SHIVA_LANE_V2_DEBUG", False))
    lane_v2_export = bool(get_env_bool("SHIVA_LANE_V2_EXPORT", False))
    lane_v2_respect_lane_states = bool(get_env_bool("SHIVA_LANE_V2_RESPECT_LANE_STATES", True))
    lane_v2_use_budgets = bool(get_env_bool("SHIVA_LANE_V2_USE_BUDGETS", True))
    lane_v2_use_soft_bias = bool(get_env_bool("SHIVA_LANE_V2_USE_SOFT_BIAS", True))
    lane_v2_max_scan = max(1, int(get_env_int("SHIVA_LANE_V2_MAX_SCAN", 50)))
    lane_concurrency_enabled = bool(get_env_bool("SHIVA_LANE_CONCURRENCY", False))
    lane_max_parallel = max(1, int(get_env_int("SHIVA_MAX_PARALLEL_LANES", 5)))
    lane_task_timeout_s = max(30, int(get_env_int("SHIVA_LANE_TASK_TIMEOUT_S", 900)))
    lane_concurrency_debug = bool(get_env_bool("SHIVA_LANE_CONCURRENCY_DEBUG", False))
    lane_concurrency_export = bool(get_env_bool("SHIVA_LANE_CONCURRENCY_EXPORT", False))
    resource_governor_enabled = bool(get_env_bool("SHIVA_RESOURCE_GOVERNOR", False))
    resource_governor_debug = bool(get_env_bool("SHIVA_RESOURCE_GOVERNOR_DEBUG", False))
    resource_governor_export = bool(get_env_bool("SHIVA_RESOURCE_GOVERNOR_EXPORT", False))
    max_total_workers = max(1, int(get_env_int("SHIVA_MAX_TOTAL_WORKERS", 40)))
    max_total_lanes = max(1, int(get_env_int("SHIVA_MAX_TOTAL_LANES", 5)))
    worker_reserve_mode = (get_env("SHIVA_WORKER_RESERVE_MODE", "workers") or "workers").strip().lower() or "workers"
    if worker_reserve_mode not in {"workers", "sessions"}:
        worker_reserve_mode = "workers"
    governor_apply_in_sequential = bool(get_env_bool("SHIVA_GOVERNOR_APPLY_IN_SEQUENTIAL", False))
    governor_pmta_scale = bool(get_env_bool("SHIVA_GOVERNOR_PMTA_SCALE", True))
    governor_pmta_level2_factor = max(0.05, min(1.0, float(get_env_float("SHIVA_GOVERNOR_PMTA_LEVEL2_FACTOR", 0.75))))
    governor_pmta_level3_factor = max(0.05, min(1.0, float(get_env_float("SHIVA_GOVERNOR_PMTA_LEVEL3_FACTOR", 0.50))))
    concurrency_stop_grace_s = max(1, int(get_env_int("SHIVA_CONCURRENCY_STOP_GRACE_S", 30)))
    concurrency_stop_force_disable = bool(get_env_bool("SHIVA_CONCURRENCY_STOP_FORCE_DISABLE", True))
    fallback_controller_enabled = bool(get_env_bool("SHIVA_FALLBACK_CONTROLLER", False))
    fallback_debug = bool(get_env_bool("SHIVA_FALLBACK_DEBUG", False))
    fallback_export = bool(get_env_bool("SHIVA_FALLBACK_EXPORT", False))
    single_domain_waves_enabled = bool(get_env_bool("SHIVA_SINGLE_DOMAIN_WAVES", False))
    single_domain_waves_debug = bool(get_env_bool("SHIVA_SINGLE_DOMAIN_WAVES_DEBUG", False))
    single_domain_waves_export = bool(get_env_bool("SHIVA_SINGLE_DOMAIN_WAVES_EXPORT", False))
    single_domain_only_if_providers_eq = bool(get_env_bool("SHIVA_SINGLE_DOMAIN_ONLY_IF_PROVIDERS_EQ", True))
    wave_burst_tokens = max(1, int(get_env_int("SHIVA_WAVE_BURST_TOKENS", 400)))
    wave_refill_per_sec = max(0.1, float(get_env_float("SHIVA_WAVE_REFILL_PER_SEC", 3.0)))
    wave_token_cost_per_msg = max(1, int(get_env_int("SHIVA_WAVE_TOKEN_COST_PER_MSG", 1)))
    wave_min_tokens_to_start_chunk = max(1, int(get_env_int("SHIVA_WAVE_MIN_TOKENS_TO_START_CHUNK", 50)))
    wave_max_parallel_single_domain = max(1, min(10, int(get_env_int("SHIVA_WAVE_MAX_PARALLEL_LANES_SINGLE_DOMAIN", 1))))
    wave_stagger_enabled = bool(get_env_bool("SHIVA_WAVE_STAGGER_ENABLED", True))
    wave_stagger_step_s = max(0.0, float(get_env_float("SHIVA_WAVE_STAGGER_STEP_S", 25)))
    wave_stagger_seed_mode = str(get_env("SHIVA_WAVE_STAGGER_SEED_MODE", "job") or "job").strip().lower()
    if wave_stagger_seed_mode not in {"job", "static"}:
        wave_stagger_seed_mode = "job"
    wave_adaptive_enabled = bool(get_env_bool("SHIVA_WAVE_ADAPTIVE", True))
    wave_deferral_up = max(0.0, min(1.0, float(get_env_float("SHIVA_WAVE_DEFERRAL_UP", 0.10))))
    wave_deferral_down = max(0.0, min(1.0, float(get_env_float("SHIVA_WAVE_DEFERRAL_DOWN", 0.20))))
    wave_hardfail_down = max(0.0, min(1.0, float(get_env_float("SHIVA_WAVE_HARDFAIL_DOWN", 0.03))))
    wave_ramp_up_factor = max(1.0, float(get_env_float("SHIVA_WAVE_RAMP_UP_FACTOR", 1.08)))
    wave_ramp_down_factor = min(1.0, max(0.1, float(get_env_float("SHIVA_WAVE_RAMP_DOWN_FACTOR", 0.70))))
    wave_min_refill = max(0.1, float(get_env_float("SHIVA_WAVE_MIN_REFILL", 0.5)))
    wave_max_refill = max(wave_min_refill, float(get_env_float("SHIVA_WAVE_MAX_REFILL", 10.0)))
    wave_min_burst = max(1.0, float(get_env_float("SHIVA_WAVE_MIN_BURST", 100)))
    wave_max_burst = max(wave_min_burst, float(get_env_float("SHIVA_WAVE_MAX_BURST", 1200)))
    fallback_window_s = max(60, int(get_env_int("SHIVA_FALLBACK_WINDOW_S", 300)))
    fallback_deferral_rate = min(1.0, max(0.0, float(get_env_float("SHIVA_FALLBACK_DEFERRAL_RATE", 0.35))))
    fallback_hardfail_rate = min(1.0, max(0.0, float(get_env_float("SHIVA_FALLBACK_HARDFAIL_RATE", 0.05))))
    fallback_timeout_rate = min(1.0, max(0.0, float(get_env_float("SHIVA_FALLBACK_TIMEOUT_RATE", 0.08))))
    fallback_blocked_per_min = max(0.0, float(get_env_float("SHIVA_FALLBACK_BLOCKED_PER_MIN", 10.0)))
    fallback_pmta_pressure_level = max(0, int(get_env_int("SHIVA_FALLBACK_PMTA_PRESSURE_LEVEL", 3)))
    fallback_min_active_s = max(1, int(get_env_int("SHIVA_FALLBACK_MIN_ACTIVE_S", 180)))
    fallback_recovery_s = max(1, int(get_env_int("SHIVA_FALLBACK_RECOVERY_S", 300)))
    fallback_disable_reenable = bool(get_env_bool("SHIVA_FALLBACK_DISABLE_REENABLE", True))
    fallback_step1_disable_concurrency = bool(get_env_bool("SHIVA_FALLBACK_STEP1_DISABLE_CONCURRENCY", True))
    fallback_step2_disable_probe = bool(get_env_bool("SHIVA_FALLBACK_STEP2_DISABLE_PROBE", True))
    fallback_step3_switch_to_legacy = bool(get_env_bool("SHIVA_FALLBACK_STEP3_SWITCH_TO_LEGACY", True))
    lane_thresholds_raw = str(get_env("SHIVA_LANE_THRESHOLDS_JSON", "") or "").strip()
    lane_quarantine_base_s = max(1, int(get_env_int("SHIVA_LANE_QUARANTINE_BASE_S", 120)))
    lane_quarantine_max_s = max(lane_quarantine_base_s, int(get_env_int("SHIVA_LANE_QUARANTINE_MAX_S", 1800)))
    lane_metrics = LaneMetrics(window=lane_metrics_window, use_ema=lane_metrics_use_ema) if lane_metrics_enabled else None
    guard_caps_bounds_override: Dict[str, Any] = {}

    def _parse_budget_json_map(raw: str, *, value_type: str, min_v: float, max_v: float) -> Dict[str, Any]:
        txt = str(raw or "").strip()
        if not txt:
            return {}
        try:
            parsed = json.loads(txt)
        except Exception as e:
            with JOBS_LOCK:
                job.log("WARN", f"Budget JSON parse failed ({value_type}): {e}")
            return {}
        if not isinstance(parsed, dict):
            with JOBS_LOCK:
                job.log("WARN", f"Budget JSON ignored ({value_type}): expected object")
            return {}
        out: Dict[str, Any] = {}
        for k, v in parsed.items():
            key = str(k or "").strip().lower()
            if not key:
                continue
            if value_type == "int":
                try:
                    iv = int(v)
                except Exception:
                    continue
                out[key] = max(int(min_v), min(int(max_v), iv))
            else:
                try:
                    fv = float(v)
                except Exception:
                    continue
                out[key] = max(float(min_v), min(float(max_v), fv))
        return out

    lane_thresholds_override = {}
    if lane_thresholds_raw:
        try:
            parsed = json.loads(lane_thresholds_raw)
            if isinstance(parsed, dict):
                lane_thresholds_override = parsed
            else:
                job.log("WARN", "SHIVA_LANE_THRESHOLDS_JSON ignored: expected JSON object")
        except Exception as e:
            job.log("WARN", f"SHIVA_LANE_THRESHOLDS_JSON parse failed: {e}")

    lane_registry = LaneRegistry(
        thresholds=lane_thresholds_override,
        quarantine_base_s=lane_quarantine_base_s,
        quarantine_max_s=lane_quarantine_max_s,
    ) if lane_registry_enabled else None

    if lane_metrics_export:
        with JOBS_LOCK:
            job.debug_lane_metrics_snapshot = {}
    if lane_state_export:
        with JOBS_LOCK:
            job.debug_lane_states_snapshot = {}
    if probe_export:
        with JOBS_LOCK:
            job.debug_probe_status = {}
    if budget_export:
        with JOBS_LOCK:
            job.debug_budget_status = {}
    if lane_v2_export:
        with JOBS_LOCK:
            job.debug_last_lane_pick = {}
    if lane_concurrency_export:
        with JOBS_LOCK:
            job.debug_lane_executor = {}
    if resource_governor_export:
        with JOBS_LOCK:
            job.debug_resource_governor = {}
    if fallback_export:
        with JOBS_LOCK:
            job.debug_fallback = {}
    if provider_canon_export:
        with JOBS_LOCK:
            job.debug_provider_canon = {}
    if SHIVA_BACKOFF_JITTER_EXPORT:
        with JOBS_LOCK:
            job.debug_backoff_jitter = []
    if learning_export:
        with JOBS_LOCK:
            job.debug_learning_policy = {}
    if lane_accounting_recon_export:
        with JOBS_LOCK:
            job.debug_lane_accounting = {}
    if policy_packs_export:
        with JOBS_LOCK:
            job.debug_policy_pack = {}

    provider_canon = ProviderCanon.from_env(
        enabled=provider_canon_enabled,
        enforce=provider_canon_enforce,
        export=provider_canon_export,
        debug=provider_canon_debug,
        alias_json=provider_alias_json,
        suffix_json=provider_suffix_json,
        use_mx_fingerprint=provider_mx_fingerprint,
        unknown_group=provider_unknown_group,
    )
    if provider_canon_enabled and provider_alias_json and not provider_canon.alias_map:
        with JOBS_LOCK:
            job.log("WARN", "SHIVA_PROVIDER_ALIAS_JSON ignored: expected JSON object with domain->group pairs")
    if provider_canon_enabled and provider_suffix_json and not ProviderCanon._parse_json_map(provider_suffix_json):
        with JOBS_LOCK:
            job.log("WARN", "SHIVA_PROVIDER_SUFFIX_JSON ignored: expected JSON object with suffix->group pairs")

    budget_config = BudgetConfig(
        enabled=budget_manager_enabled,
        debug=budget_debug,
        provider_max_inflight_default=budget_provider_max_inflight_default,
        provider_max_inflight_map=_parse_budget_json_map(budget_provider_max_inflight_json, value_type="int", min_v=1, max_v=10),
        provider_min_gap_s_default=budget_provider_min_gap_default,
        provider_min_gap_s_map=_parse_budget_json_map(budget_provider_min_gap_json, value_type="float", min_v=0, max_v=3600),
        provider_cooldown_s_default=budget_provider_cooldown_default,
        provider_cooldown_s_map=_parse_budget_json_map(budget_provider_cooldown_json, value_type="float", min_v=0, max_v=3600),
        sender_max_inflight=budget_sender_max_inflight,
        apply_to_retry=budget_apply_to_retry,
        apply_to_probe=budget_apply_to_probe,
        export=budget_export,
    )
    budget_mgr = BudgetManager(budget_config, lane_registry=lane_registry, debug=budget_debug, provider_key_resolver=provider_canon.lane_provider_key if provider_canon.enforce else None) if budget_manager_enabled else None

    learning_provider_workers_override = _parse_budget_json_map(learning_max_lanes_provider_json, value_type="int", min_v=1, max_v=10)
    learning_provider_delay_override = _parse_budget_json_map(learning_delay_floor_json, value_type="float", min_v=0.2, max_v=3.0)
    learning_provider_chunk_override = _parse_budget_json_map(learning_chunk_cap_json, value_type="int", min_v=50, max_v=1000)
    learning_caps_engine = LearningCapsEngine(
        db_getter=_db_conn,
        refresh_s=learning_refresh_s,
        min_samples=learning_min_samples,
        recency_days=learning_recency_days,
        debug=(lane_debug_enabled or budget_debug),
    ) if learning_caps_enabled else None

    provider_cooldown_until: Dict[str, float] = {}
    lock_wave = threading.Lock()

    def _lane_key(sender_idx: int, provider_domain: str) -> Tuple[int, str]:
        return (int(sender_idx or 0), str(provider_domain or "").strip().lower())

    def _lane_signature_from_detail(detail: str) -> Tuple[str, str]:
        txt = str(detail or "").strip()
        low = txt.lower()
        m = re.search(r"\b([245]\d\d)\b", txt)
        code = m.group(1) if m else ""
        if "timeout" in low or "timed out" in low:
            return "timeout", f"timeout:{txt[:120]}"
        if code.startswith("4") or any(x in low for x in ("defer", "temporary", "transient", "4.7", " 421", " 450", " 451", " 452")):
            return "4xx", (f"4xx:{code} " if code else "4xx:") + txt[:110]
        if code.startswith("5") or any(x in low for x in ("permanent", "reject", "denied", "blocked", "user unknown", "invalid recipient")):
            return "5xx", (f"5xx:{code} " if code else "5xx:") + txt[:110]
        return "5xx", f"err:{txt[:120]}"

    def _lane_chunk_result_from_recent(recent_slice: List[dict], chunk_len: int) -> dict:
        accepted = 0
        timeouts = 0
        deferrals = 0
        hardfails = 0
        signatures: List[str] = []
        for rr in (recent_slice or []):
            if bool(rr.get("ok")):
                accepted += 1
                continue
            klass, sig = _lane_signature_from_detail(str(rr.get("detail") or ""))
            if klass == "timeout":
                timeouts += 1
            elif klass == "4xx":
                deferrals += 1
            else:
                hardfails += 1
            if sig:
                signatures.append(sig)
        attempts_total = accepted + timeouts + deferrals + hardfails
        if attempts_total <= 0:
            attempts_total = max(0, int(chunk_len or 0))
        sent_attempts = max(0, int(chunk_len or attempts_total))
        return {
            "attempts_total": int(attempts_total),
            "sent_attempts": int(sent_attempts),
            "accepted_2xx": int(accepted),
            "deferrals_4xx": int(deferrals),
            "hardfails_5xx": int(hardfails),
            "timeouts_conn": int(timeouts),
            "error_signatures": signatures[:5],
        }

    def _lane_registry_update(now_ts: float, lane_key: Tuple[int, str], base_caps_hint: Optional[dict] = None) -> None:
        if not (lane_registry and lane_metrics):
            return
        prev_info = lane_registry.get_lane_info(lane_key)
        lane_id = f"{int(lane_key[0] or 0)}|{str(lane_key[1] or '').strip().lower()}"
        lane_snap = ((lane_metrics.snapshot().get("lanes") or {}).get(lane_id) if lane_metrics else None) or {}
        lane_registry.update_from_metrics(now_ts, lane_key, lane_snap, base_caps_hint=base_caps_hint)
        next_info = lane_registry.get_lane_info(lane_key)
        prev_state = str((prev_info or {}).get("state") or "HEALTHY")
        next_state = str((next_info or {}).get("state") or "HEALTHY")
        provider_domain = str(lane_key[1] or "").strip().lower()
        if provider_domain and (next_state != prev_state) and next_state in {"QUARANTINED", "INFRA_FAIL"}:
            provider_cooldown_until[provider_domain] = max(
                float(provider_cooldown_until.get(provider_domain) or 0.0),
                float(now_ts or time.time()) + float(provider_cooldown_s),
            )
            if budget_mgr:
                budget_mgr.on_lane_state_signal(lane_key, next_state, now_ts)

    def _lane_weight_multiplier(lane_key: Tuple[int, str]) -> float:
        if not soft_provider_budgets_enabled:
            return 1.0
        if not provider_state_bias_enabled:
            return 1.0
        if not lane_registry:
            return 1.0
        lane_info = lane_registry.get_lane_info(lane_key)
        lane_state = str(lane_info.get("state") or "HEALTHY")
        if lane_state == "THROTTLED":
            mul = provider_bias_throttled
        elif lane_state == "QUARANTINED":
            mul = provider_bias_quarantined
        elif lane_state == "INFRA_FAIL":
            mul = provider_bias_infra
        else:
            mul = 1.0
        return min(1.0, max(0.01, float(mul)))

    def _is_lane_temporarily_blocked(lane_key: Tuple[int, str], now_ts: float) -> bool:
        if not soft_provider_budgets_enabled:
            return False
        provider_domain = str(lane_key[1] or "").strip().lower()
        if not provider_domain:
            return False
        cooldown_until = float(provider_cooldown_until.get(provider_domain) or 0.0)
        if now_ts < cooldown_until:
            if lane_debug_enabled or soft_provider_budget_debug:
                with JOBS_LOCK:
                    job.log("INFO", f"SoftBudget: skipped provider {provider_domain} due to cooldown until {int(cooldown_until)}")
            return True
        if provider_quarantine_respect and lane_registry:
            lane_info = lane_registry.get_lane_info(lane_key)
            lane_state = str(lane_info.get("state") or "HEALTHY")
            next_allowed_ts = float(lane_info.get("next_allowed_ts") or 0.0)
            if lane_state in {"QUARANTINED", "INFRA_FAIL"} and now_ts < next_allowed_ts:
                if lane_debug_enabled or soft_provider_budget_debug:
                    with JOBS_LOCK:
                        job.log("INFO", f"SoftBudget: skipped lane {lane_key[0]}|{provider_domain} state={lane_state} next_allowed_ts={int(next_allowed_ts)}")
                return True
        return False

    def _refresh_learning_policy(now_ts: float) -> None:
        if not learning_caps_engine:
            return
        providers_scope = sorted({str(k[1] or "").strip().lower() for k in (provider_retry_chunks or {}).keys() if isinstance(k, tuple) and str(k[1] or "").strip()})
        providers_scope.extend([str(x or "").strip().lower() for x in (job.current_chunk_domains or {}).keys() if str(x or "").strip()])
        providers_scope = sorted(set([p for p in providers_scope if p]))
        if not providers_scope:
            providers_scope = sorted({str(_extract_domain_from_recipient(r) or "").strip().lower() for r in (recipients or []) if _extract_domain_from_recipient(r)})
        learning_caps_engine.refresh_if_needed(now_ts, job, sender_emails, providers_scope)
        if learning_export:
            with JOBS_LOCK:
                job.debug_learning_policy = {
                    **learning_caps_engine.snapshot(),
                    "enforce": bool(learning_caps_enforce),
                }

    def _learning_caps_for_lane(lane_key: Tuple[int, str], sender_email: str) -> dict:
        if not learning_caps_engine:
            return {}
        sender_domain = _extract_domain_from_email(sender_email)
        provider_domain = str((lane_key or (0, ""))[1] or "").strip().lower()
        if not sender_domain or not provider_domain:
            return {}
        lane_policy = learning_caps_engine.get_lane_policy(f"{sender_domain}|{provider_domain}")
        provider_policy = learning_caps_engine.get_provider_policy(provider_domain)
        out: Dict[str, Any] = {}
        if lane_policy and lane_policy.chunk_cap is not None:
            out["chunk_size_cap"] = int(lane_policy.chunk_cap)
        if lane_policy and lane_policy.workers_cap is not None:
            out["workers_cap"] = int(lane_policy.workers_cap)
        if lane_policy and lane_policy.delay_floor_s is not None:
            out["delay_floor"] = float(lane_policy.delay_floor_s)
        if provider_policy and provider_policy.chunk_cap_suggested is not None:
            out["chunk_size_cap"] = min(int(out.get("chunk_size_cap") or provider_policy.chunk_cap_suggested), int(provider_policy.chunk_cap_suggested))
        if provider_policy and provider_policy.workers_cap_suggested is not None:
            out["workers_cap"] = min(int(out.get("workers_cap") or provider_policy.workers_cap_suggested), int(provider_policy.workers_cap_suggested))
        if provider_policy and provider_policy.delay_floor_s_suggested is not None:
            out["delay_floor"] = max(float(out.get("delay_floor") or 0.0), float(provider_policy.delay_floor_s_suggested))
        if provider_domain in learning_provider_chunk_override:
            out["chunk_size_cap"] = int(learning_provider_chunk_override.get(provider_domain))
        if provider_domain in learning_provider_workers_override:
            out["workers_cap"] = int(learning_provider_workers_override.get(provider_domain))
        if provider_domain in learning_provider_delay_override:
            out["delay_floor"] = float(learning_provider_delay_override.get(provider_domain))
        if lane_registry:
            lane_registry.set_learning_caps(lane_key, out)
        return out

    def _budget_can_start(lane_key: Tuple[int, str], now_ts: float, is_retry: bool, is_probe: bool, planned_chunk_size_hint: Optional[int] = None) -> Tuple[bool, str]:
        if not budget_mgr:
            return True, "disabled"
        allowed, reason = budget_mgr.can_start(lane_key, now_ts, is_retry, is_probe, planned_chunk_size_hint=planned_chunk_size_hint)
        if not allowed and shadow_mode_active and shadow_recorder:
            shadow_recorder.record("budget_denial", {
                "lane": f"{lane_key[0]}|{lane_key[1]}",
                "reason": str(reason or "denied"),
                "is_retry": bool(is_retry),
                "is_probe": bool(is_probe),
            })
        if (not allowed) and (lane_debug_enabled or budget_debug or single_domain_waves_debug or provider_canon_debug):
            lane_group = provider_canon.group_for_domain(str((lane_key or (0, ""))[1] or "")) if provider_canon.enabled else ""
            extra = f" group={lane_group}" if provider_canon.enabled else ""
            with JOBS_LOCK:
                job.log("INFO", f"BudgetManager: denied lane {lane_key[0]}|{lane_key[1]}{extra} reason={reason}")
        return allowed, reason

    def _provider_metrics_snapshot(provider_domain: str) -> dict:
        provider = str(provider_domain or "").strip().lower()
        totals = {
            "attempts_total": 0,
            "deferrals_4xx": 0,
            "hardfails_5xx": 0,
            "timeouts_conn": 0,
            "deferral_rate": 0.0,
            "hardfail_rate": 0.0,
            "timeout_rate": 0.0,
        }
        if not lane_metrics or not provider:
            return totals
        snap = lane_metrics.snapshot()
        lanes = (snap.get("lanes") if isinstance(snap, dict) else {}) or {}
        for lane in lanes.values():
            lane_provider_raw = str((lane or {}).get("provider_domain") or "").strip().lower()
            lane_provider_cmp = provider_canon.group_for_domain(lane_provider_raw) if provider_canon.enforce else lane_provider_raw
            if lane_provider_cmp != provider:
                continue
            totals["attempts_total"] += int((lane or {}).get("attempts_total") or 0)
            totals["deferrals_4xx"] += int((lane or {}).get("deferrals_4xx") or 0)
            totals["hardfails_5xx"] += int((lane or {}).get("hardfails_5xx") or 0)
            totals["timeouts_conn"] += int((lane or {}).get("timeouts_conn") or 0)
        attempts = max(1, int(totals["attempts_total"] or 0))
        totals["deferral_rate"] = float(totals["deferrals_4xx"] / attempts)
        totals["hardfail_rate"] = float(totals["hardfails_5xx"] / attempts)
        totals["timeout_rate"] = float(totals["timeouts_conn"] / attempts)
        return totals

    def _lane_metrics_export_snapshot() -> None:
        if lane_metrics and lane_metrics_export:
            snap = lane_metrics.snapshot()
            with JOBS_LOCK:
                job.debug_lane_metrics_snapshot = snap
        if lane_registry and lane_state_export:
            with JOBS_LOCK:
                job.debug_lane_states_snapshot = lane_registry.snapshot()
        if budget_mgr and budget_config.export:
            with JOBS_LOCK:
                job.debug_budget_status = budget_mgr.snapshot()
        if wave_controller.enabled and single_domain_waves_export:
            with JOBS_LOCK:
                job.debug_wave_status = wave_controller.snapshot()

    def _tick_accounting_recon(now_ts: float) -> None:
        nonlocal last_accounting_recon_ts
        if not accounting_recon_engine:
            return
        if (float(now_ts) - float(last_accounting_recon_ts)) < float(lane_accounting_recon_interval_s):
            return
        try:
            delta = accounting_recon_engine.poll_and_update(job, now_ts)
            if lane_accounting_recon_export:
                with JOBS_LOCK:
                    job.debug_lane_accounting = accounting_recon_engine.snapshot()
            if lane_accounting_recon_debug and any(int(delta.get(k) or 0) > 0 for k in ("delivered", "bounced", "deferred", "complained")):
                with JOBS_LOCK:
                    job.log("INFO", f"Accounting recon delta: {delta}")
        except Exception as e:
            if lane_accounting_recon_debug:
                with JOBS_LOCK:
                    job.log("WARN", f"Accounting recon failed: {e}")
        finally:
            last_accounting_recon_ts = float(now_ts)

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

    def _safe_int(value: Any, default: int = 0) -> int:
        """Best-effort int parser that tolerates list-like form payloads."""
        try:
            if isinstance(value, (list, tuple)):
                if not value:
                    return int(default)
                value = value[0]
            return int(str(value).strip())
        except Exception:
            try:
                return int(default)
            except Exception:
                return 0

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

        out: Dict[str, Any] = {}

        out["chunk_size"] = max(1, min(50000, as_int("chunk_size", chunk_size)))
        out["thread_workers"] = max(1, min(200, as_int("thread_workers", thread_workers)))
        out["sleep_chunks"] = max(0.0, min(120.0, as_float("sleep_chunks", sleep_chunks)))
        out["delay_s"] = max(0.0, min(10.0, as_float("delay_s", delay_s)))

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
        out["policy_pack_name"] = str(form.get("policy_pack_name") or "").strip().lower()

        return out

    def _blacklist_check(from_email: str) -> Tuple[bool, str]:
        if SHIVA_DISABLE_BLACKLIST:
            _log_blacklist_disabled_once()
            return False, ""

        parts: List[str] = []
        listed = False

        dom = _extract_domain_from_email(from_email)
        if dom:
            dl = check_domain_dnsbl(dom)
            if dl:
                listed = True
                zones = ",".join(x.get("zone", "") for x in dl if x.get("zone"))
                parts.append(f"domain:{dom}=>{zones or 'listed'}")

        for ip in smtp_host_ips:
            hits = check_ip_dnsbl(ip)
            if hits:
                listed = True
                zones = ",".join(x.get("zone", "") for x in hits if x.get("zone"))
                parts.append(f"ip:{ip}=>{zones or 'listed'}")

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

    def _cyclic_pick(items: List[str], idx: int) -> str:
        seq = [str(x).strip() for x in (items or []) if str(x).strip()]
        if not seq:
            return ""
        return seq[int(idx or 0) % len(seq)]

    def _render_with_placeholders(base_text: str, *, url_value: str, src_value: str, rcpt: str) -> str:
        rendered = str(base_text or "")
        rendered = re.sub(r"\[(?:URL)\]", str(url_value or ""), rendered, flags=re.IGNORECASE)
        rendered = re.sub(r"\[(?:SRC)\]", str(src_value or ""), rendered, flags=re.IGNORECASE)
        rendered = re.sub(r"\[(?:MAIL|EMAIL)\]", str(rcpt or ""), rendered, flags=re.IGNORECASE)
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
        chunk_url: str,
        chunk_src: str,
    ):
        def worker_send(worker_idx: int, rcpts: List[str]):
            if not rcpts:
                return

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
                    subject_rendered = _render_with_placeholders(subject, url_value=chunk_url, src_value=chunk_src, rcpt=rcpt)
                    msg["Subject"] = subject_rendered
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

                    rendered_body = _render_with_placeholders(body_used, url_value=chunk_url, src_value=chunk_src, rcpt=rcpt)

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
                            job.record_internal_error("send_failed", str(e), email=rcpt)
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
                    job.record_internal_error("exception", f"Worker error (chunk={chunk_idx} w={worker_idx}): {e}")
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

        # Two-level partitioning (sender -> recipient_domain -> recipients).
        partition_seed = str(job.campaign_id or job.id or job_id)
        _split_csv = lambda raw: [x.strip() for x in str(raw or "").split(",") if x.strip()]
        rollout_decider = RolloutDecider(
            mode=rollout_mode,
            canary_percent=canary_percent,
            allowlists={
                "campaigns": set(_split_csv(canary_allowlist_campaigns_raw)),
                "senders": set(_split_csv(canary_allowlist_senders_raw)),
            },
            denylists={"campaigns": set(_split_csv(canary_denylist_campaigns_raw))},
            seed_mode=canary_seed_mode,
            debug=canary_debug,
        )
        rollout = rollout_decider.decide(job, sender_emails=sender_emails, force_legacy=force_legacy)
        sender_domain_buckets, partition_stats = normalize_and_partition_recipients(
            recipients=recipients,
            sender_emails=sender_emails,
            seed=partition_seed,
        )
        sender_idx_map = {em: i for i, em in enumerate(sender_emails)}
        sender_bucket_by_idx: Dict[int, Dict[str, List[str]]] = {
            sender_idx_map[s]: {d: list(v) for d, v in (domains or {}).items()}
            for s, domains in sender_domain_buckets.items()
            if s in sender_idx_map
        }
        sender_cursor = 0
        sender_idx_by_rcpt: Dict[str, int] = {}
        for _sidx, _domains in sender_bucket_by_idx.items():
            for _rcpts in (_domains or {}).values():
                for _rcpt in (_rcpts or []):
                    rr = str(_rcpt or "").strip().lower()
                    if rr:
                        sender_idx_by_rcpt[rr] = int(_sidx)
        scheduler_rng = random.Random(int(hashlib.sha256(partition_seed.encode("utf-8", errors="ignore")).hexdigest()[:16], 16))
        provider_retry_chunks: Dict[str, List[dict]] = {}
        provider_buckets = build_provider_buckets([
            rcpt
            for domains in sender_bucket_by_idx.values()
            for bucket in (domains or {}).values()
            for rcpt in (bucket or [])
        ])[0]
        provider_counts = {str(d or "").strip().lower(): int(len(v or [])) for d, v in (provider_buckets or {}).items() if str(d or "").strip()}
        provider_canon.ingest_provider_counts(provider_counts, mx_by_domain={})
        rollout_effective_mode = str(rollout.get("effective_mode") or "legacy")
        lane_v2_rollout_enabled = bool(rollout_effective_mode == "v2")
        shadow_mode_active = bool(rollout_effective_mode == "shadow")
        provider_groups_for_plan = {
            provider_canon.group_for_domain(dom) for dom in (provider_counts or {}).keys() if str(dom or "").strip()
        }
        mode_plan = ModeOrchestrator().decide_effective_features(
            job,
            {
                "force_legacy": force_legacy,
                "force_disable_concurrency": force_disable_concurrency,
                "lane_concurrency_enabled": lane_concurrency_enabled,
                "probe_mode_enabled": probe_mode_enabled,
                "single_domain_waves_enabled": single_domain_waves_enabled,
                "provider_canon_enabled": provider_canon_enabled,
                "provider_canon_enforce": provider_canon_enforce,
                "policy_packs_enabled": policy_packs_enabled,
                "policy_packs_enforce": policy_packs_enforce,
                "learning_caps_enabled": learning_caps_enabled,
                "learning_caps_enforce": learning_caps_enforce,
                "backoff_jitter_mode": SHIVA_BACKOFF_JITTER,
                "fallback_controller_enabled": fallback_controller_enabled,
                "fallback_controller_enabled_explicit": get_env_bool("SHIVA_FALLBACK_CONTROLLER", False),
                "resource_governor_enabled": resource_governor_enabled,
                "resource_governor_enabled_explicit": get_env_bool("SHIVA_RESOURCE_GOVERNOR", False),
                "lane_accounting_recon_enabled": lane_accounting_recon_enabled,
                "ui_telemetry_enabled": bool(lane_metrics_export or lane_state_export or lane_v2_export),
                "provider_domains_count": len(set(provider_counts.keys())),
                "provider_groups_count": len(provider_groups_for_plan),
                "pmta_pressure_level": int((job.pmta_pressure or {}).get("level") or 0),
                "fallback_active": False,
            },
            rollout,
        )
        if guardrails_enabled:
            guard_config_snapshot = {
                "lane_max_parallel": int(lane_max_parallel),
                "max_total_workers": int(max_total_workers),
                "caps_max_workers": int(_env_int("SHIVA_CAPS_MAX_WORKERS", 50)),
                "caps_max_chunk": int(_env_int("SHIVA_CAPS_MAX_CHUNK", 2000)),
                "caps_max_delay_s": float(_env_float("SHIVA_CAPS_MAX_DELAY_S", 5.0)),
                "provider_min_gap_s": float(budget_provider_min_gap_default),
                "provider_cooldown_s": int(provider_cooldown_s),
                "wave_max_parallel_single_domain": int(wave_max_parallel_single_domain),
                "wave_burst_tokens": int(wave_burst_tokens),
                "wave_refill_per_sec": float(wave_refill_per_sec),
                "backoff_jitter_mode": str(SHIVA_BACKOFF_JITTER),
                "backoff_jitter_pct": float(SHIVA_BACKOFF_JITTER_PCT),
                "rollout_effective_mode": str(rollout_effective_mode),
                "fallback_controller_enabled_requested": bool(get_env_bool("SHIVA_FALLBACK_CONTROLLER", False)),
                "resource_governor_enabled_requested": bool(get_env_bool("SHIVA_RESOURCE_GOVERNOR", False)),
                "guardrails_export": bool(guardrails_export),
            }
            guard_result = GuardrailsValidator(guard_limits, strict=guardrails_strict, debug=guardrails_debug).validate_plan(mode_plan, guard_config_snapshot)
            if guardrails_export:
                with JOBS_LOCK:
                    job.debug_guardrails = {
                        "ok": bool(guard_result.ok),
                        "critical_issues": list(guard_result.critical_issues or []),
                        "warnings": list(guard_result.warnings or []),
                        "clamps_applied": list(guard_result.clamps_applied or []),
                    }
            if guard_result.critical_issues and guardrails_strict:
                with JOBS_LOCK:
                    for issue in guard_result.critical_issues:
                        job.log("ERROR", f"Guardrails(strict): {issue}")
                    job.status = "error"
                    job.last_error = "Guardrails strict validation failed; job aborted safely before sending"
                return
            for warn_msg in (guard_result.warnings or []):
                with JOBS_LOCK:
                    job.log("WARN", f"Guardrails: {warn_msg}")
            for clamp in (guard_result.clamps_applied or []):
                field_name = str(clamp.get("field") or "")
                after_v = clamp.get("after")
                if field_name == "lane_max_parallel":
                    lane_max_parallel = int(after_v)
                elif field_name == "max_total_workers":
                    max_total_workers = int(after_v)
                elif field_name == "caps_max_workers":
                    guard_caps_bounds_override["max_workers"] = int(after_v)
                elif field_name == "caps_max_chunk":
                    guard_caps_bounds_override["max_chunk"] = int(after_v)
                elif field_name == "caps_max_delay_s":
                    guard_caps_bounds_override["max_delay_s"] = float(after_v)
                elif field_name == "provider_min_gap_s":
                    budget_provider_min_gap_default = float(after_v)
                elif field_name == "provider_cooldown_s":
                    provider_cooldown_s = int(after_v)
                elif field_name == "wave_max_parallel_single_domain":
                    wave_max_parallel_single_domain = int(after_v)
                elif field_name == "wave_burst_tokens":
                    wave_burst_tokens = int(after_v)
                elif field_name == "wave_refill_per_sec":
                    wave_refill_per_sec = float(after_v)
                elif field_name == "backoff_jitter_pct":
                    jitter_pct_runtime = float(after_v)
                elif field_name == "plan.fallback_controller_enabled":
                    mode_plan.fallback_controller_enabled = bool(after_v)
                elif field_name == "plan.resource_governor_enabled":
                    mode_plan.resource_governor_enabled = bool(after_v)
        scheduler_mode_runtime = str(mode_plan.scheduler_mode)
        lane_concurrency_runtime = bool(mode_plan.concurrency_enabled)
        probe_mode_enabled = bool(mode_plan.probe_enabled)
        single_domain_waves_enabled = bool(mode_plan.waves_enabled)
        provider_canon.enabled = bool(mode_plan.provider_canon_enabled)
        provider_canon.enforce = bool(mode_plan.provider_canon_enforced)
        policy_packs_enabled = bool(mode_plan.policy_pack_enabled)
        policy_packs_enforce = bool(mode_plan.policy_pack_enforced)
        learning_caps_enforce = bool(mode_plan.learning_caps_enforced)
        lane_accounting_recon_enabled = bool(mode_plan.accounting_recon_enabled)
        resource_governor_enabled = bool(mode_plan.resource_governor_enabled)
        fallback_controller_enabled = bool(mode_plan.fallback_controller_enabled)
        backoff_jitter_mode_runtime = str(mode_plan.backoff_jitter_mode or "off")
        lane_picker_v2 = LanePickerV2(
            scheduler_rng=scheduler_rng,
            lane_registry=lane_registry,
            budget_mgr=budget_mgr,
            debug=lane_v2_debug,
            export_debug=lane_v2_export,
            respect_lane_states=lane_v2_respect_lane_states,
            use_budgets=lane_v2_use_budgets,
            use_soft_bias=lane_v2_use_soft_bias,
            max_scan=lane_v2_max_scan,
            lane_weight_multiplier=_lane_weight_multiplier,
            debug_log=lambda msg: job.log("INFO", msg),
        ) if (lane_v2_rollout_enabled or shadow_mode_active or scheduler_mode == "lane_v2") else None
        shadow_recorder = ShadowRecorder(shadow_max_events) if shadow_mode_active else None
        lane_parallel_limit_runtime = min(int(lane_max_parallel), int(max_total_lanes)) if resource_governor_enabled else int(lane_max_parallel)
        resource_governor = GlobalResourceGovernor(
            max_total_workers=max_total_workers,
            debug=resource_governor_debug,
            pmta_scale_config={
                "enabled": bool(governor_pmta_scale),
                "level2_factor": float(governor_pmta_level2_factor),
                "level3_factor": float(governor_pmta_level3_factor),
            },
        ) if resource_governor_enabled else None
        if lane_concurrency_enabled and not lane_v2_rollout_enabled:
            with JOBS_LOCK:
                job.log("INFO", "Lane concurrency disabled for this job (rollout not in v2 mode).")
        policy_pack_caps_clamps: Dict[str, dict] = {}
        policy_pack_snapshot: dict = {}
        selected_pack: dict = {}
        policy_applier: Optional[PolicyPackApplier] = None
        pack_provider_keys: Set[str] = set()

        def _lane_budget_key(lane_key: Tuple[int, str]) -> Tuple[int, str]:
            return provider_canon.lane_provider_key(lane_key)

        if policy_packs_enabled:
            form_policy = db_get_campaign_form_raw(job.campaign_id) if job.campaign_id else {}
            requested_pack = str((form_policy.get("policy_pack_name") if isinstance(form_policy, dict) else "") or policy_pack_name_default or "default").strip().lower() or "default"
            packs = PolicyPackLoader.load(policy_packs_json, requested_pack)
            selected_pack = dict(packs.get(requested_pack) or packs.get(policy_pack_name_default) or packs.get("default") or {})
            policy_applier = PolicyPackApplier(selected_pack, enforce=policy_packs_enforce)
            for provider_domain in provider_counts.keys():
                dom = str(provider_domain or "").strip().lower()
                if not dom:
                    continue
                if provider_canon.enforce:
                    pack_provider_keys.add(provider_canon.group_for_domain(dom))
                else:
                    pack_provider_keys.add(dom)
                    grp = provider_canon.group_for_domain(dom)
                    if grp:
                        pack_provider_keys.add(grp)
            pack_provider_keys.add("other")
            recommendations = policy_applier.compute_recommendations({"provider_keys": sorted(pack_provider_keys)})
            applied_overrides = policy_applier.apply_job_local_overrides({
                "provider_keys": sorted(pack_provider_keys),
                "budget_config": budget_config,
                "policy_pack_caps_clamps": policy_pack_caps_clamps,
                "resource_governor": resource_governor,
            }) if policy_packs_enforce else {}
            policy_pack_snapshot = {
                "pack_name": requested_pack,
                "enforce": bool(policy_packs_enforce),
                "provider_defaults": dict(recommendations.get("provider_defaults") or {}),
                "applied_overrides": dict(applied_overrides or {}),
                "notes": [
                    "recommendation_only" if not policy_packs_enforce else "enforce_clamp_only",
                    "job_local_only",
                    "no_env_mutation",
                ],
            }
            if policy_packs_debug:
                with JOBS_LOCK:
                    job.log("INFO", f"PolicyPack: name={requested_pack} enforce={int(policy_packs_enforce)} providers={','.join(sorted(pack_provider_keys))}")
            if policy_packs_export:
                with JOBS_LOCK:
                    job.debug_policy_pack = dict(policy_pack_snapshot)

        if provider_canon.enabled and provider_canon.export:
            with JOBS_LOCK:
                job.debug_provider_canon = provider_canon.snapshot()

        accounting_recon_engine = AccountingReconEngine(
            job_id=job.id,
            lane_metrics=lane_metrics,
            lane_registry=lane_registry,
            provider_canon=provider_canon,
            sender_idx_by_rcpt=sender_idx_by_rcpt,
            lock=JOBS_LOCK,
            debug=lane_accounting_recon_debug,
            export=lane_accounting_recon_export,
        ) if lane_accounting_recon_enabled else None
        last_accounting_recon_ts = 0.0

        probe_controller = ProbeController(
            enabled=probe_mode_enabled,
            duration_s=probe_duration_s,
            rounds=probe_rounds,
            probe_caps={
                "chunk_size": probe_chunk_size,
                "workers": probe_workers,
                "delay_floor_s": probe_delay_floor_s,
                "sleep_floor_s": probe_sleep_floor_s,
            },
            min_providers=probe_min_providers,
        )
        probe_provider_domains = [
            (provider_canon.group_for_domain(d) if provider_canon.enforce else str(d or "").strip().lower())
            for d, cnt in (provider_counts or {}).items()
            if str(d or "").strip() and int(cnt or 0) > 0
        ]
        provider_domain_count = len(set(probe_provider_domains))
        single_provider_domain = str(probe_provider_domains[0] or "").strip().lower() if provider_domain_count == 1 else ""
        wave_mode_active = bool(single_domain_waves_enabled)
        if single_domain_only_if_providers_eq:
            wave_mode_active = bool(wave_mode_active and provider_domain_count == 1)
        wave_controller = WaveController(
            enabled=wave_mode_active,
            provider_domain=single_provider_domain,
            burst_tokens=wave_burst_tokens,
            refill_per_sec=wave_refill_per_sec,
            min_tokens_to_start_chunk=wave_min_tokens_to_start_chunk,
            adaptive_config={
                "enabled": wave_adaptive_enabled,
                "token_cost_per_msg": wave_token_cost_per_msg,
                "deferral_up": wave_deferral_up,
                "deferral_down": wave_deferral_down,
                "hardfail_down": wave_hardfail_down,
                "ramp_up_factor": wave_ramp_up_factor,
                "ramp_down_factor": wave_ramp_down_factor,
                "min_refill": wave_min_refill,
                "max_refill": wave_max_refill,
                "min_burst": wave_min_burst,
                "max_burst": wave_max_burst,
            },
            stagger_config={
                "enabled": wave_stagger_enabled,
                "step_s": wave_stagger_step_s,
                "seed_mode": wave_stagger_seed_mode,
            },
        )
        wave_controller.start(job_start_ts=time.time(), num_senders=len(sender_emails), partition_seed=partition_seed)
        if learning_caps_engine and wave_controller.enabled and single_provider_domain:
            learning_caps_engine.refresh_if_needed(time.time(), job, sender_emails, [single_provider_domain])
            if learning_caps_enforce:
                provider_policy = learning_caps_engine.get_provider_policy(single_provider_domain)
                if provider_policy and provider_policy.chunk_cap_suggested is not None:
                    wave_controller.burst_tokens = min(float(wave_controller.burst_tokens), float(max(50, provider_policy.chunk_cap_suggested)))
                    wave_controller.tokens_current = min(float(wave_controller.tokens_current), float(wave_controller.burst_tokens))
                if provider_policy and provider_policy.workers_cap_suggested is not None:
                    wave_controller.refill_per_sec = min(float(wave_controller.refill_per_sec), float(max(0.1, provider_policy.workers_cap_suggested)))
        if wave_controller.enabled and probe_controller.is_active(time.time()):
            probe_controller.stop()
        probe_controller.start(
            job_start_ts=time.time(),
            provider_domains=probe_provider_domains,
            num_senders=len(sender_emails),
        )
        if wave_controller.enabled and probe_controller.is_active(time.time()):
            probe_controller.stop()
        if budget_mgr and wave_controller.enabled and single_provider_domain:
            budget_mgr.set_provider_max_inflight_override(single_provider_domain, wave_max_parallel_single_domain)
            budget_mgr.register_external_gate(
                "single_domain_wave",
                lambda lane_key, now_ts, _is_retry, _is_probe, planned_chunk_size_hint: wave_controller.can_start_lane(
                    _lane_budget_key(lane_key),
                    now_ts,
                    int(planned_chunk_size_hint or wave_min_tokens_to_start_chunk),
                ),
            )
        if probe_export:
            with JOBS_LOCK:
                job.debug_probe_status = probe_controller.snapshot()
        if single_domain_waves_export:
            with JOBS_LOCK:
                job.debug_wave_status = wave_controller.snapshot()

        fallback_exception_count = 0
        fallback_controller_runtime = bool(fallback_controller_enabled)
        fallback_thresholds = {
            "deferral_rate": fallback_deferral_rate,
            "hardfail_rate": fallback_hardfail_rate,
            "timeout_rate": fallback_timeout_rate,
            "blocked_per_min": fallback_blocked_per_min,
            "pmta_pressure_level": fallback_pmta_pressure_level,
            "exceptions_per_min": 3.0,
        }
        if policy_packs_enabled and policy_packs_enforce and policy_applier:
            _pp_applied_late = policy_applier.apply_job_local_overrides({
                "provider_keys": sorted(pack_provider_keys),
                "wave_controller": wave_controller,
                "resource_governor": resource_governor,
                "fallback_thresholds": fallback_thresholds,
            })
            if isinstance(policy_pack_snapshot, dict):
                merged = dict(policy_pack_snapshot.get("applied_overrides") or {})
                for k, v in (_pp_applied_late or {}).items():
                    if isinstance(v, dict):
                        merged.setdefault(k, {}).update(v)
                    else:
                        merged[k] = v
                policy_pack_snapshot["applied_overrides"] = merged
                if policy_packs_export:
                    with JOBS_LOCK:
                        job.debug_policy_pack = dict(policy_pack_snapshot)
        fallback_controller = FallbackController(
            thresholds=fallback_thresholds,
            window_s=fallback_window_s,
            debug=fallback_debug,
            disable_reenable=fallback_disable_reenable,
            min_active_s=fallback_min_active_s,
            recovery_s=fallback_recovery_s,
            actions_config={
                "step1_disable_concurrency": fallback_step1_disable_concurrency,
                "step2_disable_probe": fallback_step2_disable_probe,
                "step3_switch_to_legacy": fallback_step3_switch_to_legacy,
            },
        ) if fallback_controller_runtime else None

        with JOBS_LOCK:
            job.debug_rollout = {
                "rollout_mode": str(rollout.get("rollout_mode") or rollout_mode),
                "effective_mode": str(rollout_effective_mode),
                "reasons": list(rollout.get("reasons") or []),
                "is_canary": bool(rollout.get("is_canary")),
                "is_shadow": bool(shadow_mode_active),
                "force_legacy": bool(force_legacy),
                "force_disable_concurrency": bool(force_disable_concurrency),
            }
            if mode_plan.ui_telemetry_enabled:
                job.debug_effective_plan = asdict(mode_plan)

        def _switch_scheduler_legacy() -> None:
            nonlocal scheduler_mode_runtime
            if scheduler_mode_runtime != "legacy":
                scheduler_mode_runtime = "legacy"
                with JOBS_LOCK:
                    job.log("WARN", "Fallback controller: scheduler switched to legacy mode for this job")

        def _disable_concurrency_runtime() -> None:
            nonlocal lane_concurrency_runtime
            if lane_concurrency_runtime:
                lane_concurrency_runtime = False
                lane_parallel_limit_runtime = 1
                with JOBS_LOCK:
                    job.log("WARN", "Fallback controller: lane concurrency disabled for this job")

        def _disable_probe_runtime() -> None:
            if probe_controller.is_active(time.time()):
                probe_controller.stop()
                with JOBS_LOCK:
                    job.log("WARN", "Fallback controller: probe mode disabled for this job")

        def _fallback_global_metrics_snapshot(executor_snapshot: Optional[dict] = None) -> dict:
            out = {
                "attempts_total": 0,
                "deferrals_4xx": 0,
                "hardfails_5xx": 0,
                "timeouts_conn": 0,
                "blocked_events": 0,
                "exceptions_count": int(fallback_exception_count),
                "quarantine_count": 0,
                "inflight_count": 0,
            }
            if lane_metrics:
                ms = lane_metrics.snapshot()
                acct_attempts = 0
                acct_def = 0
                acct_hard = 0
                for lane in (ms.get("lanes") if isinstance(ms, dict) else {}).values():
                    out["attempts_total"] += int(lane.get("attempts_total") or 0)
                    out["deferrals_4xx"] += int(lane.get("deferrals_4xx") or 0)
                    out["hardfails_5xx"] += int(lane.get("hardfails_5xx") or 0)
                    out["timeouts_conn"] += int(lane.get("timeouts_conn") or 0)
                    out["blocked_events"] += int(lane.get("blocked_events") or 0)
                    acct_attempts += int(lane.get("acct_total") or 0)
                    acct_def += int(lane.get("acct_deferred") or 0)
                    acct_hard += int(lane.get("acct_bounced") or 0) + int(lane.get("acct_complained") or 0)
                if acct_attempts > 0:
                    out["attempts_total"] = int(acct_attempts)
                    out["deferrals_4xx"] = int(acct_def)
                    out["hardfails_5xx"] = int(acct_hard)
            if lane_registry:
                rs = lane_registry.snapshot(time.time())
                lanes = (rs.get("lanes") if isinstance(rs, dict) else []) or []
                out["quarantine_count"] = sum(1 for x in lanes if str(x.get("state") or "") == "QUARANTINED")
            if isinstance(executor_snapshot, dict):
                out["inflight_count"] = int(executor_snapshot.get("inflight_count") or 0)
            return out

        with JOBS_LOCK:
            if scheduler_mode_runtime != "legacy":
                job.log("INFO", f"Scheduler mode={scheduler_mode_runtime} (rollout effective_mode={rollout_effective_mode}; sending pipeline remains legacy/sequential).")
            job.log(
                "INFO",
                "Recipient partition stats: "
                f"valid={partition_stats.get('valid_total', 0)} invalid={partition_stats.get('invalid_count', 0)} "
                f"deduplicated={partition_stats.get('deduplicated_count', 0)} totals_match={partition_stats.get('totals_match')} "
                f"domain_spread_ok={partition_stats.get('domain_spread_ok')}",
            )
            job.log("INFO", f"Per-sender totals: {partition_stats.get('sender_totals', {})}")
            job.log("INFO", f"Per-sender per-domain counts: {partition_stats.get('sender_domain_counts', {})}")
            if probe_controller.probe_active:
                job.log(
                    "INFO",
                    f"Probe mode enabled: providers={len(set(probe_provider_domains))} rounds={probe_rounds} duration_s={probe_duration_s}",
                )
            if wave_controller.enabled:
                job.log(
                    "INFO",
                    f"Single-domain wave mode enabled: provider={single_provider_domain} refill={wave_controller.refill_per_sec:.2f}/s burst={int(wave_controller.burst_tokens)} stagger_step_s={wave_stagger_step_s}",
                )

        def _remaining_total() -> int:
            queued = sum(sum(len(v) for v in domains.values()) for domains in sender_bucket_by_idx.values())
            queued += sum(sum(int(x.get("size") or len(x.get("chunk") or [])) for x in v) for v in provider_retry_chunks.values())
            return queued

        def _sd_key(sender_idx: int, domain: str) -> str:
            return f"{int(sender_idx)}|{str(domain)}"

        def _sender_has_ready_work(sender_idx: int, now_ts: float) -> bool:
            for domain in (sender_bucket_by_idx.get(sender_idx) or {}).keys():
                retries = provider_retry_chunks.get(_sd_key(sender_idx, domain)) or []
                if retries and float(retries[0].get("next_retry_ts") or 0.0) <= now_ts:
                    return True
                if (sender_bucket_by_idx.get(sender_idx) or {}).get(domain):
                    return True
            return False

        def _sender_has_pending_work(sender_idx: int) -> bool:
            for domain in (sender_bucket_by_idx.get(sender_idx) or {}).keys():
                retries = provider_retry_chunks.get(_sd_key(sender_idx, domain)) or []
                if retries:
                    return True
                if (sender_bucket_by_idx.get(sender_idx) or {}).get(domain):
                    return True
            return False

        def _domain_has_ready_work(sender_idx: int, domain: str, now_ts: float) -> bool:
            retries = provider_retry_chunks.get(_sd_key(sender_idx, domain)) or []
            if retries and float(retries[0].get("next_retry_ts") or 0.0) <= now_ts:
                return True
            return bool((sender_bucket_by_idx.get(sender_idx) or {}).get(domain))

        def _next_retry_wait(now_ts: float) -> Optional[float]:
            waits: List[float] = []
            for retries in provider_retry_chunks.values():
                if not retries:
                    continue
                next_ts = float(retries[0].get("next_retry_ts") or 0.0)
                waits.append(max(0.0, next_ts - now_ts))
            return min(waits) if waits else None

        def _pick_retry_ready_sender_domain(now_ts: float) -> Optional[Tuple[int, str]]:
            nonlocal sender_cursor
            n = len(sender_emails)
            if n <= 0:
                return None
            for step in range(n):
                sender_idx2 = (sender_cursor + step) % n
                if not _sender_has_pending_work(sender_idx2):
                    continue
                for dom2 in (sender_bucket_by_idx.get(sender_idx2) or {}).keys():
                    retry_q2 = provider_retry_chunks.get(_sd_key(sender_idx2, dom2)) or []
                    if retry_q2 and float(retry_q2[0].get("next_retry_ts") or 0.0) <= now_ts:
                        lane_key2 = _lane_key(sender_idx2, dom2)
                        if budget_mgr and budget_config.apply_to_retry:
                            allowed2, _reason2 = _budget_can_start(lane_key2, now_ts, True, False, planned_chunk_size_hint=cs)
                            if not allowed2:
                                continue
                        sender_cursor = (sender_idx2 + 1) % n
                        return sender_idx2, dom2
            return None

        def _pick_weighted_domain(sender_idx: int, now_ts: float) -> Optional[str]:
            domains = sender_bucket_by_idx.get(sender_idx) or {}
            if not soft_provider_budgets_enabled:
                weighted_legacy: List[Tuple[str, int]] = []
                for d, v in domains.items():
                    if not v:
                        continue
                    lane_key = _lane_key(sender_idx, d)
                    if budget_mgr:
                        allowed_legacy, _reason_legacy = _budget_can_start(lane_key, now_ts, False, False, planned_chunk_size_hint=cs)
                        if not allowed_legacy:
                            continue
                    weighted_legacy.append((d, len(v)))
                if not weighted_legacy:
                    return None
                total_weight_legacy = sum(w for _, w in weighted_legacy)
                if total_weight_legacy <= 0:
                    return None
                draw_legacy = scheduler_rng.randint(1, total_weight_legacy)
                acc_legacy = 0
                for dom2, w in weighted_legacy:
                    acc_legacy += w
                    if draw_legacy <= acc_legacy:
                        return dom2
                return weighted_legacy[-1][0]

            weighted: List[Tuple[str, float]] = []
            for d, v in domains.items():
                if not v:
                    continue
                lane_key = _lane_key(sender_idx, d)
                if budget_mgr:
                    allowed, _reason = _budget_can_start(lane_key, now_ts, False, False, planned_chunk_size_hint=cs)
                    if not allowed:
                        continue
                if _is_lane_temporarily_blocked(lane_key, now_ts):
                    continue
                lane_mul = _lane_weight_multiplier(lane_key)
                if (lane_debug_enabled or soft_provider_budget_debug) and lane_mul != 1.0:
                    with JOBS_LOCK:
                        job.log("INFO", f"SoftBudget: provider {d} weight multiplier={lane_mul:.2f}")
                adjusted_weight = max(0.01, float(len(v)) * lane_mul)
                weighted.append((d, adjusted_weight))
            if not weighted:
                return None
            total_weight = sum(w for _, w in weighted)
            if total_weight <= 0.0:
                return None
            draw = scheduler_rng.random() * total_weight
            acc = 0.0
            for dom2, w in weighted:
                acc += w
                if draw <= acc:
                    return dom2
            return weighted[-1][0]

        def _next_sender_domain(now_ts: float) -> Optional[Tuple[int, str]]:
            nonlocal sender_cursor
            n = len(sender_emails)
            if n <= 0:
                return None
            for step in range(n):
                sender_idx2 = (sender_cursor + step) % n
                if not _sender_has_pending_work(sender_idx2):
                    continue
                if not _sender_has_ready_work(sender_idx2, now_ts):
                    continue
                for dom2 in (sender_bucket_by_idx.get(sender_idx2) or {}).keys():
                    if _domain_has_ready_work(sender_idx2, dom2, now_ts):
                        retry_q2 = provider_retry_chunks.get(_sd_key(sender_idx2, dom2)) or []
                        if retry_q2 and float(retry_q2[0].get("next_retry_ts") or 0.0) <= now_ts:
                            lane_key2 = _lane_key(sender_idx2, dom2)
                            if budget_mgr and budget_config.apply_to_retry:
                                allowed2, _reason2 = _budget_can_start(lane_key2, now_ts, True, False, planned_chunk_size_hint=cs)
                                if not allowed2:
                                    continue
                            sender_cursor = (sender_idx2 + 1) % n
                            return sender_idx2, dom2
                dom_weighted = _pick_weighted_domain(sender_idx2, now_ts)
                if dom_weighted:
                    sender_cursor = (sender_idx2 + 1) % n
                    return sender_idx2, dom_weighted
            return None

        with JOBS_LOCK:
            # initial estimate
            cs0 = max(1, int(chunk_size or 1))
            job.chunks_total = (total + cs0 - 1) // cs0
            job.log("INFO", f"Prepared dynamic chunks (initial chunk_size={cs0}).")

        baseline_rt = _runtime_overrides()
        baseline_health = _accounting_health_policy(
            workers=_safe_int(baseline_rt.get("thread_workers", thread_workers), _safe_int(thread_workers, 1)),
            delay=float(baseline_rt.get("delay_s", delay_s)),
            chunk_sz=_safe_int(baseline_rt.get("chunk_size", chunk_size), _safe_int(chunk_size, 1)),
            sleep_between=float(baseline_rt.get("sleep_chunks", sleep_chunks)),
        )
        baseline_pressure = dict(job.pmta_pressure or {})
        baseline_live = dict(job.pmta_live or {})
        baseline_report = build_baseline_report(
            job=job,
            sender_buckets=sender_bucket_by_idx,
            provider_buckets=provider_buckets,
            partition_seed=partition_seed,
            overrides=baseline_rt,
            pmta_live=baseline_live,
            pressure_caps=baseline_pressure,
            health_caps=baseline_health,
            provider_retry_chunks=provider_retry_chunks,
        )
        baseline_report["invalid_count"] = _safe_int(partition_stats.get("invalid_count"), 0)
        baseline_report["deduped_count"] = _safe_int(partition_stats.get("deduplicated_count"), 0)

        if lane_baseline_enabled:
            with JOBS_LOCK:
                job.debug_baseline_report = dict(baseline_report)
                job.log("INFO", f"Lane baseline report: {json.dumps(baseline_report, ensure_ascii=False, sort_keys=True)}")

        used_legacy_selector = False
        if lane_debug_enabled:
            try:
                lane_debug_self_check(baseline_report)
                with JOBS_LOCK:
                    job.log("INFO", f"Lane debug self-check passed (partition_seed={partition_seed}).")
            except Exception as e:
                with JOBS_LOCK:
                    job.log("ERROR", f"Lane debug self-check fatal invariant: {e}")
                raise

        while _remaining_total() > 0:
            _tick_accounting_recon(time.time())
            if not _wait_ready():
                _stop_job("stop requested")
                return

            rt = _runtime_overrides()

            cs = _safe_int(rt.get("chunk_size", chunk_size), _safe_int(chunk_size, 1))
            workers2 = _safe_int(rt.get("thread_workers", thread_workers), _safe_int(thread_workers, 1))
            sleep2 = float(rt.get("sleep_chunks", sleep_chunks))
            delay2 = float(rt.get("delay_s", delay_s))
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
                    workers2 = _safe_int(ap.get("workers"), workers2)
                    cs = _safe_int(ap.get("chunk_size"), cs)
                    delay2 = float(ap.get("delay_s") if ap.get("delay_s") is not None else delay2)
                    sleep2 = float(ap.get("sleep_chunks") if ap.get("sleep_chunks") is not None else sleep2)

                    h_lvl = _safe_int(health_policy_applied.get("level"), 0)
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
                        lvl = _safe_int(pmta_pressure_applied.get("level"), 0)
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
                            if lvl >= 3 and probe_controller.is_active(time.time()):
                                probe_controller.stop()
                                with JOBS_LOCK:
                                    job.log("WARN", "Probe mode disabled early due to PMTA pressure level >= 3")

                except Exception:
                    pmta_pressure_applied = {}

            now_ts = time.time()
            _refresh_learning_policy(now_ts)
            if learning_caps_engine and budget_mgr:
                policy_snapshot = learning_caps_engine.snapshot().get("providers") or {}
                for provider_domain, provider_payload in policy_snapshot.items():
                    suggested_inflight = provider_payload.get("provider_max_inflight_suggested")
                    suggested_min_gap = provider_payload.get("provider_min_gap_s_suggested")
                    suggested_cooldown = provider_payload.get("provider_cooldown_s_suggested")
                    if learning_caps_enforce:
                        if isinstance(suggested_inflight, int):
                            baseline_inflight = budget_mgr.provider_max_inflight(provider_domain)
                            budget_mgr.set_provider_max_inflight_override(provider_domain, min(baseline_inflight, int(suggested_inflight)))
                        if isinstance(suggested_min_gap, (int, float)):
                            prev_gap = float(budget_config.provider_min_gap_s_map.get(provider_domain, budget_config.provider_min_gap_s_default))
                            budget_config.provider_min_gap_s_map[provider_domain] = max(prev_gap, float(suggested_min_gap))
                        if isinstance(suggested_cooldown, (int, float)):
                            prev_cd = float(budget_config.provider_cooldown_s_map.get(provider_domain, budget_config.provider_cooldown_s_default))
                            budget_config.provider_cooldown_s_map[provider_domain] = max(prev_cd, float(suggested_cooldown))

            if fallback_controller:
                pmta_level_now = int(pmta_pressure_applied.get("level") or 0) if isinstance(pmta_pressure_applied, dict) else 0
                fallback_controller.observe(
                    now_ts=now_ts,
                    global_metrics_snapshot=_fallback_global_metrics_snapshot(),
                    pmta_pressure_level=pmta_level_now,
                    executor_snapshot=None,
                )
                should_fallback, fallback_reasons = fallback_controller.should_trigger(now_ts)
                if should_fallback:
                    if shadow_mode_active and shadow_recorder:
                        shadow_recorder.record("fallback_would_trigger", {"reasons": list(fallback_reasons or [])})
                    else:
                        fallback_controller.apply_actions(
                            {
                                "disable_concurrency": _disable_concurrency_runtime,
                                "disable_probe": _disable_probe_runtime,
                                "switch_scheduler_legacy": _switch_scheduler_legacy,
                            }
                        )
                        with JOBS_LOCK:
                            job.log("WARN", f"Fallback triggered: {', '.join(fallback_reasons)}")
                if fallback_export:
                    with JOBS_LOCK:
                        job.debug_fallback = fallback_controller.snapshot()
            if shadow_mode_active and shadow_export_enabled and shadow_recorder:
                with JOBS_LOCK:
                    job.debug_shadow_events = shadow_recorder.snapshot()

            probe_selected_this_iteration = False
            sender_domain_pick = _pick_retry_ready_sender_domain(now_ts)
            if not sender_domain_pick and probe_controller.is_active(now_ts):
                sender_domain_pick = probe_controller.pick_probe_lane(
                    now_ts,
                    sender_bucket_by_idx,
                    lane_registry,
                    {"is_lane_temporarily_blocked": _is_lane_temporarily_blocked},
                    _budget_can_start if (budget_mgr and budget_config.apply_to_probe) else None,
                    sender_cursor,
                )
                if sender_domain_pick:
                    probe_selected_this_iteration = True
            lane_pick_meta: dict = {"pick_type": "none"}
            if shadow_mode_active and shadow_recorder and lane_picker_v2:
                shadow_budget_mgr = budget_mgr.clone_for_shadow() if budget_mgr else None
                shadow_picker = LanePickerV2(
                    scheduler_rng=random.Random(int(hashlib.sha256(f"{partition_seed}|shadow|{chunk_idx}|{sender_cursor}".encode("utf-8", errors="ignore")).hexdigest()[:16], 16)),
                    lane_registry=lane_registry,
                    budget_mgr=shadow_budget_mgr,
                    debug=False,
                    export_debug=False,
                    respect_lane_states=lane_v2_respect_lane_states,
                    use_budgets=lane_v2_use_budgets,
                    use_soft_bias=lane_v2_use_soft_bias,
                    max_scan=lane_v2_max_scan,
                    lane_weight_multiplier=_lane_weight_multiplier,
                )
                shadow_pick, shadow_meta = shadow_picker.pick_next(
                    now_ts=now_ts,
                    sender_cursor=sender_cursor,
                    sender_buckets={k: {d: list(v) for d, v in (vv or {}).items()} for k, vv in sender_bucket_by_idx.items()},
                    provider_retry_chunks={k: list(v or []) for k, v in provider_retry_chunks.items()},
                    probe_active=bool(probe_selected_this_iteration),
                )
                shadow_recorder.record("lane_v2_pick", {
                    "pick": (f"{shadow_pick[0]}|{shadow_pick[1]}" if shadow_pick else "none"),
                    "meta": dict(shadow_meta or {}),
                })
            if not sender_domain_pick:
                if scheduler_mode_runtime == "lane_v2" and lane_picker_v2:
                    sender_domain_pick, lane_pick_meta = lane_picker_v2.pick_next(
                        now_ts=now_ts,
                        sender_cursor=sender_cursor,
                        sender_buckets=sender_bucket_by_idx,
                        provider_retry_chunks=provider_retry_chunks,
                        probe_active=bool(probe_selected_this_iteration),
                    )
                    if lane_v2_export:
                        with JOBS_LOCK:
                            job.debug_last_lane_pick = dict(lane_pick_meta or {})
                else:
                    used_legacy_selector = True
                    sender_domain_pick = _next_sender_domain(now_ts)
            if not sender_domain_pick:
                wait_retry = _next_retry_wait(now_ts)
                if wait_retry is None:
                    break
                if wait_retry > 0:
                    with JOBS_LOCK:
                        if job.status != "error":
                            job.status = "backoff"
                        job.log("INFO", f"No provider ready yet; waiting {int(wait_retry)}s for next provider retry window.")
                    if not _sleep_checked(wait_retry):
                        _stop_job("stop requested during provider retry wait")
                        return
                continue

            sender_idx_fixed, target_domain = sender_domain_pick
            if scheduler_mode_runtime == "lane_v2" and len(sender_emails) > 0:
                sender_cursor = (int(sender_idx_fixed) + 1) % len(sender_emails)
            elif probe_selected_this_iteration and len(sender_emails) > 0:
                sender_cursor = (int(sender_idx_fixed) + 1) % len(sender_emails)
            lane_key_selected = (int(sender_idx_fixed), str(target_domain or "").strip().lower())
            sender_email_selected = from_emails2[sender_idx_fixed % len(from_emails2)] if from_emails2 else ""
            learning_caps = _learning_caps_for_lane(lane_key_selected, sender_email_selected)
            if caps_resolver_enabled:
                effective_caps, caps_meta = resolve_caps_for_attempt(
                    job=job,
                    now_ts=now_ts,
                    lane_key=lane_key_selected,
                    base_caps={
                        "chunk_size": int(chunk_size),
                        "thread_workers": int(thread_workers),
                        "delay_s": float(delay_s),
                        "sleep_chunks": float(sleep_chunks),
                    },
                    runtime_overrides={
                        "chunk_size": cs,
                        "thread_workers": workers2,
                        "delay_s": delay2,
                        "sleep_chunks": sleep2,
                        "__scheduler_mode_runtime": scheduler_mode_runtime,
                    },
                    pressure_caps=pmta_pressure_applied,
                    health_caps=health_policy_applied,
                    lane_registry=lane_registry,
                    learning_engine=learning_caps,
                    probe_selected=bool(probe_selected_this_iteration),
                    policy_pack_clamps=(
                        policy_pack_caps_clamps.get(provider_canon.group_for_domain(target_domain))
                        if provider_canon.enforce
                        else (policy_pack_caps_clamps.get(str(target_domain or "").strip().lower()) or policy_pack_caps_clamps.get(provider_canon.group_for_domain(target_domain)))
                    ),
                    caps_bounds_override=guard_caps_bounds_override,
                )
                cs = _safe_int(effective_caps.get("chunk_size"), cs)
                workers2 = _safe_int(effective_caps.get("thread_workers"), workers2)
                delay2 = _coerce_scalar_number(effective_caps.get("delay_s"), as_type="float", default=delay2)
                sleep2 = _coerce_scalar_number(effective_caps.get("sleep_chunks"), as_type="float", default=sleep2)
                if caps_resolver_export:
                    with JOBS_LOCK:
                        job.debug_last_caps_resolve = dict(caps_meta or {})
                if caps_resolver_debug:
                    applied_steps = [str(st.get("step")) for st in (caps_meta.get("steps") or []) if st.get("before") != st.get("after")]
                    with JOBS_LOCK:
                        job.log("INFO", f"CapsResolver lane={lane_key_selected[0]}|{lane_key_selected[1]} caps={{'chunk_size':{cs},'workers':{workers2},'delay_s':{delay2:.3f},'sleep_chunks':{sleep2:.3f}}} steps={','.join(applied_steps) or 'none'}")
            else:
                if probe_selected_this_iteration:
                    clamped_caps = probe_controller.apply_probe_caps(
                        {
                            "chunk_size": cs,
                            "workers": workers2,
                            "delay_s": delay2,
                            "sleep_chunks": sleep2,
                        }
                    )
                    cs = _safe_int(clamped_caps.get("chunk_size"), cs)
                    workers2 = _safe_int(clamped_caps.get("workers"), workers2)
                    delay2 = _coerce_scalar_number(clamped_caps.get("delay_s"), as_type="float", default=delay2)
                    sleep2 = _coerce_scalar_number(clamped_caps.get("sleep_chunks"), as_type="float", default=sleep2)
                if learning_caps_enforce and learning_caps:
                    if isinstance(learning_caps.get("chunk_size_cap"), int):
                        cs = max(1, min(int(cs or 1), int(learning_caps.get("chunk_size_cap") or cs)))
                    if isinstance(learning_caps.get("workers_cap"), int):
                        workers2 = max(1, min(int(workers2 or 1), int(learning_caps.get("workers_cap") or workers2)))
                    if isinstance(learning_caps.get("delay_floor"), (int, float)):
                        delay2 = max(float(delay2 or 0.0), float(learning_caps.get("delay_floor") or 0.0))
            target_key = _sd_key(sender_idx_fixed, target_domain)

            retry_q = provider_retry_chunks.get(target_key) or []
            retry_item = retry_q.pop(0) if retry_q and float(retry_q[0].get("next_retry_ts") or 0.0) <= now_ts else None
            provider_retry_chunks[target_key] = retry_q

            if retry_item:
                chunk = list(retry_item.get("chunk") or [])
                attempt = int(retry_item.get("attempt") or 0)
                chunk_subjects = list(retry_item.get("chunk_subjects") or subjects2 or subjects)
                chunk_body_variants = list(retry_item.get("chunk_body_variants") or body_variants2 or split_body_variants(body))
                sender_attempt_in_domain = int(retry_item.get("sender_attempt_in_domain") or 0)
                chunk_idx_local = int(retry_item.get("chunk_idx") or chunk_idx)
            else:
                bucket = (sender_bucket_by_idx.get(sender_idx_fixed) or {}).get(target_domain) or []
                chunk = bucket[:cs]
                sender_bucket_by_idx.setdefault(sender_idx_fixed, {})[target_domain] = bucket[len(chunk):]
                if not chunk:
                    continue
                attempt = 0
                sender_attempt_in_domain = 0
                chunk_idx_local = chunk_idx

            if lane_metrics:
                sender_email_for_lane = ""
                sender_domain_for_lane = ""
                if 0 <= int(sender_idx_fixed or 0) < len(from_emails2):
                    sender_email_for_lane = str(from_emails2[int(sender_idx_fixed)] or "")
                    sender_domain_for_lane = _extract_domain_from_email(sender_email_for_lane) or ""
                lane_metrics.on_chunk_selected(
                    _lane_key(sender_idx_fixed, target_domain),
                    len(chunk),
                    sender_email=sender_email_for_lane,
                    sender_domain=sender_domain_for_lane,
                )
                if probe_selected_this_iteration:
                    lane_metrics.on_probe_sample(
                        _lane_key(sender_idx_fixed, target_domain),
                        sender_email=sender_email_for_lane,
                        sender_domain=sender_domain_for_lane,
                    )
                _lane_registry_update(
                    time.time(),
                    _lane_key(sender_idx_fixed, target_domain),
                    base_caps_hint={
                        "chunk_size": cs,
                        "workers": workers2,
                        "delay_s": delay2,
                        "sleep_chunks": sleep2,
                    },
                )

            if probe_selected_this_iteration:
                probe_controller.mark_probed(_lane_key(sender_idx_fixed, target_domain))
            if probe_export and probe_controller.is_active(time.time()):
                with JOBS_LOCK:
                    job.debug_probe_status = probe_controller.snapshot()

            chunk_url = _cyclic_pick(urls2, chunk_idx_local)
            chunk_src = _cyclic_pick(src2, chunk_idx_local)

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
                job.current_chunk = chunk_idx_local
                job.current_chunk_domains = dom_counts
                job.current_chunk_info = {
                    "chunk": chunk_idx_local,
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

            # Per-chunk attempt loop (provider-isolated backoff)
            # Per-chunk AI rewrite chain (optional): rewrite from last accepted message,
            # then carry rewritten output forward as input for next chunk.
            if not retry_item:
                chunk_subjects = list(subjects2 or subjects)
                chunk_body_variants = list(body_variants2 or split_body_variants(body))

            if ai_enabled and not retry_item:
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

            chunk_finished = False
            while True:
                if sender_idx_fixed >= len(from_emails2):
                    sender_idx_fixed = sender_idx_fixed % max(1, len(from_emails2))
                active_sender_domain = _extract_domain_from_email(from_emails2[sender_idx_fixed]) or "unknown"
                available_domains = [active_sender_domain]
                recommendation = learning_recommendation(
                    target_domain,
                    available_domains,
                    max_backoff_retries,
                    base_backoff_s=backoff_base_s,
                    max_backoff_s=backoff_max_s,
                )
                available_domains = list(recommendation.get("sender_domains") or available_domains)
                recommended_domains = list(available_domains)
                pair_retry_cap = max(0, int(recommendation.get("retry_cap", max_backoff_retries) or max_backoff_retries))
                dynamic_backoff_base_s = max(1.0, float(recommendation.get("provider_backoff_base_s", backoff_base_s) or backoff_base_s))
                dynamic_backoff_max_s = max(dynamic_backoff_base_s, float(recommendation.get("provider_backoff_max_s", backoff_max_s) or backoff_max_s))
                if not available_domains:
                    with JOBS_LOCK:
                        job.skipped += len(chunk)
                        job.chunks_abandoned += 1
                        job.chunks_done += 1
                        job.current_chunk = -1
                        job.current_chunk_info = {}
                        job.current_chunk_domains = {}
                        job.push_chunk_state({
                            "chunk": chunk_idx_local,
                            "status": "abandoned",
                            "size": len(chunk),
                            "sender": "",
                            "subject": "",
                            "spam_score": None,
                            "blacklist": "",
                            "attempt": attempt,
                            "next_retry_ts": 0,
                            "reason": "all_sender_domains_exhausted",
                        })
                        job.log("ERROR", f"Chunk {chunk_idx_local+1} [{target_domain}]: ABANDONED after exhausting all sender domains.")
                    db_finalize_email_learning(
                        job_id=job_id,
                        campaign_id=job.campaign_id,
                        chunk_idx=chunk_idx_local,
                        sender_domain="",
                        provider_domain=target_domain,
                        attempts_taken=max(1, attempt + 1),
                        outcome="failure",
                    )
                    break

                sender_idx = sender_idx_fixed
                rot = sender_idx_fixed + attempt

                fe = from_emails2[sender_idx % len(from_emails2)]
                fn = from_names2[sender_idx % len(from_names2)] if from_names2 else "Sender"
                sb = chunk_subjects[rot % len(chunk_subjects)]
                b_used = chunk_body_variants[rot % len(chunk_body_variants)] if chunk_body_variants else body

                # Update PMTA live metrics for UI (rate-limited).
                # Keep this active even when PMTA_QUEUE_BACKOFF is OFF so the PMTA panel
                # still reflects the real monitor status during sending.
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
                bl_listed, bl_detail = _blacklist_check(fe)

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

                spam_blocked = (sc is not None and sc > job.spam_threshold)
                blacklist_blocked = bool(bl_listed)
                pmta_blocked = bool(pmta_reason)
                blocked_reasons = []
                blocked_signals: List[Tuple[str, str]] = []
                if spam_blocked:
                    spam_detail = f"spam_score={sc:.2f}>{job.spam_threshold:.1f}"
                    blocked_reasons.append(spam_detail)
                    blocked_signals.append(("spam", spam_detail))
                if blacklist_blocked:
                    bl_text = f"blacklist={bl_detail}"
                    blocked_reasons.append(bl_text)
                    blocked_signals.append(("blacklist", bl_detail or "listed"))
                if pmta_blocked:
                    pmta_text = f"pmta={pmta_reason}"
                    blocked_reasons.append(pmta_text)
                    blocked_signals.append(("pmta", pmta_reason or "policy block"))
                    if lane_metrics:
                        lane_metrics.on_blocked(
                            _lane_key(sender_idx_fixed, target_domain),
                            pmta_reason or "pmta policy block",
                            sender_email=fe,
                            sender_domain=active_sender_domain,
                        )
                        if lane_registry:
                            lane_registry.set_signal_blocked(_lane_key(sender_idx_fixed, target_domain), pmta_reason or "pmta policy block")
                        _lane_registry_update(
                            time.time(),
                            _lane_key(sender_idx_fixed, target_domain),
                            base_caps_hint={
                                "chunk_size": cs,
                                "workers": workers2,
                                "delay_s": delay2,
                                "sleep_chunks": sleep2,
                            },
                        )

                blocked = spam_blocked or blacklist_blocked or pmta_blocked
                failure_type, intervention = _classify_backoff_failure(
                    spam_blocked=spam_blocked,
                    blacklist_blocked=blacklist_blocked,
                    pmta_reason=pmta_reason,
                )

                if blocked and SHIVA_DISABLE_BACKOFF:
                    with JOBS_LOCK:
                        for reason, details in blocked_signals:
                            job.log(
                                "WARN",
                                f"Chunk {chunk_idx+1} [{target_domain}]: backoff disabled: bypassing block reason={reason} details={details}",
                            )
                    blocked = False

                with JOBS_LOCK:
                    job.current_chunk = chunk_idx
                    job.current_chunk_info.update({
                        "attempt": attempt,
                        "sender": fe,
                        "sender_domain": active_sender_domain,
                        "subject": sb,
                        "body_variant": (rot % max(1, len(chunk_body_variants))) if chunk_body_variants else 0,
                        "spam_score": sc,
                        "blacklist": bl_detail,
                        "pmta_reason": pmta_reason,
                        "pmta_slow": pmta_slow,
                        "target_domain": target_domain,
                        "learning": recommendation,
                    })

                if blocked:
                    attempt += 1
                    db_log_email_attempt(
                        job_id=job_id,
                        campaign_id=job.campaign_id,
                        chunk_idx=chunk_idx_local,
                        sender_domain=active_sender_domain,
                        provider_domain=target_domain,
                        attempt_number=attempt,
                        outcome=f"blocked_{failure_type}",
                    )
                    rtxt = " ".join(blocked_reasons) or "blocked"

                    sender_attempt_in_domain += 1
                    if sender_attempt_in_domain > pair_retry_cap:
                        with JOBS_LOCK:
                            job.skipped += len(chunk)
                            job.chunks_abandoned += 1
                            job.chunks_done += 1
                            job.current_chunk = -1
                            job.current_chunk_info = {}
                            job.current_chunk_domains = {}
                            job.push_chunk_state({
                                "chunk": chunk_idx_local,
                                "status": "abandoned",
                                "size": len(chunk),
                                "sender": fe,
                                "subject": sb,
                                "spam_score": sc,
                                "blacklist": bl_detail,
                                "attempt": attempt,
                                "next_retry_ts": 0,
                                "reason": "all_sender_domains_exhausted",
                            })
                            job.log("ERROR", f"Chunk {chunk_idx_local+1} [{target_domain}]: ABANDONED after exhausting sender domains ({rtxt})")
                        db_finalize_email_learning(
                            job_id=job_id,
                            campaign_id=job.campaign_id,
                            chunk_idx=chunk_idx_local,
                            sender_domain=active_sender_domain,
                            provider_domain=target_domain,
                            attempts_taken=max(1, attempt),
                            outcome="failure",
                        )
                        break

                    wait_s_base = _compute_backoff_wait_seconds(
                        attempt=attempt,
                        base_s=dynamic_backoff_base_s,
                        max_s=dynamic_backoff_max_s,
                        failure_type=failure_type,
                    )
                    wait_s = wait_s_base
                    jitter_delta = 0.0
                    if backoff_jitter_mode_runtime != "off":
                        wait_s, jitter_delta = apply_backoff_jitter(
                            wait_s_base=wait_s_base,
                            mode=backoff_jitter_mode_runtime,
                            pct=jitter_pct_runtime,
                            max_jitter_s=SHIVA_BACKOFF_JITTER_MAX_S,
                            min_jitter_s=SHIVA_BACKOFF_JITTER_MIN_S,
                            max_s=dynamic_backoff_max_s,
                            partition_seed=partition_seed,
                            lane_key=target_key,
                            attempt=attempt,
                            failure_type=failure_type,
                        )
                    next_ts = time.time() + wait_s

                    entry = {
                        "chunk": chunk_idx_local,
                        "size": len(chunk),
                        "attempt": attempt,
                        "next_retry_ts": next_ts,
                        "reason": rtxt,
                        "sender": fe,
                        "subject": sb,
                        "spam_score": sc,
                        "blacklist": bl_detail,
                        "failure_type": failure_type,
                        "intervention": intervention,
                        "sender_domain": active_sender_domain,
                        "sender_attempt_in_domain": sender_attempt_in_domain,
                        "provider_trend": str(recommendation.get("provider_trend") or "unknown"),
                        "provider_samples": int(recommendation.get("provider_samples") or 0),
                    }

                    with JOBS_LOCK:
                        job.status = "backoff"
                        job.chunks_backoff += 1
                        job.push_backoff(entry)
                        job.push_chunk_state({**entry, "status": "backoff"})
                    msg = (
                        f"Chunk {chunk_idx_local+1} [{target_domain}]: BACKOFF retry#{attempt} "
                        f"wait={int(wait_s)}s type={failure_type} ({rtxt}) trend={recommendation.get('provider_trend','unknown')}"
                    )
                    if intervention:
                        msg += f" | intervention={intervention}"
                    if backoff_jitter_mode_runtime != "off" and SHIVA_BACKOFF_JITTER_DEBUG:
                        msg += f" | jitter={jitter_delta:+.2f}s mode={backoff_jitter_mode_runtime}"
                    job.log("WARN", msg)
                    if backoff_jitter_mode_runtime != "off" and SHIVA_BACKOFF_JITTER_EXPORT:
                        with JOBS_LOCK:
                            job.debug_backoff_jitter.append({
                                "lane_key": target_key,
                                "attempt": int(attempt or 0),
                                "failure_type": str(failure_type or ""),
                                "wait_base": float(wait_s_base),
                                "jitter_delta": float(jitter_delta),
                                "wait_final": float(wait_s),
                            })
                            if len(job.debug_backoff_jitter) > 50:
                                job.debug_backoff_jitter = job.debug_backoff_jitter[-50:]
                    if lane_metrics:
                        lane_metrics.on_backoff_scheduled(
                            _lane_key(sender_idx_fixed, target_domain),
                            wait_s,
                            failure_type,
                            sender_email=fe,
                            sender_domain=active_sender_domain,
                        )
                        if lane_registry:
                            lane_registry.set_signal_backoff(_lane_key(sender_idx_fixed, target_domain), wait_s, failure_type)
                        if budget_mgr:
                            budget_mgr.on_lane_state_signal(_lane_key(sender_idx_fixed, target_domain), "INFRA_FAIL", time.time(), failure_type=failure_type)
                        _lane_registry_update(
                            time.time(),
                            _lane_key(sender_idx_fixed, target_domain),
                            base_caps_hint={
                                "chunk_size": cs,
                                "workers": workers2,
                                "delay_s": delay2,
                                "sleep_chunks": sleep2,
                            },
                        )
                        _lane_metrics_export_snapshot()

                    retry_queue = provider_retry_chunks.setdefault(target_key, [])
                    retry_queue.append({
                        "chunk_idx": chunk_idx_local,
                        "chunk": list(chunk),
                        "attempt": attempt,
                        "next_retry_ts": next_ts,
                        "chunk_subjects": list(chunk_subjects),
                        "chunk_body_variants": list(chunk_body_variants),
                        "sender_attempt_in_domain": sender_attempt_in_domain,
                    })
                    retry_queue.sort(key=lambda x: float(x.get("next_retry_ts") or 0.0))
                    break

                # allowed -> send
                with JOBS_LOCK:
                    job.status = "running"
                    job.push_chunk_state({
                        "chunk": chunk_idx_local,
                        "status": "running",
                        "size": len(chunk),
                        "sender": fe,
                        "subject": sb,
                        "spam_score": sc,
                        "blacklist": bl_detail,
                        "attempt": attempt,
                        "next_retry_ts": 0,
                        "reason": "",
                    })
                    job.log("INFO", f"Chunk {chunk_idx_local+1} [{target_domain}]: sending size={len(chunk)} sender={fe} workers={workers2}")

                if not _wait_ready():
                    _stop_job("stop requested")
                    return

                before_recent_len = 0
                with JOBS_LOCK:
                    before_recent_len = len(job.recent_results or [])

                lane_key_current = _lane_key(sender_idx_fixed, target_domain)
                wave_cost = max(1, len(chunk)) * wave_token_cost_per_msg
                if wave_controller.enabled:
                    with lock_wave:
                        wave_controller.reserve_tokens(_lane_budget_key(lane_key_current), time.time(), wave_cost)
                if budget_mgr:
                    budget_mgr.on_start(lane_key_current, time.time())
                try:
                    _send_chunk(
                        chunk_idx=chunk_idx_local,
                        chunk_rcpts=chunk,
                        from_name=fn,
                        from_email=fe,
                        subject=sb,
                        body_used=b_used,
                        body_format2=body_format2,
                        reply_to2=reply_to2,
                        delay2=delay2,
                        workers2=workers2,
                        chunk_url=chunk_url,
                        chunk_src=chunk_src,
                    )
                finally:
                    if budget_mgr:
                        budget_mgr.on_finish(lane_key_current, time.time())

                if lane_metrics:
                    with JOBS_LOCK:
                        recent_slice = list((job.recent_results or [])[before_recent_len:])
                    lane_metrics.on_chunk_result(
                        _lane_key(sender_idx_fixed, target_domain),
                        _lane_chunk_result_from_recent(recent_slice, len(chunk)),
                        sender_email=fe,
                        sender_domain=active_sender_domain,
                    )
                    _lane_registry_update(
                        time.time(),
                        _lane_key(sender_idx_fixed, target_domain),
                        base_caps_hint={
                            "chunk_size": cs,
                            "workers": workers2,
                            "delay_s": delay2,
                            "sleep_chunks": sleep2,
                        },
                    )
                    if wave_controller.enabled:
                        with lock_wave:
                            wave_controller.on_feedback(time.time(), _provider_metrics_snapshot(provider_canon.group_for_domain(target_domain) if provider_canon.enforce else target_domain))
                    _lane_metrics_export_snapshot()
                db_log_email_attempt(
                    job_id=job_id,
                    campaign_id=job.campaign_id,
                    chunk_idx=chunk_idx_local,
                    sender_domain=active_sender_domain,
                    provider_domain=target_domain,
                    attempt_number=max(1, attempt + 1),
                    outcome="sent",
                )
                db_finalize_email_learning(
                    job_id=job_id,
                    campaign_id=job.campaign_id,
                    chunk_idx=chunk_idx_local,
                    sender_domain=active_sender_domain,
                    provider_domain=target_domain,
                    attempts_taken=max(1, attempt + 1),
                    outcome="success",
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
                        "chunk": chunk_idx_local,
                        "status": "done" if attempt == 0 else "done_after_backoff",
                        "size": len(chunk),
                        "sender": fe,
                        "subject": sb,
                        "spam_score": sc,
                        "blacklist": bl_detail,
                        "attempt": attempt,
                        "next_retry_ts": 0,
                        "reason": "",
                    })
                _lane_metrics_export_snapshot()
                chunk_finished = True
                break

            # next chunk
            if chunk_finished:
                chunk_idx += 1

            if sleep2 > 0 and _remaining_total() > 0:
                with JOBS_LOCK:
                    job.log("INFO", f"Sleeping {sleep2}s between chunks (round-robin providers)...")
                if not _sleep_checked(sleep2):
                    _stop_job("stop requested")
                    return

        _tick_accounting_recon(time.time())
        if lane_concurrency_runtime and resource_governor and resource_governor_export:
            with JOBS_LOCK:
                job.debug_resource_governor = resource_governor.snapshot()
        with JOBS_LOCK:
            job.status = "done"
            job.current_chunk = -1
            if isinstance(job.debug_rollout, dict):
                job.debug_rollout["used_legacy_selector"] = bool(used_legacy_selector or shadow_mode_active or not lane_v2_rollout_enabled)
            if shadow_mode_active and shadow_export_enabled and shadow_recorder:
                job.debug_shadow_events = shadow_recorder.snapshot()
            job.log("INFO", "Job finished.")
            job.maybe_persist(force=True)

    except Exception as e:
        tb_tail = traceback.format_exc(limit=20).strip().splitlines()[-12:]
        debug_keys = (
            "smtp_port",
            "smtp_timeout",
            "delay_s",
            "chunk_size",
            "thread_workers",
            "sleep_chunks",
            "scheduler_mode",
            "rollout_mode",
        )
        debug_parts: List[str] = []
        _locals = locals()
        for _k in debug_keys:
            if _k not in _locals:
                continue
            _v = _locals.get(_k)
            _vs = repr(_v)
            if len(_vs) > 160:
                _vs = _vs[:157] + "..."
            debug_parts.append(f"{_k}={_vs}<{type(_v).__name__}>")
        with JOBS_LOCK:
            job.status = "error"
            job.last_error = str(e)
            job.log("ERROR", f"Job error: {e}")
            if debug_parts:
                job.log("ERROR", "Job debug context: " + " | ".join(debug_parts))
            if tb_tail:
                job.log("ERROR", "Job traceback tail:\n" + "\n".join(tb_tail))
            job.maybe_persist(force=True)


def smtp_send_job_thread_entry(*args, **kwargs) -> None:
    """Thread-safe entrypoint for smtp_send_job.

    Guarantees that unexpected crashes (outside smtp_send_job's internal try/except)
    still mark the job as failed instead of leaving it stuck in "running" state.
    """
    job_id = str((args[0] if args else kwargs.get("job_id")) or "")
    try:
        smtp_send_job(*args, **kwargs)
    except Exception as exc:
        logging.getLogger("shiva").exception("smtp_send_job_thread_entry fatal crash for job=%s", job_id)
        if not job_id:
            return
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                return
            job.status = "error"
            job.last_error = str(exc)
            job.log("ERROR", f"Fatal thread crash: {exc}")
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
    {"key": "SHIVA_DISABLE_BLACKLIST", "type": "bool", "default": "0", "group": "DNSBL", "restart_required": False,
     "desc": "If enabled: disable all DNSBL/DBL blacklist checks (alias env: DISABLE_BLACKLIST)."},

    # Recipient filter
    {"key": "RECIPIENT_FILTER_ENABLE_ROUTE_CHECK", "type": "bool", "default": "1", "group": "Recipient Filter", "restart_required": False,
     "desc": "If enabled: perform MX/A route checks before enqueueing recipient domains."},

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
    {"key": "SHIVA_DISABLE_BACKOFF", "type": "bool", "default": "0", "group": "Backoff", "restart_required": False,
     "desc": "If enabled: bypass all chunk backoff triggers (spam/blacklist/PMTA) and keep sending immediately."},
    {"key": "SHIVA_BACKOFF_JITTER", "type": "str", "default": "off", "group": "Backoff", "restart_required": False,
     "desc": "Optional backoff jitter mode: off | deterministic | random."},
    {"key": "SHIVA_BACKOFF_JITTER_PCT", "type": "float", "default": "0.15", "group": "Backoff", "restart_required": False,
     "desc": "Jitter amplitude as percentage of computed backoff wait (e.g., 0.15 => ±15%)."},
    {"key": "SHIVA_BACKOFF_JITTER_MAX_S", "type": "float", "default": "120", "group": "Backoff", "restart_required": False,
     "desc": "Absolute cap in seconds for applied backoff jitter."},
    {"key": "SHIVA_BACKOFF_JITTER_MIN_S", "type": "float", "default": "0", "group": "Backoff", "restart_required": False,
     "desc": "Absolute floor in seconds for jitter amplitude before sign is applied."},
    {"key": "SHIVA_BACKOFF_JITTER_EXPORT", "type": "bool", "default": "0", "group": "Backoff", "restart_required": False,
     "desc": "Export recent jitter applications into job debug payload (debug_backoff_jitter)."},
    {"key": "SHIVA_BACKOFF_JITTER_DEBUG", "type": "bool", "default": "0", "group": "Backoff", "restart_required": False,
     "desc": "Log concise jitter lines for blocked/backoff scheduling events."},
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

    # Accounting bridge pull mode (Shiva pull request -> bridge API response)
    {"key": "PMTA_BRIDGE_PULL_ENABLED", "type": "bool", "default": "1", "group": "Accounting", "restart_required": True,
     "desc": "Enable the only accounting flow: Shiva pulls accounting from bridge API."},
    {"key": "BRIDGE_MODE", "type": "str", "default": "counts", "group": "Accounting", "restart_required": False,
     "desc": "Bridge ingestion mode. Use 'counts' to enforce /api/v1/job/count (+ optional /job/outcomes) and disable legacy cursor /pull ingestion."},
    {"key": "BRIDGE_BASE_URL", "type": "str", "default": "", "group": "Accounting", "restart_required": False,
     "desc": "Optional explicit Bridge base URL (example: http://bridge-host:8090). If empty, Shiva derives host from campaign SMTP host."},
    {"key": "PMTA_BRIDGE_PULL_PORT", "type": "int", "default": "8090", "group": "Accounting", "restart_required": False,
     "desc": "Bridge port used by Shiva when building count/outcomes API URLs from campaign SMTP host."},
    {"key": "PMTA_BRIDGE_PULL_S", "type": "float", "default": "5", "group": "Accounting", "restart_required": False,
     "desc": "Legacy polling interval (seconds) for Shiva bridge pull thread."},
    {"key": "BRIDGE_POLL_INTERVAL_S", "type": "float", "default": "5", "group": "Accounting", "restart_required": False,
     "desc": "Polling interval (seconds) for Shiva bridge job poller loop."},
    {"key": "OUTCOMES_SYNC", "type": "bool", "default": "1", "group": "Accounting", "restart_required": False,
     "desc": "If enabled, Shiva also fetches /api/v1/job/outcomes for each active job poll cycle."},
    {"key": "BRIDGE_POLL_FETCH_OUTCOMES", "type": "bool", "default": "1", "group": "Accounting", "restart_required": False,
     "desc": "Legacy alias for OUTCOMES_SYNC. If enabled, Shiva also fetches /api/v1/job/outcomes for each active job poll cycle."},
    {"key": "PMTA_BRIDGE_PULL_MAX_LINES", "type": "int", "default": "2000", "group": "Accounting", "restart_required": False,
     "desc": "max_lines query used when Shiva pulls from bridge endpoint."},

    # Scheduler lane scaffolding (baseline/debug only in this phase)
    {"key": "SHIVA_SCHEDULER_MODE", "type": "str", "default": "legacy", "group": "Scheduler", "restart_required": False,
     "desc": "Scheduler mode: legacy | lane_v2. legacy remains default."},
    {"key": "SHIVA_LANE_V2_DEBUG", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Emit concise LanePickerV2 pick logs (type/lane and skip reasons)."},
    {"key": "SHIVA_LANE_V2_EXPORT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Export last LanePickerV2 pick metadata into job debug payload as debug_last_lane_pick."},
    {"key": "SHIVA_LANE_V2_RESPECT_LANE_STATES", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "If enabled, LanePickerV2 skips QUARANTINED/INFRA_FAIL lanes until next_allowed_ts."},
    {"key": "SHIVA_LANE_V2_USE_BUDGETS", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "If enabled, LanePickerV2 gates candidates via BudgetManager.can_start."},
    {"key": "SHIVA_LANE_V2_USE_SOFT_BIAS", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "If enabled, LanePickerV2 weighted picks apply soft lane-state multipliers."},
    {"key": "SHIVA_LANE_V2_MAX_SCAN", "type": "int", "default": "50", "group": "Scheduler", "restart_required": False,
     "desc": "Maximum domains scanned per sender during LanePickerV2 weighted candidate build."},
    {"key": "SHIVA_LANE_CONCURRENCY", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enable concurrent lane executor for inter-lane chunk scheduling (requires lane_v2 mode)."},
    {"key": "SHIVA_MAX_PARALLEL_LANES", "type": "int", "default": "5", "group": "Scheduler", "restart_required": False,
     "desc": "Maximum in-flight lane tasks allowed by concurrent lane executor."},
    {"key": "SHIVA_LANE_TASK_TIMEOUT_S", "type": "int", "default": "900", "group": "Scheduler", "restart_required": False,
     "desc": "Safety timeout in seconds for each lane task when lane concurrency is enabled."},
    {"key": "SHIVA_LANE_CONCURRENCY_DEBUG", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Emit concise lane concurrency executor logs."},
    {"key": "SHIVA_LANE_CONCURRENCY_EXPORT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Export lane executor snapshot into job debug payload as debug_lane_executor."},
    {"key": "SHIVA_RESOURCE_GOVERNOR", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enable job-scoped global worker/session governor for concurrent lane submissions."},
    {"key": "SHIVA_RESOURCE_GOVERNOR_DEBUG", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Emit concise global resource governor denial/debug logs."},
    {"key": "SHIVA_RESOURCE_GOVERNOR_EXPORT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Export global resource governor snapshot into job debug payload as debug_resource_governor."},
    {"key": "SHIVA_MAX_TOTAL_WORKERS", "type": "int", "default": "40", "group": "Scheduler", "restart_required": False,
     "desc": "Global maximum concurrent workers/sessions reserved across in-flight lanes."},
    {"key": "SHIVA_MAX_TOTAL_LANES", "type": "int", "default": "5", "group": "Scheduler", "restart_required": False,
     "desc": "Hard cap on concurrent lane tasks when resource governor is enabled."},
    {"key": "SHIVA_WORKER_RESERVE_MODE", "type": "str", "default": "workers", "group": "Scheduler", "restart_required": False,
     "desc": "Reservation unit for governor: workers | sessions (currently equivalent)."},
    {"key": "SHIVA_GOVERNOR_APPLY_IN_SEQUENTIAL", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "If enabled, apply governor reservation checks on sequential path too."},
    {"key": "SHIVA_GOVERNOR_PMTA_SCALE", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "Scale down effective total-worker budget when PMTA pressure is elevated."},
    {"key": "SHIVA_GOVERNOR_PMTA_LEVEL2_FACTOR", "type": "float", "default": "0.75", "group": "Scheduler", "restart_required": False,
     "desc": "Multiplier for total-worker budget when PMTA pressure level >= 2."},
    {"key": "SHIVA_GOVERNOR_PMTA_LEVEL3_FACTOR", "type": "float", "default": "0.50", "group": "Scheduler", "restart_required": False,
     "desc": "Multiplier for total-worker budget when PMTA pressure level >= 3."},
    {"key": "SHIVA_CONCURRENCY_STOP_GRACE_S", "type": "int", "default": "30", "group": "Scheduler", "restart_required": False,
     "desc": "Grace period in seconds for stopping lane submissions and draining in-flight tasks."},
    {"key": "SHIVA_CONCURRENCY_STOP_FORCE_DISABLE", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "After stop grace timeout, force-disable concurrency and continue sequentially when possible."},
    {"key": "SHIVA_FALLBACK_CONTROLLER", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enable job-scoped fallback controller that can disable new scheduler layers and force legacy mode on risk spikes."},
    {"key": "SHIVA_FALLBACK_DEBUG", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Emit concise fallback controller debug logs."},
    {"key": "SHIVA_FALLBACK_EXPORT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Export fallback controller snapshot into job debug payload as debug_fallback."},
    {"key": "SHIVA_FALLBACK_WINDOW_S", "type": "int", "default": "300", "group": "Scheduler", "restart_required": False,
     "desc": "Rolling window in seconds used for fallback trigger-rate calculations."},
    {"key": "SHIVA_FALLBACK_DEFERRAL_RATE", "type": "float", "default": "0.35", "group": "Scheduler", "restart_required": False,
     "desc": "Fallback trigger threshold for global deferrals/attempts."},
    {"key": "SHIVA_FALLBACK_HARDFAIL_RATE", "type": "float", "default": "0.05", "group": "Scheduler", "restart_required": False,
     "desc": "Fallback trigger threshold for global hardfails/attempts."},
    {"key": "SHIVA_FALLBACK_TIMEOUT_RATE", "type": "float", "default": "0.08", "group": "Scheduler", "restart_required": False,
     "desc": "Fallback trigger threshold for global timeout failures/attempts."},
    {"key": "SHIVA_FALLBACK_BLOCKED_PER_MIN", "type": "float", "default": "10", "group": "Scheduler", "restart_required": False,
     "desc": "Fallback trigger threshold for blocked events per minute."},
    {"key": "SHIVA_FALLBACK_PMTA_PRESSURE_LEVEL", "type": "int", "default": "3", "group": "Scheduler", "restart_required": False,
     "desc": "Fallback trigger threshold for PMTA pressure level sustained over half the fallback window."},
    {"key": "SHIVA_FALLBACK_MIN_ACTIVE_S", "type": "int", "default": "180", "group": "Scheduler", "restart_required": False,
     "desc": "Minimum time fallback remains active before any recovery checks."},
    {"key": "SHIVA_FALLBACK_RECOVERY_S", "type": "int", "default": "300", "group": "Scheduler", "restart_required": False,
     "desc": "Stable period required before re-enabling new layers when re-enable is allowed."},
    {"key": "SHIVA_FALLBACK_DISABLE_REENABLE", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "If enabled, fallback remains active for the entire job once triggered."},
    {"key": "SHIVA_FALLBACK_STEP1_DISABLE_CONCURRENCY", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "Fallback action step 1: disable lane concurrency for the active job."},
    {"key": "SHIVA_FALLBACK_STEP2_DISABLE_PROBE", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "Fallback action step 2: disable probe mode for the active job."},
    {"key": "SHIVA_FALLBACK_STEP3_SWITCH_TO_LEGACY", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "Fallback action step 3: force legacy scheduler selection for the active job."},
    {"key": "SHIVA_LANE_DEBUG", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enable lane debug self-check invariants (logging + fatal on hard mismatch)."},
    {"key": "SHIVA_LANE_BASELINE_REPORT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Emit one baseline scheduler report at job start (read-only snapshot)."},
    {"key": "SHIVA_LANE_METRICS", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enable in-memory lane metrics per (sender_idx, provider_domain) during send loop."},
    {"key": "SHIVA_LANE_METRICS_WINDOW", "type": "int", "default": "200", "group": "Scheduler", "restart_required": False,
     "desc": "Lane metrics rolling window size (samples per lane)."},
    {"key": "SHIVA_LANE_METRICS_EMA", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "Compatibility flag for lane metrics smoothing mode (rolling window implementation is used in this phase)."},
    {"key": "SHIVA_LANE_METRICS_EXPORT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Export lane metrics snapshot into job debug payload as additive field lane_metrics."},
    {"key": "SHIVA_LANE_REGISTRY", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enable read-only lane registry/state machine updates from lane metrics and blocked/backoff signals."},
    {"key": "SHIVA_LANE_STATE_EXPORT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Export lane state snapshot into job debug payload as additive field lane_states."},
    {"key": "SHIVA_LANE_THRESHOLDS_JSON", "type": "str", "default": "", "group": "Scheduler", "restart_required": False,
     "desc": "Optional JSON overrides for lane state thresholds/multipliers (safe-parse, clamped)."},
    {"key": "SHIVA_LANE_QUARANTINE_BASE_S", "type": "int", "default": "120", "group": "Scheduler", "restart_required": False,
     "desc": "Base quarantine seconds used by read-only lane state machine for QUARANTINED/INFRA_FAIL transitions."},
    {"key": "SHIVA_LANE_QUARANTINE_MAX_S", "type": "int", "default": "1800", "group": "Scheduler", "restart_required": False,
     "desc": "Maximum quarantine seconds cap used by read-only lane state machine."},
    {"key": "SHIVA_SOFT_PROVIDER_BUDGETS", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enable soft provider-aware filtering/bias in legacy scheduler weighted picks (sequential only, additive)."},
    {"key": "SHIVA_PROVIDER_COOLDOWN_S", "type": "int", "default": "90", "group": "Scheduler", "restart_required": False,
     "desc": "Minimum cooldown seconds applied per provider_domain after lane state transitions to QUARANTINED/INFRA_FAIL."},
    {"key": "SHIVA_PROVIDER_QUARANTINE_RESPECT", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "If enabled, weighted picks skip lanes in QUARANTINED/INFRA_FAIL while now < lane.next_allowed_ts."},
    {"key": "SHIVA_PROVIDER_STATE_BIAS", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "If enabled, weighted picks apply lane-state multipliers (THROTTLED/QUARANTINED/INFRA_FAIL)."},
    {"key": "SHIVA_PROVIDER_BIAS_THROTTLED", "type": "float", "default": "0.35", "group": "Scheduler", "restart_required": False,
     "desc": "Weighted-pick multiplier for lanes in THROTTLED state."},
    {"key": "SHIVA_PROVIDER_BIAS_QUAR", "type": "float", "default": "0.05", "group": "Scheduler", "restart_required": False,
     "desc": "Weighted-pick multiplier for lanes in QUARANTINED state (when otherwise allowed)."},
    {"key": "SHIVA_PROVIDER_BIAS_INFRA", "type": "float", "default": "0.05", "group": "Scheduler", "restart_required": False,
     "desc": "Weighted-pick multiplier for lanes in INFRA_FAIL state (when otherwise allowed)."},
    {"key": "SHIVA_SOFT_BUDGET_DEBUG", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Emit concise soft-budget scheduler debug logs (skips/cooldowns/bias multipliers)."},
    {"key": "SHIVA_BUDGET_MANAGER", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enable formal BudgetManager lane gating (provider/sender inflight caps, min-gap, cooldown, lane quarantine)."},
    {"key": "SHIVA_BUDGET_DEBUG", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Emit concise BudgetManager deny/debug logs."},
    {"key": "SHIVA_PROVIDER_MAX_INFLIGHT_DEFAULT", "type": "int", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "Default provider max inflight lanes used by BudgetManager (future concurrency-ready)."},
    {"key": "SHIVA_PROVIDER_MAX_INFLIGHT_JSON", "type": "str", "default": "", "group": "Scheduler", "restart_required": False,
     "desc": "Optional JSON map for per-provider max inflight (supports '*' default override)."},
    {"key": "SHIVA_PROVIDER_MIN_GAP_S_DEFAULT", "type": "float", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Default minimum seconds gap between starts per provider."},
    {"key": "SHIVA_PROVIDER_MIN_GAP_S_JSON", "type": "str", "default": "", "group": "Scheduler", "restart_required": False,
     "desc": "Optional JSON map for per-provider min gap seconds (supports '*' default override)."},
    {"key": "SHIVA_PROVIDER_COOLDOWN_S_DEFAULT", "type": "float", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Default provider cooldown seconds used by BudgetManager on severe lane signals."},
    {"key": "SHIVA_PROVIDER_COOLDOWN_S_JSON", "type": "str", "default": "", "group": "Scheduler", "restart_required": False,
     "desc": "Optional JSON map for per-provider cooldown seconds (supports '*' default override)."},
    {"key": "SHIVA_SENDER_MAX_INFLIGHT", "type": "int", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "Sender max inflight lanes budget for BudgetManager (future concurrency-ready)."},
    {"key": "SHIVA_BUDGET_APPLY_TO_RETRY", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "If enabled, BudgetManager also gates retry-ready lane picks (disabled by default to preserve legacy priority)."},
    {"key": "SHIVA_BUDGET_APPLY_TO_PROBE", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "If enabled, probe mode lane picks must pass BudgetManager gate."},
    {"key": "SHIVA_BUDGET_EXPORT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Export BudgetManager debug snapshot into job debug payload as additive field debug_budget_status."},
    {"key": "SHIVA_LEARNING_CAPS", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Compute learning-driven provider/lane safety caps from existing SQLite learning tables (debug/additive unless enforced)."},
    {"key": "SHIVA_LEARNING_CAPS_ENFORCE", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enforce learning caps as clamp-only safety limits (reduce aggressiveness only)."},
    {"key": "SHIVA_CAPS_RESOLVER", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enable unified caps resolver wiring for per-lane attempt cap merges. If disabled, legacy cap-merge logic remains unchanged."},
    {"key": "SHIVA_CAPS_RESOLVER_EXPORT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Export last resolved caps metadata into job debug payload as debug_last_caps_resolve."},
    {"key": "SHIVA_CAPS_RESOLVER_DEBUG", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Emit concise per-chunk CapsResolver debug logs (lane + final caps + applied clamps)."},
    {"key": "SHIVA_LANE_STATE_CAPS_ENFORCE", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "If enabled, enforce LaneRegistry recommended caps as clamp-only limits per lane attempt."},
    {"key": "SHIVA_LANE_STATE_CAPS_ONLY_IN_LANE_V2", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "When lane-state cap enforcement is enabled, apply only while effective scheduler mode is lane_v2."},
    {"key": "SHIVA_CAPS_MIN_CHUNK", "type": "int", "default": "50", "group": "Scheduler", "restart_required": False,
     "desc": "Global minimum chunk size bound for resolved caps."},
    {"key": "SHIVA_CAPS_MAX_CHUNK", "type": "int", "default": "2000", "group": "Scheduler", "restart_required": False,
     "desc": "Global maximum chunk size bound for resolved caps."},
    {"key": "SHIVA_CAPS_MIN_WORKERS", "type": "int", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "Global minimum worker bound for resolved caps."},
    {"key": "SHIVA_CAPS_MAX_WORKERS", "type": "int", "default": "50", "group": "Scheduler", "restart_required": False,
     "desc": "Global maximum worker bound for resolved caps."},
    {"key": "SHIVA_CAPS_MIN_DELAY_S", "type": "float", "default": "0.0", "group": "Scheduler", "restart_required": False,
     "desc": "Global minimum per-message delay bound for resolved caps."},
    {"key": "SHIVA_CAPS_MAX_DELAY_S", "type": "float", "default": "5.0", "group": "Scheduler", "restart_required": False,
     "desc": "Global maximum per-message delay bound for resolved caps."},
    {"key": "SHIVA_CAPS_MIN_SLEEP_CHUNKS", "type": "int", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Global minimum sleep-between-chunks bound for resolved caps."},
    {"key": "SHIVA_CAPS_MAX_SLEEP_CHUNKS", "type": "int", "default": "60", "group": "Scheduler", "restart_required": False,
     "desc": "Global maximum sleep-between-chunks bound for resolved caps."},
    {"key": "SHIVA_LEARNING_REFRESH_S", "type": "int", "default": "120", "group": "Scheduler", "restart_required": False,
     "desc": "Refresh interval (seconds) for learning policy DB reads."},
    {"key": "SHIVA_LEARNING_MIN_SAMPLES", "type": "int", "default": "200", "group": "Scheduler", "restart_required": False,
     "desc": "Minimum attempts required before trusting learning suggestions."},
    {"key": "SHIVA_LEARNING_RECENCY_DAYS", "type": "int", "default": "14", "group": "Scheduler", "restart_required": False,
     "desc": "Recency window (days) used for learning aggregation from attempt logs."},
    {"key": "SHIVA_LEARNING_EXPORT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Export learning policy snapshot into job.debug_learning_policy."},
    {"key": "SHIVA_LEARNING_MAX_LANES_PROVIDER_JSON", "type": "str", "default": "", "group": "Scheduler", "restart_required": False,
     "desc": "Optional JSON map overriding provider workers cap suggestions from learning policy."},
    {"key": "SHIVA_LEARNING_DELAY_FLOOR_JSON", "type": "str", "default": "", "group": "Scheduler", "restart_required": False,
     "desc": "Optional JSON map overriding provider delay floor suggestions from learning policy."},
    {"key": "SHIVA_LEARNING_CHUNK_CAP_JSON", "type": "str", "default": "", "group": "Scheduler", "restart_required": False,
     "desc": "Optional JSON map overriding provider chunk cap suggestions from learning policy."},
    {"key": "SHIVA_PROVIDER_CANON", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Compute canonical provider groups for recipient domains (debug/classification only unless enforce is enabled)."},
    {"key": "SHIVA_PROVIDER_CANON_ENFORCE", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "If enabled, budgets and single-provider wave detection use canonical provider-group keys."},
    {"key": "SHIVA_PROVIDER_CANON_EXPORT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Export provider canonicalization snapshot into job debug payload as debug_provider_canon."},
    {"key": "SHIVA_PROVIDER_ALIAS_JSON", "type": "str", "default": "", "group": "Scheduler", "restart_required": False,
     "desc": "JSON object for exact domain->provider_group aliases used before suffix/mx rules."},
    {"key": "SHIVA_PROVIDER_SUFFIX_JSON", "type": "str", "default": "", "group": "Scheduler", "restart_required": False,
     "desc": "JSON object for suffix->provider_group mappings (domain boundary match)."},
    {"key": "SHIVA_PROVIDER_MX_FINGERPRINT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "If enabled, canonicalization can use already-known MX host fingerprints (no extra lookups)."},
    {"key": "SHIVA_PROVIDER_UNKNOWN_GROUP", "type": "str", "default": "other", "group": "Scheduler", "restart_required": False,
     "desc": "Fallback provider-group key for unmatched domains."},
    {"key": "SHIVA_PROVIDER_CANON_DEBUG", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Emit concise provider canonicalization debug logs (raw domain + canonical group)."},
    {"key": "SHIVA_POLICY_PACKS", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enable provider policy-pack recommendation engine (job-local, additive; no behavior change unless enforce=1)."},
    {"key": "SHIVA_POLICY_PACKS_ENFORCE", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Apply policy-pack clamp-only enforcement (never increases aggressiveness)."},
    {"key": "SHIVA_POLICY_PACK_NAME", "type": "str", "default": "default", "group": "Scheduler", "restart_required": False,
     "desc": "Policy-pack name to use when packs are enabled (campaign_form.policy_pack_name can override per job)."},
    {"key": "SHIVA_POLICY_PACKS_JSON", "type": "str", "default": "", "group": "Scheduler", "restart_required": False,
     "desc": "Optional JSON object defining named provider policy packs; invalid/missing JSON falls back to built-in safe defaults."},
    {"key": "SHIVA_POLICY_PACKS_EXPORT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Export policy-pack snapshot into job debug payload as debug_policy_pack."},
    {"key": "SHIVA_POLICY_PACKS_DEBUG", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enable concise policy-pack decision logs for selected pack and provider scope."},
    {"key": "SHIVA_SINGLE_DOMAIN_WAVES", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enable single-provider-domain wave pacing mode (provider-wide token bucket + deterministic stagger)."},
    {"key": "SHIVA_SINGLE_DOMAIN_WAVES_DEBUG", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Emit concise wave-controller debug logs for single-domain pacing mode."},
    {"key": "SHIVA_SINGLE_DOMAIN_WAVES_EXPORT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Export wave-controller job snapshot into debug_wave_status."},
    {"key": "SHIVA_SINGLE_DOMAIN_ONLY_IF_PROVIDERS_EQ", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "Only activate wave mode when exactly one recipient provider-domain exists in this job."},
    {"key": "SHIVA_WAVE_BURST_TOKENS", "type": "int", "default": "400", "group": "Scheduler", "restart_required": False,
     "desc": "Single-domain wave token-bucket capacity (wave size ceiling)."},
    {"key": "SHIVA_WAVE_REFILL_PER_SEC", "type": "float", "default": "3.0", "group": "Scheduler", "restart_required": False,
     "desc": "Token refill rate per second for single-domain wave mode."},
    {"key": "SHIVA_WAVE_TOKEN_COST_PER_MSG", "type": "int", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "Token cost per message when reserving a chunk in wave mode."},
    {"key": "SHIVA_WAVE_MIN_TOKENS_TO_START_CHUNK", "type": "int", "default": "50", "group": "Scheduler", "restart_required": False,
     "desc": "Minimum tokens required before any chunk may start in wave mode."},
    {"key": "SHIVA_WAVE_MAX_PARALLEL_LANES_SINGLE_DOMAIN", "type": "int", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "Job-local provider inflight cap override applied when single-domain wave mode is active."},
    {"key": "SHIVA_WAVE_STAGGER_ENABLED", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "Enable deterministic sender stagger offsets in single-domain wave mode."},
    {"key": "SHIVA_WAVE_STAGGER_STEP_S", "type": "float", "default": "25", "group": "Scheduler", "restart_required": False,
     "desc": "Base stagger step seconds; sender_i starts after i * step."},
    {"key": "SHIVA_WAVE_STAGGER_SEED_MODE", "type": "str", "default": "job", "group": "Scheduler", "restart_required": False,
     "desc": "Stagger seed mode: job | static. job adds deterministic per-job jitter."},
    {"key": "SHIVA_WAVE_ADAPTIVE", "type": "bool", "default": "1", "group": "Scheduler", "restart_required": False,
     "desc": "Enable adaptive wave refill/burst tuning from lane metrics feedback."},
    {"key": "SHIVA_WAVE_DEFERRAL_UP", "type": "float", "default": "0.10", "group": "Scheduler", "restart_required": False,
     "desc": "Adaptive ramp-up guard: requires deferral_rate below this threshold."},
    {"key": "SHIVA_WAVE_DEFERRAL_DOWN", "type": "float", "default": "0.20", "group": "Scheduler", "restart_required": False,
     "desc": "Adaptive ramp-down threshold for provider deferral_rate."},
    {"key": "SHIVA_WAVE_HARDFAIL_DOWN", "type": "float", "default": "0.03", "group": "Scheduler", "restart_required": False,
     "desc": "Adaptive ramp-down threshold for provider hardfail_rate."},
    {"key": "SHIVA_WAVE_RAMP_UP_FACTOR", "type": "float", "default": "1.08", "group": "Scheduler", "restart_required": False,
     "desc": "Slow adaptive ramp-up multiplier for wave refill/burst."},
    {"key": "SHIVA_WAVE_RAMP_DOWN_FACTOR", "type": "float", "default": "0.70", "group": "Scheduler", "restart_required": False,
     "desc": "Fast adaptive ramp-down multiplier for wave refill/burst."},
    {"key": "SHIVA_WAVE_MIN_REFILL", "type": "float", "default": "0.5", "group": "Scheduler", "restart_required": False,
     "desc": "Lower clamp for adaptive refill_per_sec."},
    {"key": "SHIVA_WAVE_MAX_REFILL", "type": "float", "default": "10.0", "group": "Scheduler", "restart_required": False,
     "desc": "Upper clamp for adaptive refill_per_sec."},
    {"key": "SHIVA_WAVE_MIN_BURST", "type": "float", "default": "100", "group": "Scheduler", "restart_required": False,
     "desc": "Lower clamp for adaptive burst_tokens."},
    {"key": "SHIVA_WAVE_MAX_BURST", "type": "float", "default": "1200", "group": "Scheduler", "restart_required": False,
     "desc": "Upper clamp for adaptive burst_tokens."},
    {"key": "SHIVA_ROLLOUT_MODE", "type": "str", "default": "off", "group": "Scheduler", "restart_required": False,
     "desc": "Rollout mode: off | shadow | canary | on."},
    {"key": "SHIVA_CANARY_PERCENT", "type": "int", "default": "5", "group": "Scheduler", "restart_required": False,
     "desc": "Canary percentage of jobs eligible for lane_v2 when rollout mode is canary."},
    {"key": "SHIVA_CANARY_SEED_MODE", "type": "str", "default": "job_id", "group": "Scheduler", "restart_required": False,
     "desc": "Deterministic canary seed mode: job_id | campaign_id."},
    {"key": "SHIVA_CANARY_ALLOWLIST_CAMPAIGNS", "type": "str", "default": "", "group": "Scheduler", "restart_required": False,
     "desc": "Comma-separated campaign IDs forced into canary lane_v2."},
    {"key": "SHIVA_CANARY_DENYLIST_CAMPAIGNS", "type": "str", "default": "", "group": "Scheduler", "restart_required": False,
     "desc": "Comma-separated campaign IDs forced to legacy during canary."},
    {"key": "SHIVA_CANARY_ALLOWLIST_SENDERS", "type": "str", "default": "", "group": "Scheduler", "restart_required": False,
     "desc": "Comma-separated sender emails/domains forced into canary lane_v2."},
    {"key": "SHIVA_CANARY_DEBUG", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enable extra rollout/canary debug metadata in job payloads."},
    {"key": "SHIVA_SHADOW_EXPORT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Export bounded shadow-mode events to job debug payload."},
    {"key": "SHIVA_SHADOW_MAX_EVENTS", "type": "int", "default": "50", "group": "Scheduler", "restart_required": False,
     "desc": "Maximum retained shadow events per job."},
    {"key": "SHIVA_FORCE_LEGACY", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Emergency kill-switch: force legacy scheduler for all jobs."},
    {"key": "SHIVA_FORCE_DISABLE_CONCURRENCY", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Emergency kill-switch: disable lane concurrency at runtime."},
    {"key": "SHIVA_GUARDRAILS", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enable additive guardrails validator for runtime scheduler safety checks/clamps."},
    {"key": "SHIVA_GUARDRAILS_STRICT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "If enabled with guardrails, critical issues abort jobs safely before sending."},
    {"key": "SHIVA_GUARDRAILS_EXPORT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Export guardrails validation snapshot to job.debug_guardrails."},
    {"key": "SHIVA_GUARDRAILS_DEBUG", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Verbose guardrails diagnostics in job logs."},
    {"key": "SHIVA_GUARD_MAX_PARALLEL_LANES", "type": "int", "default": "8", "group": "Scheduler", "restart_required": False,
     "desc": "Guardrails safety cap for max parallel lanes per job."},
    {"key": "SHIVA_GUARD_MAX_TOTAL_WORKERS", "type": "int", "default": "80", "group": "Scheduler", "restart_required": False,
     "desc": "Guardrails safety cap for total workers."},
    {"key": "SHIVA_GUARD_MAX_WORKERS_PER_LANE", "type": "int", "default": "12", "group": "Scheduler", "restart_required": False,
     "desc": "Guardrails safety cap for per-lane workers via CapsResolver bounds."},
    {"key": "SHIVA_GUARD_MAX_CHUNK_SIZE", "type": "int", "default": "1000", "group": "Scheduler", "restart_required": False,
     "desc": "Guardrails safety cap for chunk size via CapsResolver bounds."},
    {"key": "SHIVA_GUARD_MAX_DELAY_S", "type": "float", "default": "5.0", "group": "Scheduler", "restart_required": False,
     "desc": "Guardrails safety cap for max delay seconds via CapsResolver bounds."},
    {"key": "SHIVA_GUARD_MAX_MIN_GAP_S", "type": "int", "default": "300", "group": "Scheduler", "restart_required": False,
     "desc": "Guardrails sanity cap for provider min gap seconds."},
    {"key": "SHIVA_GUARD_MAX_COOLDOWN_S", "type": "int", "default": "3600", "group": "Scheduler", "restart_required": False,
     "desc": "Guardrails sanity cap for provider cooldown seconds."},
    {"key": "SHIVA_UI_TELEMETRY", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enable additive scheduler_telemetry field in job API + Jobs UI telemetry panel."},
    {"key": "SHIVA_UI_TELEMETRY_MAX_LANES", "type": "int", "default": "30", "group": "Scheduler", "restart_required": False,
     "desc": "Max lanes included in scheduler_telemetry snapshot."},
    {"key": "SHIVA_UI_TELEMETRY_MAX_EVENTS", "type": "int", "default": "20", "group": "Scheduler", "restart_required": False,
     "desc": "Max events included in scheduler_telemetry snapshot."},
    {"key": "SHIVA_UI_TELEMETRY_DEBUG", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Verbose UI telemetry debug logging for snapshot assembly."},
    {"key": "SHIVA_LANE_ACCOUNTING_RECON", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Enable per-lane PMTA accounting reconciliation loop (ground-truth outcomes)."},
    {"key": "SHIVA_LANE_ACCOUNTING_RECON_INTERVAL_S", "type": "int", "default": "30", "group": "Scheduler", "restart_required": False,
     "desc": "Polling interval in seconds for lane accounting reconciliation during active jobs."},
    {"key": "SHIVA_LANE_ACCOUNTING_RECON_EXPORT", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Export bounded per-lane accounting reconciliation snapshot into job debug payload/UI telemetry."},
    {"key": "SHIVA_LANE_ACCOUNTING_RECON_DEBUG", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Verbose debug logging for lane accounting reconciliation."},
    {"key": "SHIVA_RUN_SELFTESTS", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Run lightweight deterministic rollout self-tests at startup."},
    {"key": "SHIVA_RUN_ACCEPTANCE_SUITE", "type": "bool", "default": "0", "group": "Scheduler", "restart_required": False,
     "desc": "Run internal end-to-end acceptance suite (deterministic, no network IO) at startup."},

    # App (restart-only)
    {"key": "SHIVA_HOST", "type": "str", "default": "0.0.0.0", "group": "App", "restart_required": True,
     "desc": "Bind host used by Flask when Shiva starts. Requires restart."},
    {"key": "SHIVA_PORT", "type": "int", "default": "5001", "group": "App", "restart_required": True,
     "desc": "Bind port used by Flask when Shiva starts. Requires restart."},
    {"key": "SHIVA_DB_PATH", "type": "str", "default": "", "group": "App", "restart_required": True,
     "desc": "Optional SQLite database path override for Shiva. Requires restart."},
    {"key": "SMTP_SENDER_DB_PATH", "type": "str", "default": "", "group": "App", "restart_required": True,
     "desc": "Legacy alias for SHIVA_DB_PATH. Requires restart."},
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


def cfg_get_first_str(keys: List[str], default: str = "") -> str:
    """Return first non-empty config value from a prioritized key list."""
    for k in (keys or []):
        v = cfg_get_str((k or "").strip(), "")
        if (v or "").strip():
            return v.strip()
    return (default or "").strip()


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


def get_env(key: str, default: str = "") -> str:
    """Direct env getter for non-UI debug/feature flags."""
    try:
        raw = os.getenv(str(key or "").strip())
        if raw is None:
            return str(default)
        return str(raw)
    except Exception:
        return str(default)


def get_env_bool(key: str, default: bool = False) -> bool:
    return _cfg_boolish(get_env(key, "1" if default else "0"))


def get_env_int(key: str, default: int = 0) -> int:
    """Direct env getter that safely parses ints for runtime feature flags."""
    try:
        return int(str(get_env(key, str(default))).strip())
    except Exception:
        return int(default)


def get_env_float(key: str, default: float = 0.0) -> float:
    """Direct env getter that safely parses floats for runtime feature flags."""
    try:
        return float(str(get_env(key, str(default))).strip())
    except Exception:
        return float(default)


def get_env_rt(key: str, default: str = "") -> str:
    """Backward-compatible alias used by older runtime paths/logging snippets."""
    return get_env(key, default)


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
        global RECIPIENT_FILTER_ENABLE_ROUTE_CHECK
        global _RBL_ZONES_RAW, _DBL_ZONES_RAW, RBL_ZONES_LIST, DBL_ZONES_LIST, SHIVA_DISABLE_BLACKLIST
        global PMTA_MONITOR_TIMEOUT_S, PMTA_MONITOR_BASE_URL, PMTA_MONITOR_SCHEME, PMTA_MONITOR_API_KEY, PMTA_HEALTH_REQUIRED
        global PMTA_DIAG_ON_ERROR, PMTA_DIAG_RATE_S, PMTA_QUEUE_TOP_N
        global PMTA_QUEUE_BACKOFF, PMTA_QUEUE_REQUIRED, SHIVA_DISABLE_BACKOFF
        global SHIVA_BACKOFF_JITTER, SHIVA_BACKOFF_JITTER_PCT, SHIVA_BACKOFF_JITTER_MAX_S, SHIVA_BACKOFF_JITTER_MIN_S
        global SHIVA_BACKOFF_JITTER_EXPORT, SHIVA_BACKOFF_JITTER_DEBUG
        global PMTA_LIVE_POLL_S, PMTA_DOMAIN_CHECK_TOP_N, PMTA_DETAIL_CACHE_TTL_S
        global PMTA_DOMAIN_DEFERRALS_BACKOFF, PMTA_DOMAIN_ERRORS_BACKOFF, PMTA_DOMAIN_DEFERRALS_SLOW, PMTA_DOMAIN_ERRORS_SLOW
        global PMTA_SLOW_DELAY_S, PMTA_SLOW_WORKERS_MAX
        global PMTA_PRESSURE_CONTROL, PMTA_PRESSURE_POLL_S
        global PMTA_DOMAIN_STATS, PMTA_DOMAINS_POLL_S, PMTA_DOMAINS_TOP_N
        global OPENROUTER_ENDPOINT, OPENROUTER_MODEL, OPENROUTER_TIMEOUT_S
        global PMTA_BRIDGE_PULL_ENABLED, BRIDGE_MODE, PMTA_BRIDGE_PULL_PORT, PMTA_BRIDGE_PULL_S, PMTA_BRIDGE_PULL_MAX_LINES
        global BRIDGE_BASE_URL, BRIDGE_POLL_INTERVAL_S, BRIDGE_POLL_FETCH_OUTCOMES, OUTCOMES_SYNC

        # Spam
        SPAMCHECK_BACKEND = (cfg_get_str("SPAMCHECK_BACKEND", "spamd") or "spamd").strip().lower()
        SPAMD_HOST = (cfg_get_str("SPAMD_HOST", "127.0.0.1") or "127.0.0.1").strip()
        SPAMD_PORT = int(cfg_get_int("SPAMD_PORT", 783))
        SPAMD_TIMEOUT = float(cfg_get_float("SPAMD_TIMEOUT", 5.0))

        # Recipient filter
        RECIPIENT_FILTER_ENABLE_ROUTE_CHECK = bool(
            cfg_get_bool("RECIPIENT_FILTER_ENABLE_ROUTE_CHECK", bool(RECIPIENT_FILTER_ENABLE_ROUTE_CHECK))
        )

        # DNSBL
        _RBL_ZONES_RAW = (cfg_get_str("RBL_ZONES", "zen.spamhaus.org,bl.spamcop.net,cbl.abuseat.org") or "").strip()
        _DBL_ZONES_RAW = (cfg_get_str("DBL_ZONES", "dbl.spamhaus.org") or "").strip()
        RBL_ZONES_LIST = _parse_zones(_RBL_ZONES_RAW)
        DBL_ZONES_LIST = _parse_zones(_DBL_ZONES_RAW)
        SHIVA_DISABLE_BLACKLIST = bool(cfg_get_bool("SHIVA_DISABLE_BLACKLIST", SHIVA_DISABLE_BLACKLIST))
        if SHIVA_DISABLE_BLACKLIST:
            _log_blacklist_disabled_once()

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
        SHIVA_DISABLE_BACKOFF = bool(cfg_get_bool("SHIVA_DISABLE_BACKOFF", False))
        SHIVA_BACKOFF_JITTER = (cfg_get_str("SHIVA_BACKOFF_JITTER", SHIVA_BACKOFF_JITTER) or SHIVA_BACKOFF_JITTER).strip().lower()
        if SHIVA_BACKOFF_JITTER not in {"off", "deterministic", "random"}:
            SHIVA_BACKOFF_JITTER = "off"
        SHIVA_BACKOFF_JITTER_PCT = max(0.0, float(cfg_get_float("SHIVA_BACKOFF_JITTER_PCT", SHIVA_BACKOFF_JITTER_PCT)))
        SHIVA_BACKOFF_JITTER_MAX_S = max(0.0, float(cfg_get_float("SHIVA_BACKOFF_JITTER_MAX_S", SHIVA_BACKOFF_JITTER_MAX_S)))
        SHIVA_BACKOFF_JITTER_MIN_S = max(0.0, float(cfg_get_float("SHIVA_BACKOFF_JITTER_MIN_S", SHIVA_BACKOFF_JITTER_MIN_S)))
        SHIVA_BACKOFF_JITTER_EXPORT = bool(cfg_get_bool("SHIVA_BACKOFF_JITTER_EXPORT", SHIVA_BACKOFF_JITTER_EXPORT))
        SHIVA_BACKOFF_JITTER_DEBUG = bool(cfg_get_bool("SHIVA_BACKOFF_JITTER_DEBUG", SHIVA_BACKOFF_JITTER_DEBUG))
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
        BRIDGE_MODE = (cfg_get_str("BRIDGE_MODE", BRIDGE_MODE) or BRIDGE_MODE).strip().lower()
        if BRIDGE_MODE not in {"counts", "legacy"}:
            BRIDGE_MODE = "counts"
        PMTA_BRIDGE_PULL_PORT = int(cfg_get_int("PMTA_BRIDGE_PULL_PORT", int(PMTA_BRIDGE_PULL_PORT or 8090)))
        PMTA_BRIDGE_PULL_S = float(cfg_get_float("PMTA_BRIDGE_PULL_S", float(PMTA_BRIDGE_PULL_S or 5.0)))
        BRIDGE_BASE_URL = (cfg_get_str("BRIDGE_BASE_URL", BRIDGE_BASE_URL) or BRIDGE_BASE_URL).strip()
        BRIDGE_POLL_INTERVAL_S = float(cfg_get_float("BRIDGE_POLL_INTERVAL_S", float(PMTA_BRIDGE_PULL_S or BRIDGE_POLL_INTERVAL_S or 5.0)))
        OUTCOMES_SYNC = bool(cfg_get_bool("OUTCOMES_SYNC", bool(OUTCOMES_SYNC)))
        BRIDGE_POLL_FETCH_OUTCOMES = bool(cfg_get_bool("BRIDGE_POLL_FETCH_OUTCOMES", bool(OUTCOMES_SYNC)))
        OUTCOMES_SYNC = bool(BRIDGE_POLL_FETCH_OUTCOMES)
        PMTA_BRIDGE_PULL_MAX_LINES = int(cfg_get_int("PMTA_BRIDGE_PULL_MAX_LINES", int(PMTA_BRIDGE_PULL_MAX_LINES or 2000)))

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

if bool(get_env_bool("SHIVA_RUN_SELFTESTS", False)):
    try:
        _selftest_logs = _run_rollout_selftests()
        logging.getLogger("shiva").info("Rollout self-tests passed: %s", ",".join(_selftest_logs))
    except Exception as _selftest_exc:
        logging.getLogger("shiva").error("Rollout self-tests failed: %s", _selftest_exc)

if bool(get_env_bool("SHIVA_RUN_ACCEPTANCE_SUITE", False)):
    try:
        _acceptance_logs = run_acceptance_suite()
        _msg = "Acceptance suite PASS ({}): {}".format(len(_acceptance_logs), ",".join(_acceptance_logs))
        print(_msg)
        logging.getLogger("shiva").info(_msg)
    except Exception as _acceptance_exc:
        _msg = f"Acceptance suite FAIL: {_acceptance_exc}"
        print(_msg)
        logging.getLogger("shiva").error(_msg)


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
    resp = make_response(render_template_string(PAGE_FORM, campaign_id=c["id"], campaign_name=c["name"]))
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


def build_scheduler_telemetry_snapshot(job: 'SendJob') -> dict:
    """Build bounded, read-only scheduler telemetry for Jobs UI."""
    now_ts = time.time()

    def _env_int(key: str, default: int) -> int:
        try:
            return int(get_env(key, str(default)))
        except Exception:
            return int(default)

    max_lanes = max(1, min(100, _env_int("SHIVA_UI_TELEMETRY_MAX_LANES", 30)))
    max_events = max(1, min(100, _env_int("SHIVA_UI_TELEMETRY_MAX_EVENTS", 20)))
    telemetry_debug = bool(get_env_bool("SHIVA_UI_TELEMETRY_DEBUG", False))

    lane_metrics = getattr(job, "debug_lane_metrics_snapshot", {}) or {}
    lane_states = getattr(job, "debug_lane_states_snapshot", {}) or {}
    budget_status = getattr(job, "debug_budget_status", {}) or {}
    lane_executor = getattr(job, "debug_lane_executor", {}) or {}
    fallback = getattr(job, "debug_fallback", {}) or {}
    provider_canon = getattr(job, "debug_provider_canon", {}) or {}
    shadow_events = list(getattr(job, "debug_shadow_events", []) or [])
    rollout = getattr(job, "debug_rollout", {}) or {}
    effective_plan = getattr(job, "debug_effective_plan", {}) or {}
    wave_status = getattr(job, "debug_wave_status", {}) or {}
    last_caps = getattr(job, "debug_last_caps_resolve", {}) or {}
    probe_status = getattr(job, "debug_probe_status", {}) or {}
    accounting_recon = getattr(job, "debug_lane_accounting", {}) or {}

    lane_rows: List[dict] = []
    metrics_lanes = (lane_metrics.get("lanes") if isinstance(lane_metrics, dict) else {}) or {}
    state_lanes = (lane_states.get("lanes") if isinstance(lane_states, dict) else {}) or {}
    inflight_by_lane = {}
    inflight_list = list((lane_executor.get("inflight_lanes") if isinstance(lane_executor, dict) else []) or [])
    for item in inflight_list:
        lid = str(item.get("lane") or "")
        if lid:
            inflight_by_lane[lid] = item

    denial_by_lane = {}
    for den in list((budget_status.get("last_denied_reasons") if isinstance(budget_status, dict) else []) or [])[-max_events:]:
        lid = str((den or {}).get("lane") or "")
        if lid:
            denial_by_lane[lid] = str((den or {}).get("reason") or "")

    all_lane_ids = sorted(set(list(metrics_lanes.keys()) + list(state_lanes.keys())))
    for lane_id in all_lane_ids:
        m = metrics_lanes.get(lane_id) if isinstance(metrics_lanes.get(lane_id), dict) else {}
        st = state_lanes.get(lane_id) if isinstance(state_lanes.get(lane_id), dict) else {}
        sender_idx = int(st.get("sender_idx") or m.get("sender_idx") or 0)
        provider = str(st.get("provider_domain") or m.get("provider_domain") or "")
        next_allowed_ts = float(st.get("next_allowed_ts") or 0.0)
        seconds_remaining = max(0.0, next_allowed_ts - now_ts) if next_allowed_ts > 0 else 0.0
        rec_caps = st.get("recommended_caps") if isinstance(st.get("recommended_caps"), dict) else {}
        learning_caps = st.get("recommended_caps_learning") if isinstance(st.get("recommended_caps_learning"), dict) else {}
        final_caps = (last_caps.get("final") if isinstance(last_caps, dict) else {}) or {}
        inflight_item = inflight_by_lane.get(lane_id) or {}
        lane_rows.append({
            "lane_id": lane_id,
            "sender_idx": sender_idx,
            "sender_label": str(st.get("sender_label") or m.get("sender_email") or f"sender#{sender_idx}"),
            "provider_domain": provider,
            "state": str(st.get("state") or "HEALTHY"),
            "next_allowed_ts": next_allowed_ts,
            "seconds_remaining": round(seconds_remaining, 1),
            "deferral_rate": float(st.get("deferral_rate") or m.get("deferral_rate") or 0.0),
            "hardfail_rate": float(st.get("hardfail_rate") or m.get("hardfail_rate") or 0.0),
            "timeout_rate": float(st.get("timeout_rate") or m.get("timeout_rate") or 0.0),
            "blocked_events": int(st.get("blocked_events") or m.get("blocked_events") or 0),
            "backoff_scheduled_count": int(m.get("backoff_events") or 0),
            "last_error_samples": list((st.get("recent_error_samples") or m.get("last_error_samples") or [])[-3:]),
            "recommended_caps": {
                "lane": rec_caps,
                "learning": learning_caps,
            },
            "final_caps": final_caps,
            "inflight": bool(inflight_item),
            "started_ts": float(inflight_item.get("started_ts") or 0.0),
            "last_denial_reason": denial_by_lane.get(lane_id, ""),
            "last_reason": str(st.get("last_reason") or ""),
        })

    state_rank = {"QUARANTINED": 0, "INFRA_FAIL": 0, "THROTTLED": 1, "HEALTHY": 2}
    lane_rows.sort(key=lambda x: (
        state_rank.get(str(x.get("state") or "HEALTHY"), 3),
        0 if x.get("inflight") else 1,
        -float(x.get("deferral_rate") or 0.0),
        -float(x.get("seconds_remaining") or 0.0),
        str(x.get("lane_id") or ""),
    ))

    provider_groups = provider_canon.get("provider_groups") if isinstance(provider_canon, dict) else {}
    fallback_reasons = list((fallback.get("reasons") if isinstance(fallback, dict) else []) or [])[-max_events:]
    recent_completions = list((lane_executor.get("recent_completions") if isinstance(lane_executor, dict) else []) or [])[-max_events:]
    bounded_offsets = list(sorted(((wave_status.get("next_allowed_ts_by_sender") if isinstance(wave_status, dict) else {}) or {}).items(), key=lambda kv: kv[0]))[:max_lanes]

    out = {
        "rollout": {
            "effective_mode": str(rollout.get("effective_mode") or rollout.get("selected_mode") or "legacy"),
            "is_canary": bool(rollout.get("is_canary") or rollout.get("selected_mode") == "canary"),
            "is_shadow": bool(rollout.get("is_shadow") or rollout.get("selected_mode") == "shadow"),
            "force_legacy": bool(rollout.get("force_legacy") or False),
            "force_disable_concurrency": bool(rollout.get("force_disable_concurrency") or False),
        },
        "scheduler": {
            "mode": str(effective_plan.get("scheduler_mode") or ("lane_v2" if bool(rollout.get("lane_v2_enabled") or rollout.get("effective_mode") in {"on", "canary", "shadow"}) else "legacy")),
            "concurrency_enabled": bool(effective_plan.get("concurrency_enabled") or rollout.get("lane_concurrency_enabled") or False),
            "max_parallel_lanes": int(rollout.get("max_parallel_lanes") or 1),
            "effective_plan": dict(effective_plan or {}),
        },
        "probe": {
            "active": bool(probe_status.get("probe_active") or probe_status.get("active") or False),
            "rounds_remaining": int(probe_status.get("rounds_remaining") or 0),
            "duration_left_s": float(probe_status.get("duration_left_s") or 0.0),
        },
        "fallback": {
            "active": bool(fallback.get("active") or False),
            "reasons": fallback_reasons,
            "triggered_ts": float(fallback.get("triggered_ts") or 0.0),
            "actions_taken": list((fallback.get("actions_taken") if isinstance(fallback, dict) else []) or [])[-max_events:],
        },
        "wave": {
            "enabled": bool(wave_status.get("enabled") or False),
            "provider_domain": str(wave_status.get("provider_domain") or ""),
            "tokens_current": float(wave_status.get("tokens_current") or 0.0),
            "refill_per_sec": float(wave_status.get("refill_per_sec") or 0.0),
            "burst_tokens": float(wave_status.get("burst_tokens") or 0.0),
            "stagger_offsets": [{"sender_idx": str(k), "next_allowed_ts": float(v)} for k, v in bounded_offsets],
        },
        "caps_resolver": {
            "enabled": bool(last_caps),
            "final": dict((last_caps.get("final") if isinstance(last_caps, dict) else {}) or {}),
            "applied_clamps": list((last_caps.get("applied_clamps") if isinstance(last_caps, dict) else []) or [])[-max_events:],
        },
        "provider_canonicalization": {
            "enabled": bool(provider_canon.get("enabled") if isinstance(provider_canon, dict) else False),
            "groups": dict(provider_groups or {}),
        },
        "accounting_recon": {
            "enabled": bool(accounting_recon),
            "last_recon_ts": str(accounting_recon.get("last_recon_ts") or ""),
            "lines_processed_total": int(accounting_recon.get("lines_processed_total") or 0),
            "lines_processed_delta": int(accounting_recon.get("lines_processed_delta") or 0),
            "providers": list((accounting_recon.get("providers") if isinstance(accounting_recon, dict) else []) or [])[:20],
            "lanes": list((accounting_recon.get("lanes") if isinstance(accounting_recon, dict) else []) or [])[:max_lanes],
        },
        "lanes": lane_rows[:max_lanes],
        "executor": {
            "enabled": bool(lane_executor),
            "inflight_lanes": inflight_list[:max_lanes],
            "recent_completions": recent_completions,
        },
        "events": {
            "fallback_reasons": fallback_reasons,
            "shadow_events": shadow_events[-max_events:],
            "executor_recent": recent_completions,
        },
    }
    if telemetry_debug:
        out["_debug"] = {
            "total_lanes_seen": len(all_lane_ids),
            "max_lanes": max_lanes,
            "max_events": max_events,
        }
    return out


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

        with _BRIDGE_DEBUG_LOCK:
            bridge_state = dict(_BRIDGE_DEBUG_STATE)

        # Dashboard/API outcome counters must come from SQLite (source of truth).
        _sync_job_outcome_counters_from_db(job)

        total_recent = len(job.recent_results or [])
        recent_total_pages = max(1, math.ceil(total_recent / recent_page_size))
        recent_page = min(recent_page, recent_total_pages)
        end_idx = total_recent - ((recent_page - 1) * recent_page_size)
        start_idx = max(0, end_idx - recent_page_size)
        recent_page_rows = (job.recent_results or [])[start_idx:end_idx]
        recent_page_rows.reverse()  # newest first within current page

        provider_breakdown = _job_provider_breakdown(job.id, limit=8)
        provider_reason_buckets = dict(job.accounting_error_counts or {})
        internal_samples = list(bridge_state.get("internal_error_samples") or [])[-10:]
        integrity_samples = list(bridge_state.get("integrity_samples") or [])[-10:]

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
                "debug_lane_accounting": job.debug_lane_accounting or {},
                "internal_error_counts": job.internal_error_counts,
                "internal_last_errors": (job.internal_last_errors or [])[-20:],
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
                "debug_backoff_jitter": (job.debug_backoff_jitter or [])[-50:],
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
                "bridge_mode": str(getattr(job, "bridge_mode", "") or BRIDGE_MODE or "counts"),
                "accounting_last_update_ts": job.accounting_last_ts,
                "bridge_last_success_ts": str(bridge_state.get("last_success_ts") or ""),
                "bridge_failure_count": int(bridge_state.get("failure_count") or 0),
                "bridge_last_error_message": str(bridge_state.get("last_error_message") or ""),
                "bridge_last_cursor": str(bridge_state.get("last_cursor") or ""),
                "bridge_has_more": bool(bridge_state.get("has_more") or False),
                "ingestion_last_event_ts": job.accounting_last_ts,
                "ingestion_lag_seconds": None,
                "received": int(bridge_state.get("events_received") or 0),
                "ingested": int(bridge_state.get("events_ingested") or 0),
                "duplicates_dropped": int(bridge_state.get("duplicates_dropped") or 0),
                "job_not_found": int(bridge_state.get("job_not_found") or 0),
                "db_write_failures": int(bridge_state.get("db_write_failures") or 0),
                "missing_fields": int(bridge_state.get("missing_fields") or 0),
                "provider_breakdown": provider_breakdown,
                "provider_reason_buckets": provider_reason_buckets,
                "internal_last_samples": internal_samples,
                "integrity_last_samples": integrity_samples,
                **({"scheduler_telemetry": build_scheduler_telemetry_snapshot(job)} if bool(get_env_bool("SHIVA_UI_TELEMETRY", False)) else {}),
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
    """Compute sender-domain states for this campaign (reads sender emails from SQLite).

    Domain States = sender domains used for sending (from-address domains), not recipient domains.
    """
    bid, is_new = get_or_create_browser_id()
    cid = (campaign_id or "").strip()
    c = db_get_campaign(bid, cid)
    if not c:
        resp = jsonify({"ok": False, "error": "campaign not found"})
        return attach_browser_cookie(resp, bid, is_new), 404

    form = db_get_campaign_form(bid, cid)
    sender_text = str((form or {}).get("from_email") or "")
    parsed = sender_domain_counts(sender_text)
    domains = compute_sender_domain_states(parsed.get("counts") or {})

    payload = {
        "total_emails": int(parsed.get("emails_total") or 0),
        "invalid_emails": int(parsed.get("emails_invalid") or 0),
        "unique_domains": len(parsed.get("counts") or {}),
        "domains": domains,
        "filter": {
            "checks": ["sender_domain", "mx", "dnsbl", "spf", "dkim", "dmarc"],
            "kept": int(len(parsed.get("valid_emails") or [])),
            "dropped": int(parsed.get("emails_invalid") or 0),
            "smtp_probe_used": 0,
            "smtp_probe_limit": 0,
        },
    }

    # Backward-compatible response keys (`recipients` / `safe`) are preserved.
    resp = jsonify({"ok": True, "campaign": {"id": c["id"], "name": c["name"]}, "recipients": payload, "safe": payload})
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


@app.get("/api/learning/summary")
def api_learning_summary():
    try:
        limit = int((request.args.get("limit") or "25").strip())
    except Exception:
        limit = 25
    return jsonify({"ok": True, "summary": db_learning_summary(limit=limit)})


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
            if db_set_app_config(key, canon):
                saved += 1
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

    if not db_set_app_config(key, canon):
        return jsonify({"ok": False, "error": "failed to save"}), 500

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
    sender_text = str(data.get("from_email") or "")
    parsed = sender_domain_counts(sender_text)
    payload = {
        "total_emails": int(parsed.get("emails_total") or 0),
        "invalid_emails": int(parsed.get("emails_invalid") or 0),
        "unique_domains": len(parsed.get("counts") or {}),
        "domains": compute_sender_domain_states(parsed.get("counts") or {}),
    }
    return jsonify({"ok": True, "recipients": payload, "safe": payload})


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
    domain = _extract_domain_from_email(from_email)

    if SHIVA_DISABLE_BLACKLIST:
        _log_blacklist_disabled_once()
        ip_listings = {ip: [] for ip in ips}
        domain_listings = []
    else:
        ip_listings = {ip: check_ip_dnsbl(ip) for ip in ips}
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

    if SHIVA_DISABLE_BLACKLIST:
        sender_domain_ips = {d: [] for d in sender_domains}
        sender_domain_ip_listings = {d: {} for d in sender_domains}
        sender_domain_dbl_listings = {d: [] for d in sender_domains}
    else:
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
            "rbl_zones": ([] if SHIVA_DISABLE_BLACKLIST else RBL_ZONES_LIST),
            "dbl_zones": ([] if SHIVA_DISABLE_BLACKLIST else DBL_ZONES_LIST),
            "blacklist_check_disabled": bool(SHIVA_DISABLE_BLACKLIST),
        }
    )


@app.get("/api/accounting/bridge/status")
def api_accounting_bridge_status():
    """Expose lightweight bridge polling health and per-job accounting snapshots."""
    with _BRIDGE_DEBUG_LOCK:
        state = dict(_BRIDGE_DEBUG_STATE)
    base_url = _resolve_bridge_base_url_runtime()
    poll_interval = float(BRIDGE_POLL_INTERVAL_S or PMTA_BRIDGE_PULL_S or 0)
    timeout = float(BRIDGE_TIMEOUT_S or 0)

    jobs: List[Dict[str, Any]] = []
    active_jobs = _active_jobs_for_bridge_poll()
    for job in active_jobs:
        delivered = int(getattr(job, "delivered", 0) or 0)
        deferred = int(getattr(job, "deferred", 0) or 0)
        bounced = int(getattr(job, "bounced", 0) or 0)
        complained = int(getattr(job, "complained", 0) or 0)
        jobs.append(
            {
                "pmta_job_id": _job_pmta_job_id(job),
                "counts": {
                    "linked_emails_count": delivered + deferred + bounced + complained,
                    "delivered_count": delivered,
                    "deferred_count": deferred,
                    "bounced_count": bounced,
                    "complained_count": complained,
                },
                "last_update_time": str(getattr(job, "accounting_last_ts", "") or ""),
                "outcomes_sync_enabled": bool(BRIDGE_POLL_FETCH_OUTCOMES),
            }
        )

    status = {
        "bridge_base_url": base_url,
        "poll_interval": poll_interval,
        "timeout": timeout,
        "last_ok_ts": str(state.get("last_ok_ts") or ""),
        "last_error_ts": str(state.get("last_error_ts") or ""),
        "last_error_message": str(state.get("last_error_message") or ""),
        "jobs": jobs,
    }

    state.update(status)
    state["pull_enabled"] = bool(PMTA_BRIDGE_PULL_ENABLED)
    state["bridge_mode"] = str(BRIDGE_MODE or "counts")
    state["pull_interval_s"] = poll_interval
    state["pull_max_lines"] = int(PMTA_BRIDGE_PULL_MAX_LINES or 0)
    return jsonify({"ok": True, **status, "bridge": state})


@app.post("/api/accounting/bridge/pull")
def api_accounting_bridge_pull_once():
    """Manual pull from bridge endpoint (same processing path as periodic poller)."""
    if not _resolve_bridge_base_url_runtime():
        return jsonify({"ok": False, "error": "bridge base URL is not configured"}), 400
    result = _poll_accounting_bridge_once()
    if not result.get("ok") and str(result.get("reason") or "") == "busy":
        return jsonify(result), 409
    return jsonify(result)


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
    normalized_recipients, rcpt_invalid_count, rcpt_dedup_count = normalize_recipients_for_sending(recipients)
    valid, invalid = filter_valid_emails(normalized_recipients)
    syntax_valid = list(valid)

    # Safe list (optional whitelist)
    safe_text = request.form.get("maillist_safe") or ""
    safe_raw = parse_recipients(safe_text)
    safe_valid, safe_invalid = filter_valid_emails(safe_raw)

    # Pre-send filter: run recipients + safe list validation in parallel.
    recipient_filter: Dict[str, Any]
    safe_filter: Dict[str, Any]
    mx_invalid: List[str]
    safe_mx_invalid: List[str]
    with ThreadPoolExecutor(max_workers=2) as _preflight_pool:
        _future_rcpt = _preflight_pool.submit(pre_send_recipient_filter, valid, smtp_probe=True)
        _future_safe = _preflight_pool.submit(pre_send_recipient_filter, safe_valid, smtp_probe=True)
        valid, mx_invalid, recipient_filter = _future_rcpt.result()
        safe_valid, safe_mx_invalid, safe_filter = _future_safe.result()

    if mx_invalid:
        invalid.extend(mx_invalid)
    if safe_mx_invalid:
        safe_invalid.extend(safe_mx_invalid)

    invalid_total_count = int(rcpt_invalid_count) + len(invalid)

    # Safety fallback: if DNS/probe temporarily rejects everything, do not hard-block
    # a send that already passed syntax validation. This avoids false negatives after
    # transient resolver/provider issues and lets runtime delivery decide.
    if syntax_valid and not valid:
        valid = syntax_valid
        recipient_filter = {**recipient_filter, "degraded_fallback": True, "degraded_reason": "all_filtered_by_route_checks"}

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
        return f"No valid recipients found. Invalid count={invalid_total_count}. Examples: {sample}", 400

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
        pmta_job_id=job_id,
        bridge_mode=str(BRIDGE_MODE or "counts"),
        smtp_host=smtp_host,
        total=len(valid),
        invalid=invalid_total_count,
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

    # Domain States pre-start check scope:
    # sender domains used for sending (from-address domains), not recipient domains.
    sender_counts: Dict[str, int] = {}
    for em in valid_sender_emails:
        d = _extract_domain_from_email(em)
        if not d:
            continue
        sender_counts[d] = sender_counts.get(d, 0) + 1
    sender_domain_states = compute_sender_domain_states(sender_counts)

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
    job.log("INFO", f"Accepted {len(valid)} valid recipients, {invalid_total_count} invalid recipients filtered, deduplicated={rcpt_dedup_count}.")
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
        "Domain States scope: sender domains used for sending (from-address domains), not recipient domains.",
    )
    if sender_domain_states:
        listed_domains = [x.get("domain") for x in sender_domain_states if x.get("listed")]
        job.log(
            "INFO",
            f"Sender-domain precheck: domains={len(sender_domain_states)} listed={len(listed_domains)} "
            f"spf_pass={sum(1 for x in sender_domain_states if ((x.get('spf') or {}).get('status') == 'pass'))} "
            f"dmarc_pass={sum(1 for x in sender_domain_states if ((x.get('dmarc') or {}).get('status') == 'pass'))} "
            f"dkim_pass={sum(1 for x in sender_domain_states if ((x.get('dkim') or {}).get('status') == 'pass'))}.",
        )

    job.log(
        "INFO",
        f"Sender inputs: names={len(from_names)} emails_valid={len(valid_sender_emails)} emails_invalid={len(invalid_sender_emails)} subjects={len(subjects)}. "
        f"Sending mode: provider-aware round-robin chunks (one recipient-domain chunk -> one sender email/IP rotation).",
    )
    job.log(
        "INFO",
        f"Chunk controls: chunk_size={chunk_size} workers={thread_workers} sleep_between_chunks={sleep_chunks}s delay_between_messages={delay_s}s",
    )

    with JOBS_LOCK:
        JOBS[job_id] = job

    seeded_count = db_seed_job_recipient_index(job_id, campaign_id, valid)
    job.log("INFO", f"Recipient indexing initialized: total={seeded_count} status=not_yet.")

    # Persist job immediately (so it appears in Jobs even after refresh)
    job.maybe_persist(force=True)

    t = threading.Thread(
        target=smtp_send_job_thread_entry,
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
            use_ai,
            ai_token,
        ),
    )
    t.start()

    return redirect(url_for("job_page", job_id=job_id))


if __name__ == "__main__":
    # For local use. In production, use a real WSGI server (gunicorn/waitress).
    host = (os.getenv("SHIVA_HOST", "0.0.0.0") or "0.0.0.0").strip()
    try:
        port = int((os.getenv("SHIVA_PORT", "5001") or "5001").strip())
    except Exception:
        port = 5001
    app.run(host=host, port=port, debug=True)
