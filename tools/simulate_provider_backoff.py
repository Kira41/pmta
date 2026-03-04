#!/usr/bin/env python3
"""Simple simulation for Shiva provider-aware chunk scheduling + backoff.

This script mirrors the key behaviors implemented in `shiva.py`:
- recipients grouped by recipient domain (provider buckets)
- round-robin chunk scheduling between domains
- sender rotation per provider/domain and per retry attempt
- exponential backoff for blocked chunks
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple


def domain_of(email: str) -> str:
    return (email.split("@", 1)[1].strip().lower() if "@" in email else "unknown")


def build_provider_buckets(recipients: List[str]) -> Tuple[Dict[str, List[str]], List[str]]:
    buckets: Dict[str, List[str]] = {}
    order: List[str] = []
    for rcpt in recipients:
        dom = domain_of(rcpt)
        if dom not in buckets:
            buckets[dom] = []
            order.append(dom)
        buckets[dom].append(rcpt)
    return buckets, order


@dataclass
class SimConfig:
    chunk_size: int = 3
    max_backoff_retries: int = 3
    backoff_base_s: int = 60
    backoff_max_s: int = 1800


def simulate() -> dict:
    # Sender pool (multiple sender domains)
    sender_emails = [
        "ops@alpha-mail.com",
        "mailer@beta-delivery.net",
        "notify@gamma-send.org",
    ]

    # Mixed recipient domains/providers
    recipients = [
        "u01@gmail.com", "u02@gmail.com", "u03@gmail.com", "u04@gmail.com", "u05@gmail.com",
        "u06@yahoo.com", "u07@yahoo.com", "u08@yahoo.com", "u09@yahoo.com",
        "u10@hotmail.com", "u11@hotmail.com", "u12@hotmail.com",
        "u13@aol.com", "u14@aol.com", "u15@aol.com",
    ]

    cfg = SimConfig()
    buckets, order = build_provider_buckets(recipients)

    provider_cursor = 0
    provider_sender_cursor: Dict[str, int] = {}
    timeline: List[dict] = []
    stats = {
        "delivered": 0,
        "deferred": 0,
        "abandoned_chunks": 0,
        "chunks_done": 0,
        "chunks_backoff": 0,
    }

    # Scenario: Yahoo provider is temporarily unstable for first 2 attempts per chunk.
    # Attempt 0/1 => blocked (deferred wave). Attempt 2 => recovers and sends.
    yahoo_block_until_attempt = 1

    def next_domain() -> str | None:
        nonlocal provider_cursor
        if not order:
            return None
        n = len(order)
        for step in range(n):
            idx = (provider_cursor + step) % n
            dom = order[idx]
            if buckets.get(dom):
                provider_cursor = (idx + 1) % n
                return dom
        return None

    t = 0
    chunk_idx = 0
    while True:
        dom = next_domain()
        if dom is None:
            break

        bucket = buckets.get(dom, [])
        chunk = bucket[: cfg.chunk_size]
        buckets[dom] = bucket[cfg.chunk_size :]

        sender_base = provider_sender_cursor.get(dom, 0)
        attempt = 0

        while True:
            sender = sender_emails[(sender_base + attempt) % len(sender_emails)]
            blocked = (dom == "yahoo.com" and attempt <= yahoo_block_until_attempt)

            if blocked:
                stats["chunks_backoff"] += 1
                stats["deferred"] += len(chunk)
                attempt += 1
                if attempt > cfg.max_backoff_retries:
                    stats["abandoned_chunks"] += 1
                    stats["chunks_done"] += 1
                    timeline.append(
                        {
                            "t": t,
                            "chunk": chunk_idx,
                            "domain": dom,
                            "attempt": attempt,
                            "action": "abandoned",
                            "sender": sender,
                            "size": len(chunk),
                        }
                    )
                    break

                wait_s = min(cfg.backoff_max_s, cfg.backoff_base_s * (2 ** (attempt - 1)))
                timeline.append(
                    {
                        "t": t,
                        "chunk": chunk_idx,
                        "domain": dom,
                        "attempt": attempt,
                        "action": "backoff",
                        "reason": "pmta=high deferrals on yahoo.com",
                        "wait_s": wait_s,
                        "sender": sender,
                        "size": len(chunk),
                    }
                )
                t += wait_s
                continue

            stats["delivered"] += len(chunk)
            stats["chunks_done"] += 1
            timeline.append(
                {
                    "t": t,
                    "chunk": chunk_idx,
                    "domain": dom,
                    "attempt": attempt,
                    "action": "sent",
                    "sender": sender,
                    "size": len(chunk),
                }
            )
            provider_sender_cursor[dom] = (sender_base + 1) % len(sender_emails)
            t += 3
            break

        chunk_idx += 1

    domain_totals: Dict[str, int] = {}
    for r in recipients:
        d = domain_of(r)
        domain_totals[d] = domain_totals.get(d, 0) + 1

    return {
        "config": cfg.__dict__,
        "sender_emails": sender_emails,
        "domain_totals": domain_totals,
        "stats": stats,
        "timeline": timeline,
    }


if __name__ == "__main__":
    import json

    out = simulate()
    print(json.dumps(out, ensure_ascii=False, indent=2))
