from __future__ import annotations

import copy
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, render_template_string, url_for

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
SEND_PAGE_HTML = (BASE_DIR / "shivamini_send_dashboard.html").read_text(encoding="utf-8")

# ---------------------------------------------------------------------------
# Fake data seed
# ---------------------------------------------------------------------------
NOW = datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


DASHBOARD_DATA = {
    "app_name": "Shivamini Frontend Sandbox",
    "campaign": {
        "id": "cmp-demo-001",
        "name": "Ramadan Promo · Demo Campaign",
        "status": "running",
        "owner": "demo@shivamini.local",
        "created_at": iso(NOW - timedelta(days=4, hours=2)),
        "updated_at": iso(NOW - timedelta(minutes=3)),
    },
    "kpis": [
        {"label": "Total Recipients", "value": "48,250", "tone": "neutral", "hint": "Loaded from fake campaign audience."},
        {"label": "Delivered", "value": "41,932", "tone": "good", "hint": "Simulated delivered outcomes."},
        {"label": "Deferred", "value": "2,104", "tone": "warn", "hint": "Temporary soft deferrals."},
        {"label": "Bounced", "value": "1,188", "tone": "bad", "hint": "Hard/soft bounce sample total."},
        {"label": "Complaints", "value": "67", "tone": "bad", "hint": "Complaint placeholder metric."},
        {"label": "Spam Score", "value": "2.6 / 10", "tone": "good", "hint": "Fake preflight result."},
        {"label": "Blacklist Health", "value": "2 listed", "tone": "warn", "hint": "Demo DNSBL result."},
        {"label": "Live Queue", "value": "3,842", "tone": "accent", "hint": "Simulated PMTA queue count."},
    ],
    "progress": {
        "overall": 86,
        "domain": 79,
        "chunks": 68,
        "warmup": 91,
    },
    "alerts": [
        {"title": "Adaptive throttle active", "body": "Yahoo lane was slowed down after repeated 4xx responses.", "tone": "warn"},
        {"title": "Bridge connected", "body": "Accounting bridge last synced 22 seconds ago.", "tone": "good"},
        {"title": "Two sender domains listed", "body": "mail-demo.net appears in a fake DNSBL sample.", "tone": "bad"},
    ],
    "preflight": {
        "spam_score": 2.6,
        "spam_limit": 4.0,
        "backend": "SpamAssassin (fake)",
        "smtp_host": "pmta.demo.internal",
        "sender_domains": [
            {"domain": "brand-alpha.com", "ips": ["198.51.100.21", "198.51.100.22"], "status": "Not listed", "spam_score": 2.1},
            {"domain": "brand-beta.net", "ips": ["203.0.113.80"], "status": "Listed", "spam_score": 4.4},
            {"domain": "offers-demo.org", "ips": ["203.0.113.110"], "status": "Not listed", "spam_score": 3.0},
        ],
    },
    "excel_info": {
        "file_name": "ramadan-demo-recipients.xlsx",
        "sheet_name": "Audience_Master",
        "rows_total": "48,250",
        "validated_rows": "47,901",
        "suppressed_rows": "349",
        "columns": [
            {"name": "email", "description": "Primary recipient email used to build the fake send queue."},
            {"name": "first_name", "description": "Used with [NAME] and personalization previews inside the HTML body."},
            {"name": "segment", "description": "Maps each row to a campaign slice such as VIP, warm, or re-engagement."},
            {"name": "sender_hint", "description": "Optional sender-domain hint used by the routing preview in Mini Shiva."},
        ],
        "checks": [
            "Accepts .xlsx uploads with one audience sheet or multiple segment sheets.",
            "Normalizes headers automatically before fake preview mapping.",
            "Flags duplicate emails, missing domains, and suppressed rows before send.",
            "Exports a cleaned CSV snapshot for operators to review before starting jobs.",
        ],
    },
    "message_form": {
        "smtp_host": "pmta.demo.internal",
        "smtp_port": 2525,
        "smtp_security": "starttls",
        "smtp_user": "mailer-demo",
        "smtp_timeout": 25,
        "ssh_host": "ops.demo.internal",
        "ssh_port": 22,
        "ssh_user": "pmtaops",
        "ssh_timeout": 8,
        "from_name": "Shivamini Team\nOffers Robot",
        "from_email": "hello@brand-alpha.com\ninfo@brand-beta.net",
        "subject": "Your dashboard demo is ready\nLast chance to review the sandbox",
        "body_format": "html",
        "reply_to": "support@brand-alpha.com",
        "score_range": 4.0,
        "body": "<h1>Hello [NAME]</h1><p>This is a fake preview body for the Shivamini frontend skeleton.</p>",
        "urls_list": "https://brand-alpha.com/demo\nhttps://brand-beta.net/offer",
        "src_list": "https://picsum.photos/seed/shivamini-1/600/240\nhttps://picsum.photos/seed/shivamini-2/600/240",
        "recipients": "amira@example.com\nomar@example.com\nlayla@example.com",
        "maillist_safe": "amira@example.com\nlayla@example.com",
        "delay_s": 0.2,
        "max_rcpt": 50000,
        "chunk_size": 250,
        "thread_workers": 8,
        "sleep_chunks": 1.5,
    },
}

CAMPAIGNS = [
    {
        "id": "cmp-demo-001",
        "name": "Ramadan Promo · Demo Campaign",
        "created_at": iso(NOW - timedelta(days=4, hours=2)),
        "updated_at": iso(NOW - timedelta(minutes=3)),
        "jobs": 5,
        "status": "running",
    },
    {
        "id": "cmp-demo-002",
        "name": "Eid Launch · Sample Campaign",
        "created_at": iso(NOW - timedelta(days=10)),
        "updated_at": iso(NOW - timedelta(hours=4)),
        "jobs": 2,
        "status": "paused",
    },
    {
        "id": "cmp-demo-003",
        "name": "Winback Flow · Skeleton",
        "created_at": iso(NOW - timedelta(days=18)),
        "updated_at": iso(NOW - timedelta(days=1, hours=6)),
        "jobs": 9,
        "status": "done",
    },
]

JOBS = [
    {
        "id": "job-240301-a",
        "campaign_id": "cmp-demo-001",
        "status": "running",
        "bridge_mode": "counts",
        "provider": "gmail",
        "risk": "deliverability_high",
        "created_at": iso(NOW - timedelta(hours=7)),
        "updated_at": iso(NOW - timedelta(seconds=30)),
        "sent": 22144,
        "failed": 824,
        "delivered": 21400,
        "deferred": 612,
        "complained": 18,
        "queued": 3842,
        "progress": 84,
        "top_domains": ["gmail.com", "yahoo.com", "outlook.com"],
    },
    {
        "id": "job-240301-b",
        "campaign_id": "cmp-demo-001",
        "status": "backoff",
        "bridge_mode": "legacy",
        "provider": "yahoo",
        "risk": "stale",
        "created_at": iso(NOW - timedelta(days=1, hours=2)),
        "updated_at": iso(NOW - timedelta(minutes=18)),
        "sent": 14488,
        "failed": 1350,
        "delivered": 13002,
        "deferred": 904,
        "complained": 22,
        "queued": 910,
        "progress": 63,
        "top_domains": ["yahoo.com", "aol.com", "icloud.com"],
    },
    {
        "id": "job-240301-c",
        "campaign_id": "cmp-demo-002",
        "status": "paused",
        "bridge_mode": "counts",
        "provider": "outlook",
        "risk": "internal_degraded",
        "created_at": iso(NOW - timedelta(days=2)),
        "updated_at": iso(NOW - timedelta(hours=2, minutes=12)),
        "sent": 6014,
        "failed": 388,
        "delivered": 5701,
        "deferred": 211,
        "complained": 8,
        "queued": 220,
        "progress": 47,
        "top_domains": ["hotmail.com", "outlook.com", "live.com"],
    },
]

JOB_DETAIL = {
    "job_id": "job-240301-a",
    "status": "running",
    "campaign_id": "cmp-demo-001",
    "totals": {"total": 48250, "sent": 42990, "failed": 1188, "skipped": 903, "invalid": 211},
    "domain_state": [
        {"domain": "gmail.com", "planned": 22000, "sent": 19750, "failed": 411, "pct": 92},
        {"domain": "yahoo.com", "planned": 9800, "sent": 7210, "failed": 502, "pct": 78},
        {"domain": "outlook.com", "planned": 8700, "sent": 7440, "failed": 190, "pct": 87},
        {"domain": "icloud.com", "planned": 4200, "sent": 3590, "failed": 85, "pct": 88},
    ],
    "chunks": [
        {"chunk": 188, "status": "running", "size": 250, "sender": "hello@brand-alpha.com", "spam": 2.2, "blacklist": "clean", "attempt": 1, "next_retry": "—"},
        {"chunk": 187, "status": "backoff", "size": 250, "sender": "info@brand-beta.net", "spam": 4.4, "blacklist": "listed", "attempt": 2, "next_retry": "00:02:20"},
        {"chunk": 186, "status": "done", "size": 250, "sender": "hello@brand-alpha.com", "spam": 2.0, "blacklist": "clean", "attempt": 1, "next_retry": "—"},
    ],
    "recent_results": [
        {"ts": iso(NOW - timedelta(minutes=1)), "email": "mona@gmail.com", "ok": True, "detail": "250 2.0.0 Accepted"},
        {"ts": iso(NOW - timedelta(minutes=2)), "email": "saad@yahoo.com", "ok": False, "detail": "421 4.7.0 Temporarily deferred"},
        {"ts": iso(NOW - timedelta(minutes=3)), "email": "nour@outlook.com", "ok": True, "detail": "250 2.6.0 Queued"},
        {"ts": iso(NOW - timedelta(minutes=4)), "email": "huda@icloud.com", "ok": False, "detail": "550 5.1.1 User unknown"},
    ],
    "logs": [
        "[INFO] Chunk 188 started on gmail lane.",
        "[WARN] Yahoo provider triggered adaptive slow mode.",
        "[INFO] Accounting bridge synced 782 events.",
        "[INFO] Preview-only dashboard using fake data.",
    ],
    "telemetry": {
        "mode": "v2 parallel sender lanes",
        "parallel_lanes": [
            {"lane": "lane-1", "sender": "hello@brand-alpha.com", "provider": "gmail.com", "state": "running", "processed": 8400, "success": 8160, "temp_fail": 166, "hard_fail": 74, "workers": 6},
            {"lane": "lane-2", "sender": "info@brand-beta.net", "provider": "yahoo.com", "state": "backoff", "processed": 5220, "success": 4488, "temp_fail": 601, "hard_fail": 131, "workers": 3},
            {"lane": "lane-3", "sender": "promo@offers-demo.org", "provider": "outlook.com", "state": "running", "processed": 6310, "success": 6122, "temp_fail": 110, "hard_fail": 78, "workers": 4},
        ],
    },
}

CONFIG_GROUPS = [
    {"group": "SMTP", "items": [
        {"key": "SHIVA_HOST", "value": "0.0.0.0", "type": "str", "source": "ui", "restart": True, "desc": "Flask bind host"},
        {"key": "SHIVA_PORT", "value": "5001", "type": "int", "source": "ui", "restart": True, "desc": "Flask bind port"},
        {"key": "SPAMCHECK_BACKEND", "value": "spamd", "type": "choice", "source": "env", "restart": False, "desc": "Spam score backend"},
    ]},
    {"group": "PMTA", "items": [
        {"key": "PMTA_QUEUE_BACKOFF", "value": "1", "type": "bool", "source": "ui", "restart": False, "desc": "Enable queue-based backoff"},
        {"key": "PMTA_PRESSURE_CONTROL", "value": "1", "type": "bool", "source": "default", "restart": False, "desc": "Enable pressure monitoring"},
        {"key": "PMTA_LIVE_POLL_S", "value": "5", "type": "int", "source": "ui", "restart": False, "desc": "Refresh interval for fake live stats"},
    ]},
    {"group": "Scheduler", "items": [
        {"key": "SHIVA_SCHEDULER_MODE", "value": "v2", "type": "choice", "source": "ui", "restart": False, "desc": "Fake scheduler mode"},
        {"key": "SHIVA_MAX_PARALLEL_LANES", "value": "8", "type": "int", "source": "ui", "restart": False, "desc": "Max parallel lanes"},
        {"key": "SHIVA_RESOURCE_GOVERNOR", "value": "1", "type": "bool", "source": "default", "restart": False, "desc": "Resource governor status"},
    ]},
]

DOMAINS_DATA = {
    "recipient_domains": [
        {"domain": "gmail.com", "emails": 22000, "mx": "mx", "mx_hosts": ["gmail-smtp-in.l.google.com"], "ips": ["74.125.27.26"], "listed": False, "spf": "pass", "dkim": "pass", "dmarc": "pass"},
        {"domain": "yahoo.com", "emails": 9800, "mx": "mx", "mx_hosts": ["mta5.am0.yahoodns.net"], "ips": ["67.195.204.77"], "listed": False, "spf": "pass", "dkim": "pass", "dmarc": "pass"},
        {"domain": "outlook.com", "emails": 8700, "mx": "mx", "mx_hosts": ["outlook-com.olc.protection.outlook.com"], "ips": ["104.47.14.33"], "listed": False, "spf": "pass", "dkim": "missing", "dmarc": "pass"},
    ],
    "sender_domains": [
        {"domain": "brand-alpha.com", "emails": 2, "mx": "mx", "mx_hosts": ["mx1.brand-alpha.com"], "ips": ["198.51.100.21", "198.51.100.22"], "listed": False, "spf": "pass", "dkim": "pass", "dmarc": "pass"},
        {"domain": "brand-beta.net", "emails": 1, "mx": "a_fallback", "mx_hosts": ["fallback.brand-beta.net"], "ips": ["203.0.113.80"], "listed": True, "spf": "pass", "dkim": "missing", "dmarc": "pass"},
        {"domain": "offers-demo.org", "emails": 1, "mx": "mx", "mx_hosts": ["mail.offers-demo.org"], "ips": ["203.0.113.110"], "listed": False, "spf": "pass", "dkim": "unknown_selector", "dmarc": "pass"},
    ],
}


def build_live_snapshot() -> dict:
    snapshot = copy.deepcopy(DASHBOARD_DATA)
    jitter = random.randint(-80, 80)
    queue_jitter = random.randint(-120, 120)
    snapshot["kpis"] = copy.deepcopy(DASHBOARD_DATA["kpis"])
    snapshot["kpis"][1]["value"] = f"{41932 + jitter:,}"
    snapshot["kpis"][3]["value"] = f"{1188 + abs(jitter // 4):,}"
    snapshot["kpis"][7]["value"] = f"{max(3200, 3842 + queue_jitter):,}"
    snapshot["progress"] = {
        "overall": max(10, min(100, DASHBOARD_DATA["progress"]["overall"] + random.randint(-2, 2))),
        "domain": max(10, min(100, DASHBOARD_DATA["progress"]["domain"] + random.randint(-2, 2))),
        "chunks": max(10, min(100, DASHBOARD_DATA["progress"]["chunks"] + random.randint(-3, 3))),
        "warmup": max(10, min(100, DASHBOARD_DATA["progress"]["warmup"] + random.randint(-1, 1))),
    }
    snapshot["campaign"]["updated_at"] = iso(datetime.now(timezone.utc))
    return snapshot


PAGE = r"""
<!doctype html>
<html lang="en" dir="ltr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{{ title }}</title>
  <style>
    :root{
      --bg1:#07111f; --bg2:#0d2138; --panel:rgba(255,255,255,.08); --panel2:rgba(255,255,255,.04);
      --border:rgba(255,255,255,.14); --text:#f4f8ff; --muted:rgba(244,248,255,.68); --accent:#7aa7ff;
      --good:#35e49a; --bad:#ff6b7f; --warn:#ffc85a; --shadow:0 20px 60px rgba(0,0,0,.35); --radius:18px;
    }
    *{box-sizing:border-box}
    body{
      margin:0; color:var(--text); font-family:system-ui,-apple-system,Segoe UI,Tahoma,Arial;
      background:
        radial-gradient(1000px 640px at 90% 5%, rgba(122,167,255,.16), transparent 55%),
        radial-gradient(920px 680px at 5% 10%, rgba(53,228,154,.10), transparent 55%),
        linear-gradient(180deg,var(--bg1),var(--bg2));
      min-height:100vh;
    }
    a{color:var(--accent); text-decoration:none}
    .shell{display:grid; grid-template-columns:280px 1fr; min-height:100vh}
    .sidebar{padding:22px 18px; border-right:1px solid rgba(255,255,255,.08); background:rgba(5,10,18,.35); position:sticky; top:0; height:100vh}
    .brand{font-weight:900; font-size:22px; letter-spacing:.3px}
    .brandSub{margin-top:8px; color:var(--muted); font-size:13px; line-height:1.6}
    .menu{display:flex; flex-direction:column; gap:10px; margin-top:22px}
    .menu a{display:flex; align-items:center; gap:10px; padding:12px 14px; border-radius:14px; border:1px solid rgba(255,255,255,.1); background:rgba(255,255,255,.04)}
    .menu a.active{background:rgba(122,167,255,.18); border-color:rgba(122,167,255,.35); font-weight:800}
    .sidebarCard{margin-top:18px; padding:14px; border-radius:16px; border:1px solid var(--border); background:linear-gradient(180deg,var(--panel),var(--panel2)); box-shadow:var(--shadow)}
    .content{padding:24px}
    .top{display:flex; gap:16px; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; margin-bottom:18px}
    .title{font-size:28px; margin:0}
    .subtitle{margin-top:8px; color:var(--muted); font-size:14px; line-height:1.7; max-width:980px}
    .actions{display:flex; gap:10px; flex-wrap:wrap}
    .btn, button{border:1px solid rgba(255,255,255,.16); background:rgba(122,167,255,.18); color:var(--text); padding:11px 14px; border-radius:14px; cursor:pointer; font:inherit; font-weight:700}
    .btn.secondary, button.secondary{background:rgba(255,255,255,.08)}
    .pill{display:inline-flex; align-items:center; gap:8px; padding:8px 12px; border-radius:999px; border:1px solid rgba(255,255,255,.14); background:rgba(255,255,255,.06); font-size:12px}
    .grid{display:grid; gap:14px}
    .grid.kpis{grid-template-columns:repeat(4,minmax(0,1fr))}
    .grid.two{grid-template-columns:1.2fr .8fr}
    .grid.three{grid-template-columns:repeat(3,minmax(0,1fr))}
    .card{background:linear-gradient(180deg,var(--panel),var(--panel2)); border:1px solid var(--border); border-radius:var(--radius); padding:16px; box-shadow:var(--shadow); backdrop-filter:blur(10px)}
    .card h2,.card h3,.card h4{margin:0 0 10px}
    .muted{color:var(--muted)}
    .mini{font-size:12px; color:var(--muted); line-height:1.6}
    .kpi .label{font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.4px}
    .kpi .value{font-size:28px; font-weight:900; margin-top:6px}
    .tone-good{color:var(--good)} .tone-bad{color:var(--bad)} .tone-warn{color:var(--warn)} .tone-accent{color:var(--accent)}
    .progressLine{margin-top:10px}
    .bar{height:10px; border-radius:999px; border:1px solid rgba(255,255,255,.12); background:rgba(255,255,255,.09); overflow:hidden}
    .bar > div{height:100%; background:linear-gradient(90deg,var(--accent),var(--good)); width:0}
    .alert{padding:12px 14px; border-radius:14px; border:1px solid rgba(255,255,255,.14); margin-bottom:10px}
    .alert.good{border-color:rgba(53,228,154,.35); background:rgba(53,228,154,.08)}
    .alert.warn{border-color:rgba(255,200,90,.35); background:rgba(255,200,90,.08)}
    .alert.bad{border-color:rgba(255,107,127,.35); background:rgba(255,107,127,.08)}
    table{width:100%; border-collapse:collapse; font-size:13px}
    th,td{padding:10px 8px; border-bottom:1px solid rgba(255,255,255,.1); text-align:left; vertical-align:top}
    th{color:rgba(255,255,255,.88)}
    .tag{display:inline-flex; padding:5px 10px; border-radius:999px; border:1px solid rgba(255,255,255,.12); background:rgba(255,255,255,.06); font-size:11px; font-weight:800}
    .tag.good{color:var(--good); border-color:rgba(53,228,154,.35)}
    .tag.bad{color:var(--bad); border-color:rgba(255,107,127,.35)}
    .tag.warn{color:var(--warn); border-color:rgba(255,200,90,.35)}
    .tag.accent{color:var(--accent); border-color:rgba(122,167,255,.35)}
    .statsList{display:grid; gap:10px}
    .split{display:grid; grid-template-columns:1fr 1fr; gap:14px}
    .field{margin-bottom:12px}
    label{display:block; margin-bottom:6px; color:var(--muted); font-size:12px; font-weight:700}
    input,select,textarea{width:100%; background:rgba(0,0,0,.18); color:var(--text); border:1px solid rgba(255,255,255,.16); border-radius:12px; padding:11px 12px; font:inherit}
    textarea{min-height:110px; resize:vertical}
    code{background:rgba(255,255,255,.08); padding:2px 6px; border-radius:8px}
    .telemetryRow{display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px}
    .laneBox{padding:12px; border-radius:14px; border:1px solid rgba(255,255,255,.12); background:rgba(255,255,255,.03)}
    .emptyState{padding:18px; text-align:center; color:var(--muted); border:1px dashed rgba(255,255,255,.16); border-radius:14px}
    .footerNote{margin-top:18px; color:rgba(255,255,255,.5); font-size:12px}
    @media (max-width: 1200px){ .grid.kpis{grid-template-columns:repeat(2,minmax(0,1fr))} .grid.two,.split,.telemetryRow{grid-template-columns:1fr} }
    @media (max-width: 920px){ .shell{grid-template-columns:1fr} .sidebar{position:relative; height:auto; border-right:0; border-bottom:1px solid rgba(255,255,255,.08)} .grid.three{grid-template-columns:1fr} }
  </style>
</head>
<body>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand">Shivamini</div>
      <div class="brandSub">Standalone Flask frontend sandbox with fake data only. No database, no models, and no real SMTP or PMTA actions.</div>
      <nav class="menu">
        <a href="{{ url_for('dashboard') }}" class="{% if page == 'dashboard' %}active{% endif %}">📊 Dashboard</a>
        <a href="{{ url_for('campaigns_page') }}" class="{% if page == 'campaigns' %}active{% endif %}">📌 Campaigns</a>
        <a href="{{ url_for('send_page') }}" class="{% if page == 'send' %}active{% endif %}">✉️ Send</a>
        <a href="{{ url_for('jobs_page') }}" class="{% if page == 'jobs' %}active{% endif %}">📄 Jobs</a>
        <a href="{{ url_for('job_page', job_id='job-240301-a') }}" class="{% if page == 'job' %}active{% endif %}">🧩 Job Detail</a>
        <a href="{{ url_for('config_page') }}" class="{% if page == 'config' %}active{% endif %}">⚙️ Config</a>
        <a href="{{ url_for('domains_page') }}" class="{% if page == 'domains' %}active{% endif %}">🌐 Domains</a>
      </nav>
      <div class="sidebarCard">
        <div style="font-weight:800">Demo status</div>
        <div class="mini" style="margin-top:8px">Campaign: <code>{{ sidebar_campaign.name }}</code><br>Status: <b>{{ sidebar_campaign.status }}</b><br>Updated: {{ sidebar_campaign.updated_at }}</div>
      </div>
    </aside>
    <main class="content">
      {{ body|safe }}
      <div class="footerNote">This file is intentionally frontend-heavy so you can replace the fake content later with your own real implementation.</div>
    </main>
  </div>
<script>
async function hydrateDashboard(){
  const root = document.getElementById('liveDashboardRoot');
  if(!root) return;
  try{
    const res = await fetch('{{ url_for('api_dashboard') }}');
    const data = await res.json();
    const kpiNodes = root.querySelectorAll('[data-kpi-value]');
    kpiNodes.forEach((node, idx) => {
      if(data.kpis && data.kpis[idx]) node.textContent = data.kpis[idx].value;
    });
    Object.entries(data.progress || {}).forEach(([name, value]) => {
      const bar = root.querySelector(`[data-progress="${name}"]`);
      const text = root.querySelector(`[data-progress-text="${name}"]`);
      if(bar) bar.style.width = value + '%';
      if(text) text.textContent = value + '%';
    });
    const stamp = document.getElementById('liveStamp');
    if(stamp) stamp.textContent = data.campaign.updated_at;
  }catch(err){
    console.warn('Dashboard hydrate failed', err);
  }
}
setInterval(hydrateDashboard, 4000);
hydrateDashboard();
</script>
</body>
</html>
"""


def render(page: str, title: str, body: str):
    return render_template_string(
        PAGE,
        page=page,
        title=title,
        body=body,
        sidebar_campaign=DASHBOARD_DATA["campaign"],
    )


@app.get("/")
def dashboard():
    body = render_template_string(
        """
        <div class="top">
          <div>
            <h1 class="title">Dashboard frontend skeleton</h1>
            <div class="subtitle">A full Flask-only mock frontend that mirrors the core dashboard surfaces: overview KPIs, alerts, campaign form, preflight summary, jobs, telemetry, config, and domains — all backed by fake data.</div>
          </div>
          <div class="actions">
            <a class="btn" href="{{ url_for('jobs_page') }}">Open Jobs</a>
            <a class="btn secondary" href="{{ url_for('config_page') }}">Open Config</a>
            <span class="pill">Live fake refresh: <b id="liveStamp">{{ data.campaign.updated_at }}</b></span>
          </div>
        </div>

        <div id="liveDashboardRoot">
          <div class="grid kpis">
            {% for item in data.kpis %}
            <div class="card kpi">
              <div class="label">{{ item.label }}</div>
              <div class="value tone-{{ item.tone if item.tone in ['good','bad','warn','accent'] else 'accent' }}" data-kpi-value>{{ item.value }}</div>
              <div class="mini">{{ item.hint }}</div>
            </div>
            {% endfor %}
          </div>

          <div class="grid two" style="margin-top:14px">
            <div class="card">
              <h2>Campaign summary</h2>
              <div class="split">
                <div class="statsList">
                  <div><span class="mini">Campaign</span><div><b>{{ data.campaign.name }}</b></div></div>
                  <div><span class="mini">Owner</span><div>{{ data.campaign.owner }}</div></div>
                  <div><span class="mini">Campaign ID</span><div><code>{{ data.campaign.id }}</code></div></div>
                  <div><span class="mini">Status</span><div><span class="tag good">{{ data.campaign.status }}</span></div></div>
                </div>
                <div class="statsList">
                  {% for key, value in data.progress.items() %}
                  <div class="progressLine">
                    <div style="display:flex; justify-content:space-between; gap:8px; margin-bottom:6px">
                      <span style="text-transform:capitalize">{{ key }}</span>
                      <b data-progress-text="{{ key }}">{{ value }}%</b>
                    </div>
                    <div class="bar"><div data-progress="{{ key }}" style="width:{{ value }}%"></div></div>
                  </div>
                  {% endfor %}
                </div>
              </div>
            </div>
            <div class="card">
              <h2>Alerts & notices</h2>
              {% for alert in data.alerts %}
              <div class="alert {{ alert.tone }}">
                <div style="font-weight:800">{{ alert.title }}</div>
                <div class="mini" style="margin-top:6px">{{ alert.body }}</div>
              </div>
              {% endfor %}
            </div>
          </div>

          <div class="grid two" style="margin-top:14px">
            <div class="card">
              <h2>Excel audience workflow</h2>
              <div class="mini">Mini Shiva now highlights how the Excel import is prepared before operators open the dedicated Send surface.</div>
              <div style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap">
                <span class="tag accent">Workbook {{ data.excel_info.file_name }}</span>
                <span class="tag good">Sheet {{ data.excel_info.sheet_name }}</span>
                <span class="tag">Rows {{ data.excel_info.rows_total }}</span>
                <span class="tag good">Validated {{ data.excel_info.validated_rows }}</span>
                <span class="tag warn">Suppressed {{ data.excel_info.suppressed_rows }}</span>
              </div>
              <div class="grid two" style="margin-top:12px">
                <div>
                  <h3 style="margin:0 0 10px">Mapped columns</h3>
                  <table>
                    <thead><tr><th>Column</th><th>Usage</th></tr></thead>
                    <tbody>
                      {% for column in data.excel_info.columns %}
                      <tr>
                        <td><code>{{ column.name }}</code></td>
                        <td>{{ column.description }}</td>
                      </tr>
                      {% endfor %}
                    </tbody>
                  </table>
                </div>
                <div>
                  <h3 style="margin:0 0 10px">Preparation checks</h3>
                  <div class="statsList">
                    {% for item in data.excel_info.checks %}
                    <div class="alert accent" style="margin:0">{{ item }}</div>
                    {% endfor %}
                  </div>
                </div>
              </div>
            </div>
            <div class="card">
              <h2>Preflight summary</h2>
              <div class="mini">SMTP host: <code>{{ data.preflight.smtp_host }}</code> · Backend: {{ data.preflight.backend }}</div>
              <div style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap">
                <span class="tag good">Spam {{ data.preflight.spam_score }}</span>
                <span class="tag warn">Limit {{ data.preflight.spam_limit }}</span>
                <span class="tag accent">{{ data.preflight.sender_domains|length }} sender domains</span>
              </div>
              <div style="overflow:auto; margin-top:12px">
                <table>
                  <thead><tr><th>Domain</th><th>IPs</th><th>Status</th><th>Spam</th></tr></thead>
                  <tbody>
                    {% for item in data.preflight.sender_domains %}
                    <tr>
                      <td>{{ item.domain }}</td>
                      <td>{{ item.ips|join(', ') }}</td>
                      <td><span class="tag {{ 'bad' if item.status == 'Listed' else 'good' }}">{{ item.status }}</span></td>
                      <td>{{ item.spam_score }}</td>
                    </tr>
                    {% endfor %}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
        """,
        data=DASHBOARD_DATA,
    )
    return render("dashboard", "Shivamini Dashboard", body)


@app.get("/send")
def send_page():
    return Response(SEND_PAGE_HTML, mimetype="text/html")


@app.get("/campaigns")
def campaigns_page():
    body = render_template_string(
        """
        <div class="top">
          <div>
            <h1 class="title">Campaigns</h1>
            <div class="subtitle">Frontend-only sample listing for saved campaigns, states, and quick open actions.</div>
          </div>
          <div class="actions">
            <button>➕ New Campaign</button>
            <button class="secondary">🧨 Wipe Demo Data</button>
          </div>
        </div>
        <div class="grid">
          {% for campaign in campaigns %}
          <div class="card">
            <div style="display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap">
              <div>
                <h3>{{ campaign.name }}</h3>
                <div class="mini">ID: <code>{{ campaign.id }}</code> · Created: {{ campaign.created_at }}</div>
              </div>
              <div class="tag {{ 'good' if campaign.status == 'running' else ('warn' if campaign.status == 'paused' else 'accent') }}">{{ campaign.status }}</div>
            </div>
            <div class="mini" style="margin-top:8px">Updated: {{ campaign.updated_at }} · Jobs: {{ campaign.jobs }}</div>
            <div class="actions" style="margin-top:12px">
              <a class="btn" href="{{ url_for('dashboard') }}">Open</a>
              <button class="secondary">Rename</button>
              <button class="secondary">Duplicate</button>
              <button class="secondary">Delete</button>
            </div>
          </div>
          {% endfor %}
        </div>
        """,
        campaigns=CAMPAIGNS,
    )
    return render("campaigns", "Shivamini Campaigns", body)


@app.get("/jobs")
def jobs_page():
    body = render_template_string(
        """
        <div class="top">
          <div>
            <h1 class="title">Jobs board</h1>
            <div class="subtitle">Simulated jobs list with risk labels, provider grouping, progress bars, and outcomes overview.</div>
          </div>
          <div class="actions">
            <button>🔄 Refresh</button>
            <button class="secondary">🎛️ Filters</button>
          </div>
        </div>
        <div class="grid">
          {% for job in jobs %}
          <div class="card">
            <div style="display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap">
              <div>
                <h3>Job <code>{{ job.id }}</code></h3>
                <div class="mini">Campaign: {{ job.campaign_id }} · Created: {{ job.created_at }} · Updated: {{ job.updated_at }}</div>
              </div>
              <div style="display:flex; gap:8px; flex-wrap:wrap">
                <span class="tag {{ 'good' if job.status == 'running' else ('warn' if job.status in ['backoff','paused'] else 'accent') }}">{{ job.status }}</span>
                <span class="tag accent">{{ job.bridge_mode }}</span>
                <span class="tag {{ 'bad' if job.risk != 'none' else 'good' }}">{{ job.risk }}</span>
                <span class="tag">{{ job.provider }}</span>
              </div>
            </div>
            <div class="grid three" style="margin-top:12px">
              <div><div class="mini">Delivered</div><div style="font-size:24px; font-weight:900; color:var(--good)">{{ '{:,}'.format(job.delivered) }}</div></div>
              <div><div class="mini">Deferred</div><div style="font-size:24px; font-weight:900; color:var(--warn)">{{ '{:,}'.format(job.deferred) }}</div></div>
              <div><div class="mini">Queued</div><div style="font-size:24px; font-weight:900; color:var(--accent)">{{ '{:,}'.format(job.queued) }}</div></div>
            </div>
            <div class="progressLine">
              <div style="display:flex; justify-content:space-between; gap:8px; margin-bottom:6px"><span>Progress</span><b>{{ job.progress }}%</b></div>
              <div class="bar"><div style="width:{{ job.progress }}%"></div></div>
            </div>
            <div class="mini" style="margin-top:10px">Top domains: {{ job.top_domains|join(', ') }}</div>
            <div class="actions" style="margin-top:12px">
              <a class="btn" href="{{ url_for('job_page', job_id=job.id) }}">View details</a>
              <button class="secondary">Pause</button>
              <button class="secondary">Resume</button>
              <button class="secondary">Stop</button>
            </div>
          </div>
          {% endfor %}
        </div>
        """,
        jobs=JOBS,
    )
    return render("jobs", "Shivamini Jobs", body)


@app.get("/job/<job_id>")
def job_page(job_id: str):
    detail = copy.deepcopy(JOB_DETAIL)
    detail["job_id"] = job_id
    body = render_template_string(
        """
        <div class="top">
          <div>
            <h1 class="title">Job detail · <code>{{ detail.job_id }}</code></h1>
            <div class="subtitle">Detailed fake job view: totals, domains, chunk state, recent results, logs, and lane telemetry.</div>
          </div>
          <div class="actions">
            <a class="btn" href="{{ url_for('jobs_page') }}">← Back to jobs</a>
            <button class="secondary">📥 Delivered CSV</button>
            <button class="secondary">⏳ Queue CSV</button>
            <button class="secondary">🚫 Failed CSV</button>
          </div>
        </div>
        <div class="grid two">
          <div class="card">
            <h2>Totals</h2>
            <div class="grid three">
              {% for key, value in detail.totals.items() %}
              <div>
                <div class="mini">{{ key|replace('_', ' ')|title }}</div>
                <div style="font-size:24px; font-weight:900">{{ '{:,}'.format(value) }}</div>
              </div>
              {% endfor %}
            </div>
          </div>
          <div class="card">
            <h2>Scheduler telemetry</h2>
            <div class="mini">Mode: <b>{{ detail.telemetry.mode }}</b></div>
            <div class="telemetryRow" style="margin-top:10px">
              {% for lane in detail.telemetry.parallel_lanes %}
              <div class="laneBox">
                <div style="font-weight:800">{{ lane.lane }}</div>
                <div class="mini">{{ lane.sender }} → {{ lane.provider }}</div>
                <div style="margin-top:8px"><span class="tag {{ 'warn' if lane.state == 'backoff' else 'good' }}">{{ lane.state }}</span></div>
                <div class="mini" style="margin-top:8px">Processed {{ lane.processed }} · Success {{ lane.success }} · Temp {{ lane.temp_fail }} · Hard {{ lane.hard_fail }} · Workers {{ lane.workers }}</div>
              </div>
              {% endfor %}
            </div>
          </div>
        </div>

        <div class="grid two" style="margin-top:14px">
          <div class="card">
            <h2>Domain state</h2>
            <table>
              <thead><tr><th>Domain</th><th>Planned</th><th>Sent</th><th>Failed</th><th>Progress</th></tr></thead>
              <tbody>
                {% for row in detail.domain_state %}
                <tr>
                  <td>{{ row.domain }}</td>
                  <td>{{ row.planned }}</td>
                  <td>{{ row.sent }}</td>
                  <td>{{ row.failed }}</td>
                  <td style="min-width:180px"><div class="bar"><div style="width:{{ row.pct }}%"></div></div><div class="mini">{{ row.pct }}%</div></td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
          <div class="card">
            <h2>Chunk state & backoff</h2>
            <table>
              <thead><tr><th>Chunk</th><th>Status</th><th>Size</th><th>Sender</th><th>Spam</th><th>BL</th><th>Attempt</th><th>Next retry</th></tr></thead>
              <tbody>
                {% for row in detail.chunks %}
                <tr>
                  <td>{{ row.chunk }}</td>
                  <td><span class="tag {{ 'warn' if row.status == 'backoff' else ('good' if row.status == 'running' else 'accent') }}">{{ row.status }}</span></td>
                  <td>{{ row.size }}</td>
                  <td>{{ row.sender }}</td>
                  <td>{{ row.spam }}</td>
                  <td>{{ row.blacklist }}</td>
                  <td>{{ row.attempt }}</td>
                  <td>{{ row.next_retry }}</td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
        </div>

        <div class="grid two" style="margin-top:14px">
          <div class="card">
            <h2>Recent results</h2>
            <table>
              <thead><tr><th>Time</th><th>Email</th><th>OK</th><th>Detail</th></tr></thead>
              <tbody>
                {% for item in detail.recent_results %}
                <tr>
                  <td>{{ item.ts }}</td>
                  <td>{{ item.email }}</td>
                  <td><span class="tag {{ 'good' if item.ok else 'bad' }}">{{ 'YES' if item.ok else 'NO' }}</span></td>
                  <td>{{ item.detail }}</td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
          <div class="card">
            <h2>Recent logs</h2>
            <div style="white-space:pre-wrap; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:13px">{{ detail.logs|join('\n') }}</div>
          </div>
        </div>
        """,
        detail=detail,
    )
    return render("job", f"Shivamini Job {job_id}", body)


@app.get("/config")
def config_page():
    body = render_template_string(
        """
        <div class="top">
          <div>
            <h1 class="title">Config surface</h1>
            <div class="subtitle">Static config table intended for frontend extraction and future replacement with your real settings API.</div>
          </div>
          <div class="actions">
            <button>💾 Save all</button>
            <button class="secondary">🔄 Reload</button>
          </div>
        </div>
        <div class="grid">
          {% for group in groups %}
          <div class="card">
            <h2>{{ group.group }}</h2>
            <table>
              <thead><tr><th>Key</th><th>Value</th><th>Type</th><th>Source</th><th>Restart</th><th>Description</th></tr></thead>
              <tbody>
                {% for item in group["items"] %}
                <tr>
                  <td><code>{{ item.key }}</code></td>
                  <td>{{ item.value }}</td>
                  <td>{{ item.type }}</td>
                  <td><span class="tag {{ 'good' if item.source == 'ui' else ('warn' if item.source == 'env' else 'accent') }}">{{ item.source }}</span></td>
                  <td>{{ 'yes' if item.restart else 'no' }}</td>
                  <td>{{ item.desc }}</td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
          {% endfor %}
        </div>
        """,
        groups=CONFIG_GROUPS,
    )
    return render("config", "Shivamini Config", body)


@app.get("/domains")
def domains_page():
    body = render_template_string(
        """
        <div class="top">
          <div>
            <h1 class="title">Domains health</h1>
            <div class="subtitle">Recipient and sender domain tables with fake MX/SPF/DKIM/DMARC/blacklist states for visual frontend testing.</div>
          </div>
          <div class="actions">
            <button>🌐 Refresh</button>
            <button class="secondary">🔎 Search</button>
          </div>
        </div>
        <div class="grid two">
          <div class="card">
            <h2>Recipient domains</h2>
            <table>
              <thead><tr><th>Domain</th><th>Emails</th><th>MX</th><th>Hosts</th><th>IPs</th><th>Listed</th><th>SPF</th><th>DKIM</th><th>DMARC</th></tr></thead>
              <tbody>
                {% for item in data.recipient_domains %}
                <tr>
                  <td>{{ item.domain }}</td>
                  <td>{{ item.emails }}</td>
                  <td>{{ item.mx }}</td>
                  <td>{{ item.mx_hosts|join(', ') }}</td>
                  <td>{{ item.ips|join(', ') }}</td>
                  <td><span class="tag {{ 'bad' if item.listed else 'good' }}">{{ 'listed' if item.listed else 'clean' }}</span></td>
                  <td>{{ item.spf }}</td>
                  <td>{{ item.dkim }}</td>
                  <td>{{ item.dmarc }}</td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
          <div class="card">
            <h2>Sender domains</h2>
            <table>
              <thead><tr><th>Domain</th><th>Emails</th><th>MX</th><th>Hosts</th><th>IPs</th><th>Listed</th><th>SPF</th><th>DKIM</th><th>DMARC</th></tr></thead>
              <tbody>
                {% for item in data.sender_domains %}
                <tr>
                  <td>{{ item.domain }}</td>
                  <td>{{ item.emails }}</td>
                  <td>{{ item.mx }}</td>
                  <td>{{ item.mx_hosts|join(', ') }}</td>
                  <td>{{ item.ips|join(', ') }}</td>
                  <td><span class="tag {{ 'bad' if item.listed else 'good' }}">{{ 'listed' if item.listed else 'clean' }}</span></td>
                  <td>{{ item.spf }}</td>
                  <td>{{ item.dkim }}</td>
                  <td>{{ item.dmarc }}</td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
        </div>
        """,
        data=DOMAINS_DATA,
    )
    return render("domains", "Shivamini Domains", body)


@app.get("/api/dashboard")
def api_dashboard():
    return jsonify(build_live_snapshot())


@app.get("/api/jobs")
def api_jobs():
    return jsonify({"jobs": JOBS})


@app.get("/api/job/<job_id>")
def api_job(job_id: str):
    detail = copy.deepcopy(JOB_DETAIL)
    detail["job_id"] = job_id
    return jsonify(detail)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5099, debug=True)
