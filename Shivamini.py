from __future__ import annotations

import copy
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template_string, url_for

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
JOBS_HTML_PATH = BASE_DIR / "jobs.html"

JOBS_PAGE_NAV_STYLE = r"""
    .shivaMiniNav{
      display:flex;
      gap:10px;
      flex-wrap:wrap;
      align-items:center;
      justify-content:space-between;
      margin-bottom:14px;
      padding:12px 14px;
      border:1px solid rgba(255,255,255,.14);
      border-radius:16px;
      background:linear-gradient(180deg, rgba(255,255,255,.08), rgba(255,255,255,.04));
      box-shadow:var(--shadow);
      backdrop-filter:blur(10px);
    }
    .shivaMiniNavTitle{font-size:13px; color:var(--muted); line-height:1.6;}
    .shivaMiniNavLinks{display:flex; gap:10px; flex-wrap:wrap; align-items:center;}
    .shivaMiniNavLinks a{
      display:inline-flex;
      align-items:center;
      gap:8px;
      padding:10px 12px;
      border:1px solid rgba(255,255,255,.14);
      border-radius:14px;
      background:rgba(255,255,255,.06);
      color:rgba(255,255,255,.92);
      font-weight:800;
      text-decoration:none;
    }
    .shivaMiniNavLinks a.active{background:rgba(122,167,255,.18);}
"""

JOBS_PAGE_NAV_HTML = r"""
    <nav class="shivaMiniNav" aria-label="Shivamini navigation">
      <div>
        <div style="font-size:18px; font-weight:900;">Shivamini Jobs</div>
        <div class="shivaMiniNavTitle">The `/jobs` surface now reuses the same full `jobs.html` CSS/layout, with only a lightweight navigation bar added above it.</div>
      </div>
      <div class="shivaMiniNavLinks">
        <a href="{{ url_for('dashboard') }}">📊 Dashboard</a>
        <a href="{{ url_for('campaigns_page') }}">📌 Campaigns</a>
        <a href="{{ url_for('send_page') }}">✉️ Send</a>
        <a href="{{ url_for('jobs_page') }}" class="active">📄 Jobs</a>
        <a href="{{ url_for('config_page') }}">⚙️ Config</a>
        <a href="{{ url_for('domains_page') }}">🌐 Domains</a>
      </div>
    </nav>
"""


def build_jobs_page_html() -> str:
    html = JOBS_HTML_PATH.read_text(encoding="utf-8")
    html = html.replace("</style>", f"{JOBS_PAGE_NAV_STYLE}\n  </style>", 1)
    html = html.replace('<div class="wrap">', f'<div class="wrap">\n{JOBS_PAGE_NAV_HTML}', 1)
    return html

SEND_PAGE_BODY = r"""
<div class="wrap">
  <div class="top">
    <div>
      <h1>SMTP Mail Sender · <span style="color: var(--muted)">Campaign {{ campaign_ts }}</span></h1>
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

  <form class="grid send-layout" method="post" action="/start" enctype="multipart/form-data" id="mainForm">
    <input type="hidden" name="campaign_id" value="abac50d078ae">
    <div class="stack">
      <div class="card">
      <h2>SMTP Settings</h2>

      <div class="row">
        <div>
          <label>SMTP Host</label>
          <input name="smtp_host" placeholder="Example: mail.example.com or an IP" required="">
        </div>
        <div>
          <label>Port</label>
          <input name="smtp_port" type="number" placeholder="Example: 25 / 2525 / 587 / 465" required="" value="2525">
        </div>
      </div>

      <div class="row">
        <div>
          <label>Security</label>
          <select name="smtp_security">
            <option value="starttls">STARTTLS (587)</option>
            <option value="ssl">SSL/TLS (465)</option>
            <option value="none" selected="">None (not recommended)</option>
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
      <h2>SSH Connection</h2>

      <div class="row">
        <div>
          <label>SSH Host</label>
          <input name="ssh_host" placeholder="Example: same PMTA server host/IP">
        </div>
        <div>
          <label>SSH Port</label>
          <input name="ssh_port" type="number" placeholder="22" value="22">
        </div>
      </div>

      <div class="row">
        <div>
          <label>SSH Username</label>
          <input name="ssh_user" placeholder="Example: root or pmtaops">
        </div>
        <div>
          <label>SSH Key Path (optional)</label>
          <input name="ssh_key_path" placeholder="/home/app/.ssh/id_rsa">
        </div>
      </div>

      <div class="row">
        <div>
          <label>SSH Password (optional)</label>
          <input name="ssh_pass" type="password" placeholder="Password auth supported directly by Shiva">
        </div>
        <div>
          <label>SSH Timeout (seconds)</label>
          <input name="ssh_timeout" type="number" value="8" min="3" max="120">
        </div>
      </div>

      <div class="check" style="margin-top:10px">
        <input type="checkbox" id="remember_ssh_pass" name="remember_ssh_pass">
        <div>
          Remember SSH password on this browser (saved in server database (SQLite)). <b style="color: var(--warn)">Not recommended</b> on shared PCs.
        </div>
      </div>

      <div class="hint">
        <b>PMTA monitoring/accounting now uses SSH only.</b> Shiva runs commands such as <code>pmta show status</code> and tails the remote accounting CSV via SSH.
      </div>

      <div class="actions">
        <button class="btn secondary" type="button" id="btnSshTest">🖧 Test SSH</button>
        <div class="mini">Checks SSH access and runs <code>pmta show status</code>.</div>
      </div>
      <div class="inline-status" id="sshTestInline"></div>
      </div>

      <div class="card">
        <h2>Preflight &amp; Send Controls</h2>

        <div class="check">
        <input type="checkbox" name="permission_ok" required="">
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
          <textarea name="from_name" placeholder="Example: Ahmed (one per line)" required="" style="min-height:48px"></textarea>
        </div>
        <div>
          <label>Sender Email</label>
          <textarea name="from_email" placeholder="Example: sender@domain.com (one per line)" required="" style="min-height:48px"></textarea>
        </div>
      </div>

      <label>Subject</label>
      <textarea name="subject" placeholder="Email subject (one per line)" required="" style="min-height:48px"></textarea>

      <div class="row">
        <div>
          <label>Format</label>
          <select name="body_format">
            <option value="text" selected="">Text</option>
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
      <textarea name="body" placeholder="Write your message here..." required=""></textarea>

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
          <div class="mini">Use <code>[SRC]</code> in subject/body. Replaced per chunk in line order (cycles back to first line after the last). Use <code>[MAIL]</code> or <code>[EMAIL]</code> for recipient email, and <code>[NAME]</code> for the part before @.</div>
        </div>
      </div>

      <h2 style="margin-top:14px">Recipients</h2>

      <label>Recipients (newline / comma / semicolon)</label>
      <textarea name="recipients" placeholder="a@x.com
b@y.com
c@z.com"></textarea>

      <label>Or upload a .txt or .csv file (single column or multiple columns)</label>
      <input type="file" name="recipients_file" accept=".txt,.csv">

      <label>Maillist Safe (optional whitelist)</label>
      <textarea name="maillist_safe" placeholder="If set, ONLY these emails will receive (newline / comma / semicolon)"></textarea>
      <div class="mini">If this field is filled, recipients not in this list will be skipped.</div>

      <div class="hint">
        ✅ This tool will:
        <ul style="margin:8px 0 0; padding:0 18px; color: rgba(255,255,255,.62)">
          <li>Clean &amp; deduplicate recipients</li>
          <li>Filter invalid emails</li>
          <li>Show progress + logs</li>
        </ul>
      </div>

      <div class="actions">
        <button class="btn" type="submit" id="btnStart">🚀 Start Sending</button>
        <a class="btn secondary" href="/jobs?c=abac50d078ae" style="text-decoration:none; display:inline-block;">📄 Jobs</a>
        <a class="btn secondary" href="/campaign/abac50d078ae/config" style="text-decoration:none; display:inline-block;">⚙️ Config</a>
      </div>

      <div class="foot">
        Tip: test first with 2–5 emails to confirm SMTP settings before sending large batches.
      </div>
    </div>
  </form>

  <div class="card" id="domainsCard" style="margin-top:14px">
    <h2>Save Domains</h2>

    <div class="actions" style="margin-top:12px">
      <input id="domQ" placeholder="Search domain..." style="max-width:320px">
      <button class="btn secondary" type="button" id="btnDomains" disabled="">🌐 Refresh</button>
      <div class="mini" id="domStatus">Loading...</div>
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
"""

SEND_PAGE_SCRIPT = r"""
function q(name){ return document.querySelector(`[name="${name}"]`); }

  function labelForElement(el){
    if(!el) return '';
    const raw = (el.textContent || '').replace(/\s+/g, ' ').trim();
    return raw.replace(/^[-•\s]+/, '');
  }

  // -------------------------
  // Persist form values (SQLite via server API)
  // -------------------------

  const CAMPAIGN_ID = "abac50d078ae";
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
        if(name === 'ssh_pass'){
          const rememberSsh = document.getElementById('remember_ssh_pass')?.checked;
          data[name] = rememberSsh ? (el.value || '') : '';
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

  async function doSshTest(){
    const btn = document.getElementById('btnSshTest');
    const box = document.getElementById('sshTestInline');
    const setBox = (html, kind) => {
      box.classList.add('show');
      box.style.borderColor = kind === 'good' ? 'rgba(53,228,154,.35)' : (kind === 'bad' ? 'rgba(255,94,115,.35)' : 'rgba(255,193,77,.35)');
      box.innerHTML = html;
    };

    btn.disabled = true;
    const payload = {
      smtp_host: (q('smtp_host')?.value || '').trim(),
      ssh_host: (q('ssh_host')?.value || '').trim(),
      ssh_port: (q('ssh_port')?.value || '22').trim(),
      ssh_user: (q('ssh_user')?.value || '').trim(),
      ssh_key_path: (q('ssh_key_path')?.value || '').trim(),
      ssh_pass: (q('ssh_pass')?.value || '').trim(),
      ssh_timeout: (q('ssh_timeout')?.value || '8').trim(),
    };

    try{
      const r = await fetch('/api/ssh_test', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(payload)
      });
      const j = await r.json().catch(()=>({}));
      if(r.ok && j.ok){
        toast('✅ SSH OK', j.detail || 'SSH connection successful', 'good');
        setBox(`<b>SSH OK</b><br>• ${(j.detail || '')}<br>• Target: <b>${escHtml(j.target || '—')}</b>`, 'good');
      }else{
        const msg = (j && (j.detail || j.error)) ? (j.detail || j.error) : `HTTP ${r.status}`;
        toast('❌ SSH Failed', msg, 'bad');
        setBox(`<b>SSH Failed</b><br>• ${escHtml(msg)}`, 'bad');
      }
    }catch(e){
      const msg = e?.toString?.() || 'Unknown error';
      toast('❌ SSH Failed', msg, 'bad');
      setBox(`<b>SSH Failed</b><br>• ${escHtml(msg)}`, 'bad');
    }finally{
      btn.disabled = false;
    }
  }

  document.getElementById('btnSshTest').addEventListener('click', doSshTest);

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
            ? (`This campaign already has a job in progress:\n`+
               `- ID: ${latest.id}\n`+
               `- Status: ${latest.status}\n\n`+
               `Do you want another job?`)
            : (`This campaign already has job history (latest):\n`+
               `- ID: ${latest.id}\n`+
               `- Status: ${latest.status}\n\n`+
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
"""

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
    "ops_snapshot": [
        {"label": "Active operators", "value": "4", "tone": "accent", "hint": "Fake dashboard staffing info for the current shift."},
        {"label": "Bridge poll", "value": "5s", "tone": "good", "hint": "Preview-only bridge polling interval."},
        {"label": "Warmup profile", "value": "Tier B", "tone": "warn", "hint": "Demo sender warmup cohort for this campaign."},
        {"label": "Inbox seed tests", "value": "18/20", "tone": "good", "hint": "Sample seed inbox placement result."},
    ],
    "dashboard_notes": [
        {"title": "Shift owner", "body": "Maya (deliverability) is monitoring Gmail and Outlook lanes for this demo job.", "tone": "accent"},
        {"title": "Next milestone", "body": "The board switches to reconciliation mode after the live queue drops below 1,000 recipients.", "tone": "good"},
        {"title": "Demo caveat", "body": "All numbers on this dashboard are fake placeholders for frontend preview only.", "tone": "warn"},
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

JOBS_NAV_ITEMS = [
    {"label": "Overview", "href": "#job-overview"},
    {"label": "PMTA Live", "href": "#job-pmta-live"},
    {"label": "Outcomes", "href": "#job-outcomes"},
    {"label": "Providers", "href": "#job-providers"},
    {"label": "Chunk preflight", "href": "#job-chunk-preflight"},
]

JOBS_SHOWCASE_HTML = r"""
<div class="job" id="job-overview" data-jobid="83b5cd63007e" data-created="2026-03-22T10:19:10Z">
  <div class="jobTop">
    <div>
      <div class="titleRow">
        <div style="font-weight:900">Job <code>83b5cd63007e</code></div>
        <div class="pill bad" data-k="status">Status: error</div>
        <div class="pill" data-k="speed">0 epm</div>
        <div class="pill" data-k="eta">ETA —</div>
      </div>
      <div class="triageRow">
        <div class="triageBadge" data-k="badgeMode"><span class="badgeLabel">—</span><span class="tip" data-tip="Bridge mode not available yet for this job.">ⓘ</span></div>
        <div class="triageBadge" data-k="badgeFreshness"><span class="badgeLabel">—</span><span class="tip" data-tip="Freshness signal: how recent accounting or legacy ingestion updates are for this job.">ⓘ</span></div>
        <div class="triageBadge good" data-k="badgeHealth"><span class="badgeLabel">OK (0)</span><span class="tip" data-tip="Internal health checks are clean (no bridge/runtime failure counters).">ⓘ</span></div>
        <div class="triageBadge" data-k="badgeRisk"><span class="badgeLabel">RISK —</span><span class="tip" data-tip="Deliverability risk derived from bounce, complaint, and deferred rates.">ⓘ</span></div>
        <div class="triageBadge bridgeConnBadge bad" data-k="badgeBridgeConn" title="Bridge↔Shiva disconnected"><span class="statusDot bad" aria-hidden="true"></span><span>Bridge↔Shiva disconnected</span><span class="tip" data-tip="Real-time bridge transport status between PMTA accounting bridge and Shiva receiver. Current endpoint is not available yet.">ⓘ</span></div>
        <div class="triageBadge" data-k="badgeIntegrity" style="display:none"><span class="badgeLabel">INTEGRITY</span><span class="tip" data-tip="Data integrity counters are clean.">ⓘ</span></div>
      </div>
      <div class="mini">Created: <span class="muted">2026-03-22T10:19:10Z</span></div>
      <div class="mini" data-k="alerts">Quick issues: ❌ abandoned chunks</div>
    </div>

    <div class="nav jobActionNav" style="margin-top:0">
      <a class="btn secondary" href="/job/83b5cd63007e">Open</a>
      <button class="btn secondary" type="button" data-action="pause" disabled>⏸ Pause</button>
      <button class="btn secondary" type="button" data-action="resume" disabled>▶ Resume</button>
      <button class="btn danger" type="button" data-action="stop" disabled>⛔ Stop</button>
      <button class="btn danger" type="button" data-action="delete">🗑 Delete</button>
    </div>
  </div>

  <div class="kpiWrap">
    <div class="kpiRow">
      <div class="kpiCell kpi-sent"><div class="k">Sent</div><div class="v"><span data-k="sent">0</span></div></div>
      <div class="kpiCell"><div class="k">Pending</div><div class="v"><span data-k="pending">0</span><span class="kpiWarn" data-k="pendingWarn" style="display:none" title="Pending was clamped to 0 because Sent is lower than PMTA outcomes.">⚠</span></div></div>
      <div class="kpiCell kpi-del"><div class="k">Del</div><div class="v"><span data-k="delivered">0</span></div></div>
      <div class="kpiCell kpi-bnc"><div class="k">Bnc</div><div class="v"><span data-k="bounced">0</span></div></div>
      <div class="kpiCell kpi-def"><div class="k">Def</div><div class="v"><span data-k="deferred">0</span></div></div>
      <div class="kpiCell kpi-cmp"><div class="k">Cmp</div><div class="v"><span data-k="complained">0</span></div></div>
    </div>
    <div class="ratesRow">
      <div class="rateCell"><div class="k">Bounce %</div><div class="v" data-k="rateBounce">—</div></div>
      <div class="rateCell"><div class="k">Complaint %</div><div class="v" data-k="rateComplaint">—</div></div>
      <div class="rateCell"><div class="k">Deferred %</div><div class="v" data-k="rateDeferred">—</div></div>
    </div>

    <div class="panel" id="job-pmta-live" style="margin-top:10px;">
      <h4>PMTA Live Panel</h4>
      <div class="pmtaLive" data-k="pmtaLine">
        <div class="pmtaGrid">
          <div class="pmtaBox"><div class="pmtaTitle"><span>Spool</span><span class="tag good">rcpt</span></div><div class="pmtaHint">Total recipients/messages currently held by PMTA spool.</div><div class="pmtaRow"><span class="pmtaKey">RCPT</span><span class="pmtaVal good pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">MSG</span><span class="pmtaVal good">—</span></div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Queue</span><span class="tag good">rcpt</span></div><div class="pmtaHint">Recipients/messages still queued to be delivered.</div><div class="pmtaRow"><span class="pmtaKey">RCPT</span><span class="pmtaVal good pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">MSG</span><span class="pmtaVal good">—</span></div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Connections</span></div><div class="pmtaHint">Live SMTP sessions used for inbound/outbound traffic.</div><div class="pmtaRow"><span class="pmtaKey">SMTP In</span><span class="pmtaVal good pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">SMTP Out</span><span class="pmtaVal good pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">Total</span><span class="pmtaVal good">—</span></div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Last minute</span></div><div class="pmtaHint">Recent PMTA throughput over the last 60 seconds.</div><div class="pmtaRow"><span class="pmtaKey">In</span><span class="pmtaVal warn pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">Out</span><span class="pmtaVal warn pmtaBig">—</span></div><div class="pmtaSub">traffic recipients / minute</div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Last hour</span></div><div class="pmtaHint">Rolling traffic totals for the previous 60 minutes.</div><div class="pmtaRow"><span class="pmtaKey">In</span><span class="pmtaVal warn pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">Out</span><span class="pmtaVal warn pmtaBig">—</span></div><div class="pmtaSub">traffic recipients / hour</div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Top queues</span></div><div class="pmtaHint">Queues with the highest recipient backlog and latest queue errors.</div><div class="pmtaSub">0=0</div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Time</span></div><div class="pmtaHint">Timestamp of the latest PMTA snapshot used for this panel.</div><div class="pmtaSub">2026-03-22T10:19:41Z</div></div>
        </div>
      </div>
      <div class="mini" style="margin-top:6px" data-k="pmtaNote">Note: <b>sent</b> = accepted by PMTA (client-side). Delivery may still be queued/deferred.</div>
      <div class="chunkMeta" style="margin-top:6px" data-k="pmtaDiag"><span class="chunkMetaPill">Diag: —</span></div>
      <div class="mini" style="margin-top:8px"><b>Error summary</b></div>
      <div class="mini errorSummaryBox" data-k="pmtaErrorSummary" style="display: none;"></div>
    </div>

    <details class="qualityMini">
      <summary>Quality</summary>
      <div class="qualityLine">Final-fail: <span data-k="failed">0</span> · Skipped: <span data-k="skipped">0</span> · Invalid: <span data-k="invalid">0</span> · Total: <span data-k="total">1</span></div>
    </details>
  </div>

  <div class="bars">
    <div class="panel">
      <h4>Progress</h4>
      <div class="mini" data-k="progressText">Send progress: 0% (0/1)</div>
      <div class="bar"><div data-k="barSend" style="width: 0%;"></div></div>
      <div class="mini" style="margin-top:8px" data-k="chunksText">Chunks: 1/1 done · backoff_events=0 · abandoned=1</div>
      <div class="mini" data-k="attemptsText" style="display:none">—</div>
      <div class="bar"><div data-k="barChunks" style="width: 100%;"></div></div>
      <div class="mini" style="margin-top:8px" data-k="domainsText">Domains: 0% (0/1)</div>
      <div class="bar"><div data-k="barDomains" style="width: 0%;"></div></div>
    </div>
  </div>

  <div class="quickIssues" data-k="quickIssues">Quick issues: ❌ abandoned chunks</div>

  <details class="more" open>
    <summary>More details</summary>
    <div class="moreBlock twoCol">
      <div class="panel">
        <h4>Current chunk</h4>
        <div class="mini">Current send settings + top active domains in this running chunk.</div>
        <div class="mini" data-k="chunkLine"><div class="mini">—</div></div>
        <div class="mini" data-k="chunkDomains"><div class="mini chunkNote chunkNoteDomains">🔥 Top active domains: —</div></div>
      </div>
      <div class="panel">
        <h4>Backoff</h4>
        <div class="mini">Latest retry event when PMTA/provider pressure slows delivery.</div>
        <div class="mini" data-k="backoffLine">—</div>
      </div>
    </div>

    <div class="panel moreBlock" id="job-outcomes">
      <h4>Outcomes (PMTA accounting)</h4>
      <div class="outcomesWrap" data-k="outcomes">
        <div class="outcomesGrid">
          <div class="outChip del"><span class="k">Delivered</span><span class="v">0</span></div>
          <div class="outChip bnc"><span class="k">Bounced</span><span class="v">0</span></div>
          <div class="outChip def"><span class="k">Deferred</span><span class="v">0</span></div>
          <div class="outChip cmp"><span class="k">Complained</span><span class="v">0</span></div>
        </div>
        <div class="outMeta">Pending (sent - final outcomes): <b>0</b> · PMTA queue now: <b>0</b></div>
        <div class="outMeta">Last accounting update: —</div>
      </div>
      <div class="outTrend" data-k="outcomeTrend">Trend · —</div>
    </div>

    <div class="moreGrid moreBlock">
      <div class="panel" id="job-providers">
        <h4 data-k="domainsPanelTitle">Top providers</h4>
        <div class="mini" data-k="topDomains">Gmail: <b>0</b> · Yahoo: <b>0</b> · Outlook: <b>0</b> · iCloud: <b>0</b> · Other: <b>1</b></div>
        <div class="mini" style="margin-top: 10px; display: none;"><b>Domain progress (bars)</b></div>
        <div data-k="topDomainsBars"><div style="margin-top:10px"><div class="mini"><b>Gmail</b> · 0</div><div class="smallBar"><div style="width:0%"></div></div></div><div style="margin-top:10px"><div class="mini"><b>Yahoo</b> · 0</div><div class="smallBar"><div style="width:0%"></div></div></div><div style="margin-top:10px"><div class="mini"><b>Outlook</b> · 0</div><div class="smallBar"><div style="width:0%"></div></div></div><div style="margin-top:10px"><div class="mini"><b>iCloud</b> · 0</div><div class="smallBar"><div style="width:0%"></div></div></div><div style="margin-top:10px"><div class="mini"><b>Other</b> · 1</div><div class="smallBar"><div style="width:100%"></div></div></div></div>
      </div>

      <div class="panel">
        <h4 class="sopHeader">📌 System / Provider / Integrity</h4>

        <div class="sopBlock">
          <div class="sopLabel system">🖥️ System / Internal</div>
          <div class="sopLine" data-k="systemSummary">🔗 Bridge failures: <b>0</b> · ⏱️ Last bridge success: <b>0m ago</b> · ⚙️ Runtime internal errors: <b>0</b> · 💾 DB write failures: <b>0</b></div>
          <details class="errorFold">
            <summary>View details</summary>
            <div class="mini" style="margin-top:8px" data-k="systemDetails">—</div>
          </details>
        </div>

        <div class="sopBlock">
          <div class="sopLabel provider">📬 Provider / Deliverability</div>
          <div class="sopLine" data-k="providerSummary">✅ Delivered: <b>0</b> (—) · ⏳ Deferred: <b>0</b> (—) · ❌ Bounced: <b>0</b> (—) · 📢 Complained: <b>0</b> (—)</div>
          <div class="sopLine" style="margin-top:6px" data-k="providerBreakdown">🌐 Provider/domain breakdown: —</div>
          <div class="sopLine" style="margin-top:6px" data-k="providerReasons">🧠 Top reason buckets: —</div>
          <details class="errorFold">
            <summary>View details</summary>
            <div class="mini" style="margin-top:8px" data-k="providerDetails">—</div>
          </details>
        </div>

        <div class="sopBlock">
          <div class="sopLabel integrity">🗂️ Data Integrity / Mapping</div>
          <div class="sopLine" data-k="integritySummary">♻️ duplicates_dropped: <b>0</b> · 🔎 job_not_found: <b>0</b> · 🧾 missing_fields: <b>0</b> · 💽 db_write_failures: <b>0</b></div>
          <details class="errorFold">
            <summary>View details</summary>
            <div class="mini" style="margin-top:8px" data-k="integrityDetails">—</div>
          </details>
        </div>

        <div class="legacyDiagnosticsBox">
          <div class="legacyDiagnosticsTitle">📄 Legacy quality + errors (unchanged data)</div>
          <div class="legacySectionLabel">📊 Quality counters</div>
          <div class="mini legacyDataLine" data-k="counters">safe_total=0 · safe_invalid=0 · invalid_filtered=0 · skipped=0 · backoff_events=0 · abandoned_chunks=1 · paused=no · stop_requested=no</div>
          <div class="legacySectionLabel">🚨 Error type</div>
          <div class="mini legacyDataLine" data-k="errorTypes">—</div>
          <div class="legacySectionLabel">⚠️ Error summary</div>
          <div class="mini legacyDataLine" data-k="lastErrors">—</div>
          <div class="mini legacyDataLine" data-k="lastErrors2">—</div>
          <div class="mini legacyDataLine" data-k="internalErrors">—</div>
        </div>
        <div class="bridgeSnapshotBox">
          <div class="legacySectionLabel" style="margin-top:0">🌉 Data source: Bridge snapshot</div>
          <div class="mini legacyDataLine" style="margin-top:8px" data-k="bridgeReceiver">Data source: <b>Bridge snapshot</b><br>Last poll success: <b>2026-03-22T11:55:02Z (2m ago)</b><br>Last accounting update: <b>—</b></div>
        </div>
      </div>
    </div>

    <div class="panel" id="job-chunk-preflight" style="margin-top:10px">
      <h4>Chunk preflight</h4>
      <div class="mini" style="margin-top:6px"><b>Active / Live chunk</b></div>
      <div style="overflow:auto; margin-top:8px">
        <table>
          <thead>
            <tr>
              <th>Chunk</th>
              <th>Status</th>
              <th>Size</th>
              <th>Sender mail</th>
              <th>Receiver domain</th>
              <th>Spam</th>
              <th>Blacklist</th>
            </tr>
          </thead>
          <tbody data-k="chunkLive"><tr><td colspan="7" class="mini">No active chunk right now.</td></tr></tbody>
        </table>
      </div>

      <div class="mini" style="margin-top:10px"><b>History chunk (last 12)</b></div>
      <div style="overflow:auto; margin-top:8px">
        <table>
          <thead>
            <tr>
              <th>Chunk</th>
              <th>Status</th>
              <th>Size</th>
              <th>Sender mail</th>
              <th>Receiver domain</th>
              <th>Spam</th>
              <th>Blacklist</th>
              <th>Attempt</th>
              <th>Next retry</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody data-k="chunkHist"><tr><td>2</td><td>abandoned</td><td>1</td><td title="welcome@101crossroadsstudio.com">welcome@101crossroadsstudio.co…</td><td>srv1.mail-tester.com</td><td>-1.90</td><td title="domain:101crossroadsstudio.com=&gt;dbl.spamhaus.org">domain:101crossroadsstudio.com…</td><td><b>0</b></td><td><span title="">—</span></td><td title="preflight_blocked: blacklist">preflight_blocked: blacklist</td></tr></tbody>
        </table>
      </div>
    </div>
  </details>
</div>
"""


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
    }
    a{color:var(--accent); text-decoration:none}
    .shell{display:grid; grid-template-columns:280px 1fr; min-height:100vh}
    .sidebar{padding:22px 18px; border-right:1px solid rgba(255,255,255,.08); background:rgba(5,10,18,.35); position:sticky; top:0; height:100vh}
    .brand{font-weight:900; font-size:22px; letter-spacing:.3px}
    .brandSub{margin-top:8px; color:var(--muted); font-size:13px; line-height:1.6}
    .menu{display:flex; flex-direction:column; gap:10px; margin-top:22px}
    .menu a{display:flex; align-items:center; gap:10px; padding:12px 14px; border-radius:14px; border:1px solid rgba(255,255,255,.1); background:rgba(255,255,255,.04)}
    .menu a.active{background:rgba(122,167,255,.18); border-color:rgba(122,167,255,.35); font-weight:800}
    .sidebarCard{margin-top:18px; padding:14px; border-radius:16px; border:1px solid var(--border); background:linear-gradient(180deg,var(--card),var(--card2)); box-shadow:var(--shadow)}
    .content{padding:28px 18px 28px 24px}
    .wrap{max-width: 1100px; margin: 0 auto;}
    .top{
      display:flex; gap:14px; align-items:flex-start; justify-content:space-between;
      flex-wrap:wrap; margin-bottom: 18px;
    }
    h1,.title{ margin:0; font-size: 22px; letter-spacing: .2px; }
    .title{font-size:28px}
    .sub,.subtitle{
      margin-top:6px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
      max-width: 980px;
    }
    .subtitle{font-size:14px; line-height:1.7}
    .badge,.pill,.tag{
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
    .tag{padding:5px 10px; font-weight:800; box-shadow:none; background:rgba(255,255,255,.06)}
    .tag.good,.tone-good{color:var(--good); border-color:rgba(53,228,154,.35)}
    .tag.bad,.tone-bad{color:var(--bad); border-color:rgba(255,94,115,.35)}
    .tag.warn,.tone-warn{color:var(--warn); border-color:rgba(255,193,77,.35)}
    .tag.accent,.tone-accent{color:var(--accent); border-color:rgba(122,167,255,.35)}
    .topActions{ display:flex; flex-direction:column; gap:10px; align-items:flex-end; }
    .topLinks{ display:flex; gap:10px; flex-wrap:wrap; justify-content:flex-end; }
    .grid{ display:grid; gap: 14px; }
    .grid.kpis{grid-template-columns:repeat(4,minmax(0,1fr))}
    .grid.two{grid-template-columns:1.2fr .8fr}
    .grid.three{grid-template-columns:repeat(3,minmax(0,1fr))}
    .grid.send-layout{grid-template-columns: minmax(0, 1.05fr) minmax(340px, .95fr)}
    .stack{ display:flex; flex-direction:column; gap:14px; }
    .card{
      background: linear-gradient(180deg, var(--card), var(--card2));
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 16px;
      backdrop-filter: blur(10px);
    }
    .card h2,.card h3,.card h4{ margin:0 0 10px; font-size: 16px; color: rgba(255,255,255,.88); }
    label{ display:block; margin: 10px 0 6px; color: var(--muted); font-size: 12px; font-weight:700; }
    input, select, textarea{
      width:100%;
      padding: 11px 12px;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,.16);
      background: rgba(0,0,0,.18);
      color: var(--text);
      outline: none;
      font: inherit;
    }
    input::placeholder, textarea::placeholder{color: rgba(255,255,255,.35)}
    textarea{min-height: 130px; resize: vertical}
    .row,.split,.telemetryRow{ display:grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .hint,.alert,.laneBox,.emptyState,.check{
      padding: 10px 12px;
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,.14);
      background: rgba(255,255,255,.06);
      color: var(--muted);
      font-size: 12px;
      line-height: 1.6;
    }
    .alert{margin-bottom:10px}
    .alert.good{ border-color: rgba(53,228,154,.35); background: rgba(53,228,154,.08); }
    .alert.warn{ border-color: rgba(255,193,77,.35); background: rgba(255,193,77,.08); }
    .alert.bad{ border-color: rgba(255,94,115,.35); background: rgba(255,94,115,.08); }
    .alert.accent{ border-color: rgba(122,167,255,.35); background: rgba(122,167,255,.08); }
    .actions{display:flex; gap:10px; align-items:center; justify-content:flex-start; flex-wrap: wrap; margin-top: 14px;}
    .btn, button{
      border: 1px solid rgba(255,255,255,.18);
      background: rgba(122,167,255,.18);
      color: var(--text);
      padding: 12px 14px;
      border-radius: 14px;
      cursor:pointer;
      font-weight: 600;
      letter-spacing:.2px;
      font:inherit;
    }
    .btn:hover, button:hover{filter: brightness(1.06)}
    .btn.secondary, button.secondary{ background: rgba(255,255,255,.08); }
    .btn:disabled, button:disabled{ opacity:.55; cursor:not-allowed; }
    .check{display:flex; gap: 8px; align-items:flex-start; margin-top: 12px; background: rgba(0,0,0,.12)}
    .check input{width:auto; margin-top: 2px;}
    .foot,.footerNote{ margin-top: 16px; color: rgba(255,255,255,.45); font-size: 12px; line-height: 1.7; }
    .mini,.muted{ font-size: 12px; color: var(--muted); margin-top: 8px; }
    code{background:rgba(255,255,255,.08); padding:2px 6px; border-radius:8px;}
    .smallBar,.bar{height:10px; border-radius:999px; background:rgba(255,255,255,.10); border:1px solid rgba(255,255,255,.12); overflow:hidden}
    .smallBar > div,.bar > div{height:100%; width:0%; background: linear-gradient(90deg, var(--accent), rgba(53,228,154,.75));}
    .nav{display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin:8px 0 14px;}
    .nav a, .nav button{display:inline-flex; align-items:center; gap:8px; padding:8px 10px; border:1px solid rgba(255,255,255,.14); background: rgba(255,255,255,.06); border-radius: 12px; text-decoration:none;}
    .nav a:hover{filter:brightness(1.06)}
    .nav a.primary{ background: rgba(122,167,255,.14); font-weight:800; }
    table{width:100%; border-collapse:collapse; font-size: 12px;}
    th,td{padding:8px; border-bottom:1px solid rgba(255,255,255,.10); text-align:left; vertical-align:top}
    .statsList{display:grid; gap:10px}
    .kpi .label{font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.4px}
    .kpi .value{font-size:28px; font-weight:900; margin-top:6px}
    .progressLine{margin-top:10px}
    .field{margin-bottom:12px}
    .toast-wrap{ position: fixed; right: 16px; bottom: 16px; z-index: 9999; display:flex; flex-direction:column; gap:10px; }
    .toast{ min-width: 280px; max-width: 420px; background: rgba(0,0,0,.55); border: 1px solid rgba(255,255,255,.18); box-shadow: 0 18px 55px rgba(0,0,0,.35); backdrop-filter: blur(10px); border-radius: 14px; padding: 12px 14px; color: rgba(255,255,255,.92); font-size: 13px; line-height: 1.5; animation: pop .18s ease-out; }
    @keyframes pop{ from{ transform: translateY(6px); opacity: .2; } to{ transform: translateY(0); opacity: 1; } }
    .toast .t{font-weight:800; margin-bottom:4px}
    .toast.good{ border-color: rgba(53,228,154,.35); }
    .toast.bad{ border-color: rgba(255,94,115,.35); }
    .toast.warn{ border-color: rgba(255,193,77,.35); }
    .inline-status{ margin-top: 10px; padding: 10px 12px; border-radius: 14px; border: 1px solid rgba(255,255,255,.14); background: rgba(0,0,0,.12); color: var(--muted); font-size: 12px; line-height: 1.6; display:none; }
    .inline-status.show{ display:block; }
    .inline-status b{ color: rgba(255,255,255,.88); }
    .sectionNav{display:flex; gap:10px; flex-wrap:wrap; margin:14px 0 18px}
    .sectionNav a{display:inline-flex; align-items:center; gap:8px; padding:10px 12px; border-radius:999px; border:1px solid rgba(255,255,255,.14); background:rgba(255,255,255,.05)}
    .job{padding:18px; border-radius:22px; border:1px solid var(--border); background:linear-gradient(180deg, rgba(9,16,28,.92), rgba(11,24,38,.84)); box-shadow:var(--shadow)}
    .jobTop{display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap}
    .titleRow,.triageRow,.kpiRow,.ratesRow,.outcomesGrid,.pmtaGrid,.moreGrid{display:grid; gap:10px}
    .titleRow{grid-template-columns:repeat(auto-fit,minmax(120px,max-content)); align-items:center}
    .triageRow{grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); margin-top:12px}
    .triageBadge,.chunkMetaPill,.outChip,.pmtaBox,.rateCell,.kpiCell,.sopBlock,.legacyDiagnosticsBox,.bridgeSnapshotBox{border:1px solid rgba(255,255,255,.12); background:rgba(255,255,255,.05); border-radius:16px}
    .triageBadge{display:flex; align-items:center; gap:8px; padding:10px 12px; color:var(--muted)}
    .triageBadge.good{border-color:rgba(53,228,154,.3); color:var(--good)}
    .triageBadge.bad{border-color:rgba(255,94,115,.3); color:var(--bad)}
    .statusDot{width:10px; height:10px; border-radius:999px; display:inline-block; background:currentColor}
    .badgeLabel{font-weight:700}
    .tip{cursor:help; opacity:.8}
    .jobActionNav{align-self:flex-start}
    .kpiWrap,.bars,.quickIssues,.moreBlock{margin-top:14px}
    .kpiRow{grid-template-columns:repeat(auto-fit,minmax(120px,1fr))}
    .ratesRow{grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); margin-top:10px}
    .kpiCell,.rateCell,.outChip{padding:12px}
    .kpiCell .k,.rateCell .k,.outChip .k,.pmtaKey,.pmtaHint,.pmtaSub,.sopLine,.legacyDataLine{color:var(--muted); font-size:12px}
    .kpiCell .v,.rateCell .v,.outChip .v{font-size:24px; font-weight:900; margin-top:6px}
    .kpi-del .v,.outChip.del .v,.pmtaVal.good{color:var(--good)}
    .kpi-bnc .v,.outChip.bnc .v,.bridgeConnBadge.bad{color:var(--bad)}
    .kpi-def .v,.outChip.def .v,.pmtaVal.warn{color:var(--warn)}
    .kpi-cmp .v,.outChip.cmp .v{color:#ff97cf}
    .kpi-sent .v{color:var(--accent)}
    .kpiWarn{margin-left:6px; color:var(--warn)}
    .panel{padding:16px; border-radius:18px; border:1px solid rgba(255,255,255,.12); background:rgba(255,255,255,.04)}
    .pmtaGrid{grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); margin-top:12px}
    .pmtaBox{padding:12px}
    .pmtaTitle{display:flex; justify-content:space-between; gap:8px; align-items:center; font-weight:800}
    .pmtaRow{display:flex; justify-content:space-between; gap:8px; margin-top:10px}
    .pmtaBig{font-size:22px; font-weight:900}
    .qualityMini{margin-top:12px}
    .qualityLine,.outMeta,.outTrend{margin-top:10px; color:var(--muted); font-size:12px}
    .quickIssues{padding:12px 14px; border:1px solid rgba(255,94,115,.25); background:rgba(255,94,115,.08); border-radius:14px; color:#ffd8df}
    .more summary,.errorFold summary,.qualityMini summary{cursor:pointer; font-weight:800}
    .twoCol{display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px}
    .outcomesGrid{grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); margin-top:12px}
    .moreGrid{grid-template-columns:minmax(260px,.9fr) minmax(320px,1.1fr)}
    .sopHeader{margin-bottom:12px}
    .sopBlock,.legacyDiagnosticsBox,.bridgeSnapshotBox{padding:12px; margin-top:12px}
    .sopLabel,.legacyDiagnosticsTitle,.legacySectionLabel{font-weight:800; margin-bottom:8px}
    .sopLabel.system{color:var(--accent)}
    .sopLabel.provider{color:var(--warn)}
    .sopLabel.integrity{color:var(--good)}
    .errorSummaryBox{padding:10px 12px; border-radius:14px; border:1px dashed rgba(255,255,255,.14)}
    @media (max-width: 1200px){ .grid.kpis{grid-template-columns:repeat(2,minmax(0,1fr))} .grid.two,.grid.send-layout,.split,.telemetryRow,.twoCol,.moreGrid{grid-template-columns:1fr} }
    @media (max-width: 920px){ .shell{grid-template-columns:1fr} .sidebar{position:relative; height:auto; border-right:0; border-bottom:1px solid rgba(255,255,255,.08)} .grid.three{grid-template-columns:1fr} }
    @media (max-width: 520px){ .row{grid-template-columns: 1fr;} .topActions{ align-items:stretch; width:100%; } .topLinks{ justify-content:flex-start; } .content{padding:18px 14px 24px} .sectionNav a{width:100%; justify-content:center} }
  </style>
</head>
<body>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand">Shivamini</div>
      <div class="brandSub">Unified single-file Flask frontend sandbox with the Shiva Mini Sand styling applied across dashboard, jobs, job details, config, domains, and send surfaces.</div>
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
      <div class="footerNote">All frontend surfaces now inherit the same Shiva Mini Sand dashboard visual language from this single Python file.</div>
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
{{ page_script|safe }}
</body>
</html>
"""


def render(page: str, title: str, body: str, page_script: str = ""):

    return render_template_string(
        PAGE,
        page=page,
        title=title,
        body=body,
        page_script=page_script,
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

          <div class="grid two" style="margin-top:14px">
            <div class="card">
              <h2>Operations snapshot</h2>
              <div class="grid two" style="margin-top:12px">
                {% for item in data.ops_snapshot %}
                <div class="alert {{ item.tone }}" style="margin:0">
                  <div style="font-weight:800">{{ item.label }}</div>
                  <div style="font-size:22px; font-weight:900; margin-top:8px">{{ item.value }}</div>
                  <div class="mini">{{ item.hint }}</div>
                </div>
                {% endfor %}
              </div>
            </div>
            <div class="card">
              <h2>Dashboard fake notes</h2>
              <div class="statsList" style="margin-top:12px">
                {% for note in data.dashboard_notes %}
                <div class="alert {{ note.tone }}" style="margin:0">
                  <div style="font-weight:800">{{ note.title }}</div>
                  <div class="mini" style="margin-top:6px">{{ note.body }}</div>
                </div>
                {% endfor %}
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
    body = render_template_string(SEND_PAGE_BODY, campaign_ts=NOW.strftime("%Y-%m-%d %H:%M:%S"))
    page_script = "<script>\n" + SEND_PAGE_SCRIPT + "\n</script>"
    return render("send", "Shivamini Send", body, page_script=page_script)


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
    return render_template_string(build_jobs_page_html())


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
