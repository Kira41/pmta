# تقرير شامل: طريقة اتصال Shiva مع Bridge

> هذا التقرير يشرح تدفّق الاتصال بين `shiva.py` و `pmta_accounting_bridge.py` بشكل تفصيلي، مع اقتباسات مباشرة من الكود، أسماء الدوال، المتغيرات، وسلوك النظام وقت التشغيل.

## 1) الصورة العامة للتدفّق

- Bridge يعرّف خدمة API عبر FastAPI ويقدّم endpoint رئيسي للسحب:

```python
@app.get("/api/v1/pull")
def pull_accounting(...):
    ...
```

- Shiva يعمل بنمط **Pull** (وليس Push) ويستدعي هذا endpoint دوريًا:

```python
PMTA_BRIDGE_PULL_PATH = "/api/v1/pull"
...
def _resolve_bridge_pull_url_runtime() -> str:
    host = _normalize_bridge_host(_resolve_bridge_pull_host_from_campaign())
    limit = max(1, int(PMTA_BRIDGE_PULL_MAX_LINES or 2000))
    return f"http://{host}:{PMTA_BRIDGE_PULL_PORT}{PMTA_BRIDGE_PULL_PATH}?kinds=acct&limit={limit}"
```

## 2) جهة Bridge (`pmta_accounting_bridge.py`)

### 2.1 الإعدادات الأساسية

```python
PMTA_LOG_DIR = Path(os.getenv("PMTA_LOG_DIR", "/var/log/pmta")).resolve()
DEFAULT_PULL_LIMIT = int(os.getenv("DEFAULT_PULL_LIMIT", "500"))
MAX_PULL_LIMIT = int(os.getenv("MAX_PULL_LIMIT", "2000"))
RECENT_PULL_MAX_FILES = int(os.getenv("RECENT_PULL_MAX_FILES", "32"))
RECENT_PULL_MAX_AGE_HOURS = int(os.getenv("RECENT_PULL_MAX_AGE_HOURS", "48"))
```

**التحليل:**
- هذه المتغيرات تتحكم في: عدد السطور في كل طلب، سقف الحماية، وعدد/عمر الملفات المفحوصة.
- Bridge لا يقرأ كل الأرشيف التاريخي؛ يركز على الملفات الحديثة لتخفيف الحمل.

### 2.2 المصادقة (مفتوحة)

```python
def require_token(_: Request):
    """Bridge API is intentionally open; no token/auth is required."""
    return None
```

**التحليل:**
- لا يوجد token بين Shiva وBridge في هذا المسار.

### 2.3 آلية اختيار الملفات

```python
def _recent_matching_files(patterns: List[str]) -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc).timestamp()
    min_mtime = now - max(1, RECENT_PULL_MAX_AGE_HOURS) * 3600
    ...
    files.sort(key=lambda x: (x["mtime"], x["name"]))
    return files[-max(1, RECENT_PULL_MAX_FILES):]
```

**التحليل:**
- Bridge يبني قائمة ملفات مطابقة للأنماط (غالبًا `acct-*.csv`) ثم يقصّها لآخر `RECENT_PULL_MAX_FILES`.

### 2.4 آلية Cursor في Bridge

```python
def _encode_cursor(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _decode_cursor(cursor: str) -> Dict[str, Any]:
    ...
```

ومع القراءة:

```python
def _read_from_cursor(files: List[Dict[str, Any]], cursor_payload: Optional[Dict[str, Any]], limit: int) -> Dict[str, Any]:
    ...
    next_cursor = _encode_cursor({
        "v": 1,
        "path": cursor_file["path"],
        "inode": int(cursor_file["inode"]),
        "offset": int(current_off),
        "mtime": float(cursor_file["mtime"]),
    })
    ...
    return {
        "items": items,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "stats": {...},
    }
```

**التحليل:**
- `cursor` يحتوي: مسار الملف + inode + offset + mtime.
- هذا يمنع تكرار السحب ويتيح الاستكمال من نفس النقطة بعد restart.

### 2.5 Endpoint السحب الذي يستهلكه Shiva

```python
@app.get("/api/v1/pull")
def pull_accounting(...):
    requested_kinds = [x.strip() for x in (kinds or "").split(",") if x.strip()]
    ...
    safe_limit = max(1, min(MAX_PULL_LIMIT, int(limit or DEFAULT_PULL_LIMIT)))
    files = _recent_matching_files(patterns)
    payload = _decode_cursor(cursor) if cursor else None
    result = _read_from_cursor(files, payload, safe_limit)
    ...
    return {
        "ok": True,
        "kinds": requested_kinds,
        "count": len(result["items"]),
        **result,
    }
```

**التحليل:**
- يرجّع `items` + `next_cursor` + `has_more` + `stats`.
- لو فشل parsing أو cursor، يعيد أخطاء HTTP مع `invalid_cursor` أو غيرها.

### 2.6 تحويل سطر accounting إلى حدث Structured

```python
def _structured_event(ev: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": ...,
        "outcome": _normalized_outcome(ev),
        "time_logged": ...,
        "orig": ...,
        "rcpt": ...,
        "job_id": _event_job_id(ev),
        "campaign_id": _event_campaign_id(ev),
        "message_id": ...,
        "dsn_action": ...,
        "dsn_status": ...,
        "dsn_diag": ...,
        "source_file": ...,
        "line_no_or_offset": ...,
    }
```

**التحليل:**
- هذا هو payload الفعلي الذي يستقبله Shiva غالبًا كـ dict جاهز.

---

## 3) جهة Shiva (`shiva.py`) – كيف يتصل فعليًا

### 3.1 متغيرات الاتصال الأساسية

```python
PMTA_BRIDGE_PULL_ENABLED = ...
PMTA_BRIDGE_PULL_PORT = ...
PMTA_BRIDGE_PULL_PATH = "/api/v1/pull"
PMTA_BRIDGE_PULL_S = ...
PMTA_BRIDGE_PULL_MAX_LINES = ...
```

**المعنى:**
- `ENABLED`: تشغيل/إيقاف poller.
- `PORT` + `PATH`: عنوان endpoint في Bridge.
- `PULL_S`: الفاصل الزمني بين كل poll.
- `MAX_LINES`: قيمة limit التي يطلبها Shiva من Bridge.

### 3.2 تحديد Host ديناميكيًا من الحملة

```python
def _resolve_bridge_pull_host_from_campaign() -> str:
    ...
    for job in jobs:
        host = (getattr(job, "smtp_host", "") or "").strip()
        if host:
            return host
    ...
    return "127.0.0.1"
```

ثم التطبيع:

```python
def _normalize_bridge_host(raw_host: str) -> str:
    ...
```

ثم بناء URL النهائي:

```python
def _resolve_bridge_pull_url_runtime() -> str:
    ...
    return f"http://{host}:{PMTA_BRIDGE_PULL_PORT}{PMTA_BRIDGE_PULL_PATH}?kinds=acct&limit={limit}"
```

**التحليل:**
- Shiva لا يعتمد مباشرة على IP ثابت للسيرفر؛ يأخذ `smtp_host` من آخر job فعّال.
- يدعم host بصيغة URL أو host:port أو IPv6 bracketed.

### 3.3 حفظ cursor داخل SQLite في Shiva

```python
def _db_get_bridge_cursor() -> str:
    row = conn.execute("SELECT value FROM bridge_pull_state WHERE key='accounting_cursor'").fetchone()


def _db_set_bridge_cursor(cursor: str) -> None:
    _exec_upsert_compat(... key='accounting_cursor' ...)
```

**التحليل:**
- هذا هو ربط مهم مع Bridge Cursor: Shiva يحفظ آخر `next_cursor` ويستأنف منه.

### 3.4 منطق الاتصال الشبكي مع Bridge

```python
def _poll_accounting_bridge_once() -> dict:
    raw_url = _resolve_bridge_pull_url_runtime()
    pull_urls = _normalize_bridge_pull_urls(raw_url)
    headers = {"Accept": "application/json"}
    cursor = _db_get_bridge_cursor()
    ...
    req = Request(req_url, headers=headers, method="GET")
    with urlopen(req, timeout=20) as resp:
        raw = (resp.read() or b"{}").decode("utf-8", errors="replace")
```

**تفاصيل مهمة:**
- يوجد retry (`max_request_attempts = 3`).
- fallback بين مسارات `/api/v1/pull` و `/api/v1/pull/latest` في `_normalize_bridge_pull_urls`.
- timeout الطلب 20 ثانية.

### 3.5 كيف Shiva يقرأ payload القادم من Bridge

```python
obj = json.loads(raw)
lines = obj.get("lines") if isinstance(obj, dict) else None
bridge_rows: List[Any] = []
if isinstance(lines, list):
    bridge_rows = list(lines)
elif isinstance(obj, dict):
    for key in ("events", "outcomes", "results", "messages", "items", "rows", "data"):
        v = obj.get(key)
        if isinstance(v, list):
            bridge_rows = v
            break
```

**التحليل:**
- Shiva متسامح مع عدة أسماء مفاتيح، وليس فقط `items`.
- هذا يحافظ على التوافق مع نسخ Bridge مختلفة.

### 3.6 معالجة كل Event داخل Shiva

```python
for row in bridge_rows:
    if isinstance(row, dict):
        ev = row
    else:
        ev = _parse_accounting_line(s2, path="bridge")
    res = process_pmta_accounting_event(ev)
```

الدالة المركزية:

```python
def process_pmta_accounting_event(ev: dict) -> dict:
    typ = _normalize_outcome_type(...)
    rcpt = ev.get("rcpt") or ev.get("recipient") or ...
    job_id = _event_value(ev, "header_x-job-id", "x-job-id", "job-id", "job_id", "jobid").lower()
    campaign_id = _event_value(ev, "x-campaign-id", "campaign-id", "campaign_id", "cid")
    msgid = _event_value(ev, "msgid", "message-id", ...)
    ...
    event_row = _build_accounting_event_row(ev, typ, rcpt, job_id)
    if not db_insert_accounting_event(event_row):
        return {"ok": True, "duplicate": True, ...}
    ...
    job = JOBS.get(job_id) ... or _find_job_by_campaign(...) or _find_job_by_recipient(...)
    if not job:
        return {"ok": False, "reason": "job_not_found", ...}
    _apply_outcome_to_job(job, rcpt, typ, ev)
    _record_accounting_error(job, rcpt, typ, ev)
```

**التحليل:**
- deduplication مبني على `event_id` ثابت (sha256) من مصدر/offset/recipient/type/time/message_id.
- في حال عدم العثور على job من `job_id`، يحاول `campaign_id` ثم recipient mapping.

### 3.7 إدارة has_more + next_cursor

```python
has_cursor_fields = isinstance(obj, dict) and any(k in obj for k in ("cursor", "next_cursor", "has_more"))
...
has_more = bool(obj.get("has_more")) if isinstance(obj, dict) and has_cursor_fields else False
next_cursor = str(obj.get("next_cursor") or obj.get("cursor") or "").strip()

if used_cursor_fields and next_cursor:
    _db_set_bridge_cursor(next_cursor)
    cursor = next_cursor

if not (used_cursor_fields and has_more):
    break
```

**التحليل:**
- طالما `has_more=true` ومعه `next_cursor`، Shiva يكرر السحب فورًا داخل نفس الدورة.
- لو `has_more=true` بدون `next_cursor` يتوقف لتجنب تكرار البيانات.

### 3.8 تشغيل poller الدوري

```python
def _accounting_bridge_poller_thread():
    while True:
        try:
            _poll_accounting_bridge_once()
        except Exception:
            pass
        time.sleep(max(1.0, float(PMTA_BRIDGE_PULL_S or 5.0)))


def start_accounting_bridge_poller_if_needed():
    if not PMTA_BRIDGE_PULL_ENABLED:
        return
    ...
```

**التحليل:**
- خيط daemon مستمر.
- الفاصل الزمني adaptive ثابت من env/UI (`PMTA_BRIDGE_PULL_S`).

### 3.9 API مراقبة الاتصال من طرف Shiva

```python
@app.get("/api/accounting/bridge/status")
def api_accounting_bridge_status():
    ...
    state["pull_url"] = runtime_url
    state["pull_url_masked"] = state["pull_url"].split("?", 1)[0]
    ...
    return jsonify({"ok": True, "bridge": state})
```

و manual trigger:

```python
@app.post("/api/accounting/bridge/pull")
def api_accounting_bridge_pull_once():
    return jsonify(_poll_accounting_bridge_once())
```

---

## 4) أهم الدوال المستخدمة في الاتصال (ملخص بالأسماء)

### داخل Bridge
- `pull_accounting`
- `_recent_matching_files`
- `_read_from_cursor`
- `_encode_cursor` / `_decode_cursor`
- `_parse_accounting_line`
- `_structured_event`
- `_event_job_id`, `_event_campaign_id`, `_normalized_outcome`
- `bridge_status`

### داخل Shiva
- `_resolve_bridge_pull_host_from_campaign`
- `_normalize_bridge_host`
- `_resolve_bridge_pull_url_runtime`
- `_normalize_bridge_pull_urls`
- `_db_get_bridge_cursor`, `_db_set_bridge_cursor`
- `_poll_accounting_bridge_once`
- `process_pmta_accounting_event`
- `_build_accounting_event_row`
- `_apply_outcome_to_job`
- `_accounting_bridge_poller_thread`, `start_accounting_bridge_poller_if_needed`
- `api_accounting_bridge_status`, `api_accounting_bridge_pull_once`

---

## 5) المتغيرات الأساسية المؤثرة

### Bridge
- `PMTA_LOG_DIR`
- `DEFAULT_PULL_LIMIT`
- `MAX_PULL_LIMIT`
- `RECENT_PULL_MAX_FILES`
- `RECENT_PULL_MAX_AGE_HOURS`
- `_BRIDGE_STATUS` (تشخيص آخر سحب)
- `_CSV_HEADER_STATE` (حالة headers لكل ملف)

### Shiva
- `PMTA_BRIDGE_PULL_ENABLED`
- `PMTA_BRIDGE_PULL_PORT`
- `PMTA_BRIDGE_PULL_PATH`
- `PMTA_BRIDGE_PULL_S`
- `PMTA_BRIDGE_PULL_MAX_LINES`
- `_BRIDGE_DEBUG_STATE` (تشخيص حي كامل)
- `_BRIDGE_CURSOR_COMPAT_WARNED`

---

## 6) نقاط القوة / المخاطر التشغيلية

### نقاط القوة
1. **Cursor-based ingestion** يقلل الضياع والتكرار عند restart.
2. **Idempotent ledger** في Shiva عبر `event_id` يمنع احتساب نفس الحدث مرتين.
3. **Fallback payload keys** يزيد التوافق بين نسخ مختلفة للـ Bridge.
4. **Debug endpoints** تسهّل troubleshooting بسرعة.

### المخاطر المحتملة
1. اختيار host من `smtp_host` في آخر job قد يسبب سحب من عنوان غير المقصود إذا الإعدادات مختلطة.
2. إذا Bridge رجّع payload بدون cursor fields، Shiva يدخل legacy mode (تحذير موجود بالكود).
3. لو `limit` صغير جدًا مع تدفق عالي، قد يتطلب دورات أكثر للحاق بالبيانات.

---

## 7) خلاصة تنفيذية

- الاتصال بين Shiva وBridge يتم عبر HTTP GET دوري إلى `/api/v1/pull` مع `kinds=acct&limit=...`.
- Bridge يقرأ ملفات PMTA accounting الحديثة، يحوّلها إلى `items` منظمة، ويرجع `next_cursor` + `has_more`.
- Shiva يستهلك الدُفعات، يطبّق dedupe، يربط event بـ job (job_id/campaign_id/recipient fallback)، ويحدّث counters/outcomes.
- حالة الاتصال قابلة للمراقبة عبر `/api/accounting/bridge/status` مع عدادات مفصلة.
