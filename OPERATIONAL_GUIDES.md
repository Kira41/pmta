# Operational Guides

هذا الملف يجمع ملفات الشرح التشغيلية في المشروع (باستثناء ملف `ENVIRONMENT_VARIABLES.md` الذي يبقى مستقلاً).

---

## 1) Accounting Flow (Shiva Pull Model)

التدفق الحالي يعمل بنمط **Pull** من Shiva إلى bridge:

1. Bridge (`pmta_accounting_bridge.py`) يقرأ ملفات PMTA accounting.
2. Shiva (`shiva.py`) ينفّذ طلبات دورية إلى bridge API عبر IP السيرفر.
3. Bridge يعيد سطور البيانات فقط.
4. Shiva يفسّر السطور ويحدّث outcomes الخاصة بالـ jobs/campaigns.

> بهذه الطريقة لا يحتاج Shiva إلى public IP ليستقبل push.

### Bridge API endpoint

- `GET /api/v1/pull/latest?kind=acct&max_lines=<N>`
- المصادقة: `Authorization: Bearer <API_TOKEN>` (أو `?token=` كخيار بديل)

### مثال استجابة

```json
{
  "ok": true,
  "kind": "acct",
  "file": "acct-2026-02-24.csv",
  "from_offset": 12345,
  "to_offset": 14789,
  "has_more": false,
  "count": 120,
  "lines": ["{...}", "{...}"]
}
```

### إعدادات Shiva (Pull Mode)

```bash
export PMTA_BRIDGE_PULL_ENABLED=1
export PMTA_BRIDGE_PULL_URL="http://194.116.172.135:8090/api/v1/pull/latest?kind=acct"
export PMTA_BRIDGE_PULL_TOKEN="<API_TOKEN>"
export PMTA_BRIDGE_PULL_S=5
export PMTA_BRIDGE_PULL_MAX_LINES=2000
```

### إعدادات Bridge

```bash
export API_TOKEN="<API_TOKEN>"
export PMTA_LOG_DIR="/var/log/pmta"
python3 pmta_accounting_bridge.py
```

### فحوصات الجاهزية

```bash
# 1) اختبار endpoint على bridge
curl -i -H "Authorization: Bearer <API_TOKEN>" \
  "http://194.116.172.135:8090/api/v1/pull/latest?kind=acct&max_lines=5"

# 2) حالة إعدادات bridge داخل Shiva
curl -s "http://127.0.0.1:5000/api/accounting/bridge/status"

# 3) تنفيذ سحب يدوي من Shiva
curl -s -X POST "http://127.0.0.1:5000/api/accounting/bridge/pull"
```

الإشارات المتوقعة:

- `pull_enabled=true`
- `pull_url` مضبوط على endpoint السحب
- نجاح طلب السحب اليدوي وتحديث outcomes

---

## 2) Multi Sender Domains Scenario

هذا القسم يشرح سلوك التوزيع عند استخدام عدة Sender Domains.

### الفكرة العامة

التوزيع يتم على مستويين:

1. **داخل Shiva:** اختيار `from_email` بطريقة rotation لكل chunk.
2. **داخل PowerMTA:** ربط `MAIL FROM` مع `virtual-mta`/IP مناسب (strict 1:1 domain→IP).

### مثال عملي (5 دومينات Sender)

إذا كانت القيم في Sender Email كالتالي (كل سطر مرسل مختلف):

- `a@mediapaypro.cloud`
- `b@mediapaypro.info`
- `c@mediapaypro.live`
- `d@mediapaypro.vip`
- `e@mediapaypro.work`

فالسلوك يكون:

1. تجميع المستلمين حسب recipient domain (مثل `gmail.com`, `yahoo.com`, `outlook.com`).
2. الإرسال بنمط round-robin عبر buckets بدلاً من إنهاء provider واحد بالكامل.
3. تدوير المرسل (`from_email`) بشكل عادل أثناء العمل.

### النتيجة المتوقعة

- توزيع أكثر توازنًا على providers.
- تقليل الاندفاع على provider واحد.
- الحفاظ على سياسة الربط الصارم domain→IP داخل PMTA.

### ماذا يحدث إذا دخل Chunk في Backoff؟

هذا السؤال مهم لأنه يحدد هل التوقف يكون على مستوى chunk واحد أم على مستوى job كامل.

1. **الـ backoff يطبق على الـ chunk الحالي فقط (المستهدف لدومين واحد)**
   - كل chunk يتم بناؤه من bucket خاص بـ recipient domain واحد (`target_domain`).
   - إذا فشل pre-check (spam/PMTA policy/blacklist) لهذا chunk، يدخل في backoff مع retry لنفس chunk.

2. **لا يتم الانتقال مباشرةً لباقي الشانكات أثناء انتظار backoff**
   - الحلقة الرئيسية تنتظر انتهاء backoff (`sleep`) ثم تعيد فحص نفس chunk.
   - يعني عمليًا التنفيذ sequential على مستوى الشانكات: إما chunk الحالي ينجح، أو يُترك (abandoned) بعد تجاوز عدد المحاولات.

3. **تدوير المرسل يحصل تلقائيًا عند إعادة المحاولة**
   - مع كل retry يزيد المؤشر (`attempt`) فيتغير `from_email`/`subject`/`body variant` (حسب الدوران).
   - الهدف إعطاء فرصة لـ route/domain مختلف إذا القائمة تحتوي أكثر من sender domain.

4. **في حالة تعدد الدومينات (recipient domains كثيرة)**
   - Shiva يختار الدومينات بنمط round-robin بين buckets (`gmail` ثم `yahoo` ثم `outlook` ...).
   - إذا chunk لدومين معين دخل backoff، يتأخر التقدم العام مؤقتًا لأن التنفيذ لا يقفز فورًا لـ domain آخر قبل حسم chunk الحالي.
   - بعد نجاح/abandon لهذا chunk، يكمل الدوران طبيعيًا على بقية الدومينات.

> خلاصة تشغيلية: backoff **ليس إيقاف دائم لكل job**، لكنه **pause مؤقت لمسار التنفيذ الحالي** حتى يُعاد تقييم نفس chunk، مع تدوير sender تلقائيًا لمحاولة تحسين المرور.

---

## ملاحظات تنظيمية

- الملف `ENVIRONMENT_VARIABLES.md` متروك بشكل مستقل لأنه ملف مرجعي خاص بالمتغيرات.
- جميع الشروحات التشغيلية الأخرى تم تجميعها هنا لتسهيل الوصول.

---

## 3) دليل شرح المتغيرات (Variables Explanation Guide)

هذا القسم يكمّل `ENVIRONMENT_VARIABLES.md` بشكل تشغيلي سريع، ويربط المتغيرات مباشرةً مع الدوال التي تعتمد عليها.

### متى أرجع لأي ملف؟
- **تفصيل كامل لكل متغير (الدوال + التأثير + السيناريو):** راجع القسم 16 في `ENVIRONMENT_VARIABLES.md`.
- **تشغيل يومي سريع:** استخدم هذا القسم كـ playbook مختصر.

### Playbook مختصر حسب السيناريو

1. **Bridge لا يرجع بيانات accounting**
   - راجع: `PMTA_LOG_DIR`, `PMTA_BRIDGE_PULL_URL`, `PMTA_BRIDGE_PULL_MAX_LINES`.
   - الدوال المؤثرة: `list_dir_files`, `_find_latest_file`, `_poll_accounting_bridge_once`.

2. **401/403 بين Shiva وBridge**
   - راجع: `ALLOW_NO_AUTH`, `PMTA_BRIDGE_PULL_TOKEN`.
   - الدوال المؤثرة: `require_token`, `_poll_accounting_bridge_once`.

3. **تباطؤ شديد مع ضغط على PMTA**
   - راجع: `PMTA_PRESSURE_*`, `PMTA_QUEUE_BACKOFF`, `PMTA_DOMAIN_*`.
   - الدوال المؤثرة: `pmta_pressure_policy_from_live`, `pmta_chunk_policy`.

4. **مشاكل false timeout في المراقبة**
   - راجع: `PMTA_MONITOR_TIMEOUT_S`, `PMTA_MONITOR_SCHEME`, `PMTA_MONITOR_BASE_URL`.
   - الدوال المؤثرة: `_http_get_json`, `pmta_health_check`, `pmta_probe_endpoints`.

5. **جودة لوائح ضعيفة / bounce مرتفع**
   - راجع: `RECIPIENT_FILTER_ENABLE_SMTP_PROBE`, `RECIPIENT_FILTER_SMTP_PROBE_LIMIT`, `RECIPIENT_FILTER_SMTP_TIMEOUT`.
   - الدالة المؤثرة: `pre_send_recipient_filter`.

6. **تحسين تقييم المحتوى قبل الإرسال**
   - راجع: `SPAMCHECK_BACKEND`, `SPAMD_HOST`, `SPAMD_PORT`, `SPAMD_TIMEOUT`.
   - الدوال المؤثرة: `compute_spam_score`, `_score_via_spamd`.

7. **AI rewrite بطيء أو غير مناسب**
   - راجع: `OPENROUTER_MODEL`, `OPENROUTER_TIMEOUT_S`, `OPENROUTER_ENDPOINT`.
   - الدالة المؤثرة: `ai_rewrite_subjects_and_body`.

---

## 4) Troubleshooting سريع: PMTA Monitor errors + Backoff

هذا القسم يجاوب مباشرةً على أكثر سؤالين شائعين:

1) لماذا أخطاء PMTA لا تظهر في الـ monitor داخل الـ dashboard؟
2) خيار backoff يكون `active` أم `disable`؟

### A) إعداد PMTA الصحيح لوصول بيانات الأخطاء إلى الـ monitor

تأكد أن PMTA يسمح للـ monitor API + يكتب ملفات `acct/diag`:

```pmta
# PMTA monitor API
http-mgmt-port 8080
http-access 0.0.0.0/0 admin
http-access 0.0.0.0/0 monitor

# accounting + diagnostics logs
<acct-file /var/log/pmta/acct.csv>
    max-size 50M
</acct-file>

<acct-file /var/log/pmta/diag.csv>
    move-interval 1d
    delete-after never
    records t
</acct-file>
```

> أمنيًا في الإنتاج: بدّل `0.0.0.0/0` بـ IP محدد (`x.x.x.x/32`) بدل فتحه للجميع.

### B) إعداد Shiva الصحيح للاتصال بالـ monitor

ضع هذه القيم في `.env` (أو Environment):

```bash
# PMTA monitor connectivity
PMTA_MONITOR_SCHEME=auto
# إن كان monitor على نفس smtp_host اترك BASE_URL فارغ
PMTA_MONITOR_BASE_URL=
PMTA_MONITOR_TIMEOUT_S=3
# إذا عندك http-api-key في PMTA
PMTA_MONITOR_API_KEY=

# مهم: اجعلها 1 لكي يعتبر monitor failure خطأ فعلي
PMTA_HEALTH_REQUIRED=1

# Backoff global (checkbox default)
ENABLE_BACKOFF=1
BACKOFF_MAX_RETRIES=3
BACKOFF_BASE_S=60
BACKOFF_MAX_S=1800

# PMTA policy-based backoff
PMTA_QUEUE_BACKOFF=1
PMTA_QUEUE_REQUIRED=0

# Disable DNSBL/DBL blacklist checks بالكامل (اختياري)
SHIVA_DISABLE_BLACKLIST=0  # يقبل: 1/0, true/false, yes/no (alias: DISABLE_BLACKLIST)
```

### C) جواب مباشر: backoff يكون Active أم Disable؟

- **القيمة الصحيحة لتفعيل backoff الطبيعي هي: `active` (أو `1` / ON).**
- إذا وضعت **disable** فمعناه أنك **أوقفت** آلية backoff، وبالتالي الإرسال يكمل حتى مع إشارات منع/ضغط.

### D) فحص سريع إذا الأخطاء لا تزال لا تظهر

نفّذ الاختبارات التالية بالترتيب:

```bash
# 1) PMTA status API
curl -sk "https://<PMTA_IP>:8080/status?format=json"

# 2) PMTA queues API (مصدر last_error/deferrals)
curl -sk "https://<PMTA_IP>:8080/queues?format=json"

# 3) Shiva يقرأ monitor كما يجب
curl -s "http://127.0.0.1:5000/api/config/runtime" | jq '.PMTA_MONITOR_BASE_URL,.PMTA_MONITOR_SCHEME,.PMTA_HEALTH_REQUIRED,.PMTA_QUEUE_BACKOFF,.ENABLE_BACKOFF'
```

لو (1) أو (2) فشلوا، المشكلة من PMTA monitor access / scheme / api-key.  
لو نجحوا لكن dashboard لا يعكس الأخطاء، المشكلة غالبًا من قيم backoff أو من runtime config غير معمولة لها reload.
