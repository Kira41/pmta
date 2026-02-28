# Environment Variables Reference

هذا الملف يجمع **جميع متغيرات البيئة (Environment Variables)** المستخدمة في الشيفرة داخل المشروع، مع شرح عملي لكل متغير وأمثلة تشغيل.

> ملاحظة مهمة: في `shiva_app.py` يوجد نظام إعدادات ديناميكي (`APP_CONFIG_SCHEMA`) يجعل القيمة الفعّالة تأتي بالترتيب التالي:
> 1) قيمة من واجهة الإعدادات (UI) إن وُجدت،
> 2) ثم Environment Variable،
> 3) ثم القيمة الافتراضية (Default).

---

## 1) متغيرات خدمة الجسر `pmta_accounting_bridge.py`

### `PMTA_LOG_DIR`
- **الافتراضي:** `/var/log/pmta`
- **الدور:** مسار ملفات لوج/أكاونتنغ PowerMTA التي يقرأ منها الـ Bridge.
- **مثال عملي:**
  - إذا وضعت: `PMTA_LOG_DIR=/opt/pmta/logs`
  - سيبدأ endpoint مثل `/api/v1/files` و`/api/v1/pull/latest` بالقراءة من هذا المسار بدل الافتراضي.

### `ALLOW_NO_AUTH`
- **الافتراضي:** `0`
- **الدور:** تعطيل/تفعيل التحقق بالتوكن للـ Bridge API.
- **السلوك:**
  - `1` = يسمح بالوصول بدون توكن (غير آمن للإنتاج).
  - غير ذلك = يفرض التوكن.
- **مثال:** في بيئة اختبار سريعة:
  - `ALLOW_NO_AUTH=1`

### `DEFAULT_PUSH_MAX_LINES`
- **الافتراضي:** `5000`
- **الدور:** عدد الأسطر الافتراضي التي يعيدها `/api/v1/pull/latest` إذا لم ترسل `max_lines` في الطلب.
- **مثال:**
  - `DEFAULT_PUSH_MAX_LINES=1000`
  - أي سحب بدون `max_lines` سيقتصر على 1000 سطر.

### `CORS_ORIGINS`
- **الافتراضي:** `*`
- **الدور:** السماح للأصول (Origins) التي يمكنها استدعاء API من المتصفح.
- **أمثلة:**
  - `CORS_ORIGINS=*` (السماح للجميع)
  - `CORS_ORIGINS=https://admin.example.com,https://ops.example.com`

### `BIND_ADDR`
- **الافتراضي:** `0.0.0.0`
- **الدور:** عنوان الشبكة الذي تستمع عليه خدمة الـ Bridge عند التشغيل المباشر.
- **مثال:** `BIND_ADDR=127.0.0.1` لجعل الخدمة محلية فقط.

### `PORT`
- **الافتراضي:** `8090`
- **الدور:** بورت تشغيل خدمة الـ Bridge.
- **مثال:** `PORT=9090`.

---

## 2) متغيرات تشغيل Flask الأساسي `shiva_app.py`

### `SHIVA_HOST`
- **الافتراضي:** `0.0.0.0`
- **الدور:** عنوان الاستماع لخدمة Shiva.
- **مثال:** `SHIVA_HOST=127.0.0.1` للاستخدام المحلي فقط.

### `SHIVA_PORT`
- **الافتراضي:** `5001`
- **الدور:** بورت تشغيل Shiva.
- **مثال:** `SHIVA_PORT=8081`.

### `DB_CLEAR_ON_START`
- **الافتراضي:** `0`
- **الدور:** إذا كان `1` يتم تفريغ جداول SQLite عند بدء التطبيق.
- **تحذير:** قد يمسح بيانات حملات/نتائج/recipients.
- **مثال:**
  - للتصفير في بيئة تطوير: `DB_CLEAR_ON_START=1`

---

## 3) Spam / SpamAssassin

### `SPAMCHECK_BACKEND`
- **الافتراضي:** `spamd`
- **القيم المقترحة:** `spamd | spamc | spamassassin | module | off`
- **الدور:** يحدد محرك حساب spam score.
- **مثال:**
  - `SPAMCHECK_BACKEND=off` لتعطيل حساب السبام نهائياً.

### `SPAMD_HOST`
- **الافتراضي:** `127.0.0.1`
- **الدور:** عنوان خادم `spamd`.
- **مثال:** `SPAMD_HOST=10.0.0.15`.

### `SPAMD_PORT`
- **الافتراضي:** `783`
- **الدور:** بورت `spamd`.
- **مثال:** `SPAMD_PORT=1783`.

### `SPAMD_TIMEOUT`
- **الافتراضي:** `5` ثواني
- **الدور:** مهلة استدعاء spamd/spamc/spamassassin.
- **مثال:** `SPAMD_TIMEOUT=10` لو الشبكة أبطأ.

---

## 4) Recipient Filtering (SMTP Probe)

### `RECIPIENT_FILTER_ENABLE_SMTP_PROBE`
- **الافتراضي:** `1`
- **الدور:** تفعيل فحص SMTP probe لصلاحية المستلمين.
- **مثال:** `RECIPIENT_FILTER_ENABLE_SMTP_PROBE=0` لتعطيل الفحص.

### `RECIPIENT_FILTER_SMTP_PROBE_LIMIT`
- **الافتراضي:** `25`
- **الدور:** حد أقصى لعدد probes في الدورة.
- **مثال:** `RECIPIENT_FILTER_SMTP_PROBE_LIMIT=50`.

### `RECIPIENT_FILTER_SMTP_TIMEOUT`
- **الافتراضي:** `5` ثواني
- **الدور:** timeout للاتصال أثناء probe.
- **مثال:** `RECIPIENT_FILTER_SMTP_TIMEOUT=8`.

---

## 5) DNSBL / DBL Reputation

### `RBL_ZONES`
- **الافتراضي:** `zen.spamhaus.org,bl.spamcop.net,cbl.abuseat.org`
- **الدور:** قائمة مناطق DNSBL لفحص IP.
- **مثال:** `RBL_ZONES=zen.spamhaus.org`

### `DBL_ZONES`
- **الافتراضي:** `dbl.spamhaus.org`
- **الدور:** قائمة مناطق DBL لفحص الدومين.
- **مثال:** `DBL_ZONES=dbl.spamhaus.org,uribl.spameatingmonkey.net`

### `SEND_DNSBL`
- **الافتراضي:** `1`
- **الدور:** إذا كان مفعّلًا يستمر الإرسال حتى لو ظهر listing (مع تسجيل معلومات).
- **مثال:**
  - `SEND_DNSBL=0` لتشديد السياسة وإيقاف الإرسال في سيناريوهات listing.

---

## 6) PMTA Monitor Health

### `PMTA_MONITOR_TIMEOUT_S`
- **الافتراضي:** `3`
- **الدور:** timeout لطلبات PMTA monitor API.

### `PMTA_MONITOR_BASE_URL`
- **الافتراضي:** فارغ
- **الدور:** Override لعنوان monitor بالكامل.
- **مثال:** `PMTA_MONITOR_BASE_URL=https://194.116.172.135:8080`

### `PMTA_MONITOR_SCHEME`
- **الافتراضي:** `auto`
- **القيم:** `auto | http | https`
- **الدور:** يحدد بروتوكول monitor عند الاشتقاق التلقائي.

### `PMTA_MONITOR_API_KEY`
- **الافتراضي:** فارغ
- **الدور:** مفتاح API يرسل في `X-API-Key` إذا كان monitor محمي.

### `PMTA_HEALTH_REQUIRED`
- **الافتراضي:** `1`
- **الدور:**
  - `1`: فشل monitor يمنع بدء الإرسال.
  - `0`: يعطي تحذير فقط.

### عتبات Busy الخاصة بصحة PMTA
> تستخدم لتحديد أن السيرفر "مشغول" وبالتالي يمنع بدء Job جديد.

- `PMTA_MAX_SPOOL_RECIPIENTS` (افتراضي: `200000`)
- `PMTA_MAX_SPOOL_MESSAGES` (افتراضي: `50000`)
- `PMTA_MAX_QUEUED_RECIPIENTS` (افتراضي: `250000`)
- `PMTA_MAX_QUEUED_MESSAGES` (افتراضي: `60000`)

**مثال عملي:**
- إذا كان `PMTA_MAX_QUEUED_RECIPIENTS=100000` وعدد queued الفعلي 140000، ستعتبر الحالة Busy وقد يتم منع start.

---

## 7) Backoff عام قبل الإرسال

### `ENABLE_BACKOFF`
- **الافتراضي:** `1`
- **الدور:** الحالة الافتراضية لخيار backoff في واجهة الإرسال.

### `BACKOFF_MAX_RETRIES`
- **الافتراضي:** `3`
- **الدور:** أقصى عدد retries لكل chunk عندما policy تمنع الإرسال مؤقتاً.

### `BACKOFF_BASE_S`
- **الافتراضي:** `60`
- **الدور:** زمن الانتظار الأساسي (ثوانٍ) في backoff الأسي.

### `BACKOFF_MAX_S`
- **الافتراضي:** `1800`
- **الدور:** الحد الأعلى لانتظار backoff.

**مثال:**
- `BACKOFF_BASE_S=30`, `BACKOFF_MAX_S=600`, `BACKOFF_MAX_RETRIES=5` يعطي retries أسرع لكن بسقف 10 دقائق.

---

## 8) PMTA Live + Domain Detail Backoff

### متغيرات عامة
- `PMTA_DIAG_ON_ERROR` (افتراضي `1`): تفعيل تشخيص PMTA عند أخطاء SMTP.
- `PMTA_DIAG_RATE_S` (افتراضي `1.0`): معدل أخذ التشخيص (rate limit).
- `PMTA_QUEUE_TOP_N` (افتراضي `6`): عدد top queues في لوحة PMTA Live.
- `PMTA_QUEUE_BACKOFF` (افتراضي `1`): تفعيل منطق backoff بناءً على domain/queue detail.
- `PMTA_QUEUE_REQUIRED` (افتراضي `0`): وضع strict إذا endpoints التفاصيل غير متاحة.
- `PMTA_LIVE_POLL_S` (افتراضي `3`): فترة تحديث لوحة PMTA Live.
- `PMTA_DOMAIN_CHECK_TOP_N` (افتراضي `2`): عدد أهم الدومينات التي تُفحَص لكل chunk.
- `PMTA_DETAIL_CACHE_TTL_S` (افتراضي `3`): TTL كاش نداءات detail.

### عتبات slow/backoff حسب أخطاء الدومين
- `PMTA_DOMAIN_DEFERRALS_BACKOFF` (80)
- `PMTA_DOMAIN_ERRORS_BACKOFF` (6)
- `PMTA_DOMAIN_DEFERRALS_SLOW` (25)
- `PMTA_DOMAIN_ERRORS_SLOW` (3)
- `PMTA_SLOW_DELAY_S` (0.35)
- `PMTA_SLOW_WORKERS_MAX` (3)

**مثال عملي:**
- إذا دومين معين وصل `deferrals=30` و`errors=2`:
  - يتجاوز `PMTA_DOMAIN_DEFERRALS_SLOW` ⇒ التطبيق يخفض السرعة (`delay` أعلى وعدد workers أقل).
- إذا وصل `deferrals=120` أو `errors=7`:
  - يتجاوز عتبة backoff ⇒ chunk قد يتوقف مؤقتاً حسب السياسة.

---

## 9) PMTA Pressure Control (التحكم حسب الحمل)

### تفعيل ومعدل التحديث
- `PMTA_PRESSURE_CONTROL` (افتراضي `1`): تفعيل سياسة التحكم التلقائي.
- `PMTA_PRESSURE_POLL_S` (افتراضي `3`): فترة الحساب.

### Domain snapshot
- `PMTA_DOMAIN_STATS` (افتراضي `1`): تفعيل جلب `/domains` وعرض الإحصائيات.
- `PMTA_DOMAINS_POLL_S` (افتراضي `4`)
- `PMTA_DOMAINS_TOP_N` (افتراضي `6`)

### عتبات مستويات الضغط
> النظام يحسب مستوى ضغط 0..3 من queue/spool/deferred.

- Queue thresholds: `PMTA_PRESSURE_Q1=50000`, `PMTA_PRESSURE_Q2=120000`, `PMTA_PRESSURE_Q3=250000`
- Spool thresholds: `PMTA_PRESSURE_S1=30000`, `PMTA_PRESSURE_S2=80000`, `PMTA_PRESSURE_S3=160000`
- Deferred thresholds: `PMTA_PRESSURE_D1=200`, `PMTA_PRESSURE_D2=800`, `PMTA_PRESSURE_D3=2000`

### سياسة كل مستوى
- Level 1:
  - `PMTA_PRESSURE_L1_DELAY_MIN=0.15`
  - `PMTA_PRESSURE_L1_WORKERS_MAX=6`
  - `PMTA_PRESSURE_L1_CHUNK_MAX=80`
  - `PMTA_PRESSURE_L1_SLEEP_MIN=0.5`
- Level 2:
  - `PMTA_PRESSURE_L2_DELAY_MIN=0.35`
  - `PMTA_PRESSURE_L2_WORKERS_MAX=3`
  - `PMTA_PRESSURE_L2_CHUNK_MAX=45`
  - `PMTA_PRESSURE_L2_SLEEP_MIN=2.0`
- Level 3:
  - `PMTA_PRESSURE_L3_DELAY_MIN=0.75`
  - `PMTA_PRESSURE_L3_WORKERS_MAX=2`
  - `PMTA_PRESSURE_L3_CHUNK_MAX=25`
  - `PMTA_PRESSURE_L3_SLEEP_MIN=4.0`

**مثال عملي:**
- إذا queued recipients = 130000 و deferred = 900:
  - Queue يعطي مستوى 2 وDeferred يعطي مستوى 2 ⇒ policy النهائية مستوى 2.
  - النتيجة: التطبيق يرفع أقل delay، ويقلل workers/chunk size حسب إعدادات Level 2.

---

## 10) PMTA Accounting Bridge Pull (داخل Shiva)

### `PMTA_BRIDGE_PULL_ENABLED`
- **الافتراضي:** `1`
- **الدور:** تشغيل/إيقاف خيط السحب الدوري من bridge.

### `PMTA_BRIDGE_PULL_URL`
- **الافتراضي:** فارغ
- **الدور:** رابط endpoint للسحب.
- **مثال:** `http://194.116.172.135:8090/api/v1/pull/latest?kind=acct`

### `PMTA_BRIDGE_PULL_TOKEN`
- **الافتراضي:** فارغ
- **الدور:** Bearer token يرسل مع طلب السحب للـ bridge.

### `PMTA_BRIDGE_PULL_S`
- **الافتراضي:** `5`
- **الدور:** فترة polling (ثوانٍ).

### `PMTA_BRIDGE_PULL_MAX_LINES`
- **الافتراضي:** `2000`
- **الدور:** قيمة `max_lines` في طلب السحب.

**مثال:**
- `PMTA_BRIDGE_PULL_S=2` و`PMTA_BRIDGE_PULL_MAX_LINES=5000` يعني سحب أسرع وبحجم أكبر لكل دفعة.

---

## 11) OpenRouter (AI Rewrite)

### `OPENROUTER_ENDPOINT`
- **الافتراضي:** `https://openrouter.ai/api/v1/chat/completions`
- **الدور:** endpoint للاتصال بخدمة OpenRouter.

### `OPENROUTER_MODEL`
- **الافتراضي:** `arcee-ai/trinity-large-preview:free`
- **الدور:** اسم الموديل المستخدم لإعادة الصياغة.

### `OPENROUTER_TIMEOUT_S`
- **الافتراضي:** `40`
- **الدور:** timeout لطلبات OpenRouter.

**مثال:**
- `OPENROUTER_MODEL=openai/gpt-4o-mini` لاختيار موديل مختلف (حسب توفره في حسابك).

---

## 12) مثال ملف `.env` تجميعي (Production-like)

```env
# Bridge
PMTA_LOG_DIR=/var/log/pmta
ALLOW_NO_AUTH=0
DEFAULT_PUSH_MAX_LINES=5000
CORS_ORIGINS=https://panel.example.com
BIND_ADDR=0.0.0.0
PORT=8090

# Shiva runtime
SHIVA_HOST=0.0.0.0
SHIVA_PORT=5001
DB_CLEAR_ON_START=0

# Spam
SPAMCHECK_BACKEND=spamd
SPAMD_HOST=127.0.0.1
SPAMD_PORT=783
SPAMD_TIMEOUT=5

# PMTA monitor
PMTA_MONITOR_SCHEME=auto
PMTA_MONITOR_BASE_URL=
PMTA_MONITOR_TIMEOUT_S=3
PMTA_MONITOR_API_KEY=
PMTA_HEALTH_REQUIRED=1

# PMTA accounting pull
PMTA_BRIDGE_PULL_ENABLED=1
PMTA_BRIDGE_PULL_URL=http://127.0.0.1:8090/api/v1/pull/latest?kind=acct
PMTA_BRIDGE_PULL_TOKEN=
PMTA_BRIDGE_PULL_S=5
PMTA_BRIDGE_PULL_MAX_LINES=2000
```

---

## 13) ملاحظات تشغيل مهمة

- أي قيمة غير صالحة في بعض المتغيرات الرقمية يتم fallback تلقائيًا إلى default داخل الشيفرة.
- المتغيرات من نوع boolean غالبًا تقبل: `1/true/yes/on` للتفعيل.
- بعض الإعدادات داخل Shiva يمكن تغييرها من UI، وقد تتغلب على قيمة Environment Variable.
