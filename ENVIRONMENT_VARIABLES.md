# Environment Variables Reference (Deep Dive)

هذا المستند هو النسخة التفصيلية العميقة لشرح **كل متغيرات البيئة (Environment Variables)** المستخدمة داخل المشروع، مع توضيح:

- ماذا يفعل المتغير داخل الكود بالضبط (الخلفية البرمجية).
- كيف تُقرأ القيمة وتُحوَّل (Parsing / Casting / Fallback).
- ماذا يحدث لو غيّرت القيمة إلى رقم أعلى أو أقل أو عطّلت الخاصية.
- العلاقات بين المتغيرات وتأثيرها على الأداء، الأمان، ودقة الإرسال.

> الهدف: هذا الملف ليس مجرد "افتراضي/وصف"، بل **مرجع تشغيل Production** يساعدك على اتخاذ قرار صحيح لكل متغير.

---

## 0) كيف تُحسم القيمة النهائية لأي متغير؟ (مهم جدًا)

داخل `shiva_app.py` يوجد نظام إعدادات ديناميكي (`APP_CONFIG_SCHEMA`) يجعل القيمة الفعلية لبعض المتغيرات تأتي بهذا الترتيب:

1. **قيمة UI** (المخزنة في SQLite) إن وُجدت.
2. ثم **Environment Variable**.
3. ثم **Default** المعرّف في المخطط.

**ماذا يعني ذلك عمليًا؟**
- لو غيّرت `.env` ولن ترى أثرًا، غالبًا هناك Override من واجهة التطبيق.
- إزالة القيمة من UI تعيدك مباشرةً إلى ENV/default.
- ليست كل المتغيرات تخضع لـ UI؛ بعضها يقرأ مباشرة من ENV عند بدء العملية.

**نمط الـ Parsing في المشروع:**
- Boolean: غالبًا القيم التالية تعتبر `True`: `1`, `true`, `yes`, `on`.
- Int/Float: أي قيمة غير قابلة للتحويل ترجع تلقائيًا إلى قيمة افتراضية آمنة.
- Strings: غالبًا يتم `strip()` لإزالة المسافات من البداية والنهاية.

---

## 1) متغيرات خدمة الجسر `pmta_accounting_bridge.py`

هذه المتغيرات تخص خدمة Bridge التي تقرأ Accounting/Log files وتقدّم API للسحب.

### `PMTA_LOG_DIR`
- **الافتراضي:** `/var/log/pmta`
- **النوع:** `path`
- **الخلفية البرمجية:** المسار الذي تعتمد عليه Endpoints لاكتشاف ملفات اللوج وقراءتها.
- **تأثير تغييره:**
  - إذا المسار صحيح وملفات PMTA موجودة → API ترجع ملفات وبيانات.
  - إذا المسار خاطئ أو لا يملك صلاحيات قراءة → endpoints سترجع أخطاء أو قوائم فارغة.
- **متى تغيّره؟**
  - عند وجود PMTA في مسار مخصص مثل `/opt/pmta/logs`.
- **أفضل ممارسة:**
  - استخدم مسارًا ثابتًا ومقروءًا من user تشغيل الخدمة، وتأكد من rotation policy.

### `ALLOW_NO_AUTH`
- **الافتراضي:** `0`
- **النوع:** `bool` (فعليًا في الكود: `== "1"` فقط)
- **الخلفية البرمجية:** يفعّل/يعطل اشتراط Bearer token على API.
- **السلوك الدقيق:**
  - `1` → إلغاء التحقق الأمني (API مفتوح).
  - أي قيمة أخرى → التوكن مطلوب.
- **إذا غيّرته:**
  - `0 -> 1`: مناسب فقط في dev/local debugging.
  - `1 -> 0`: يجب التأكد أن المستهلك (Shiva) يرسل `PMTA_BRIDGE_PULL_TOKEN`.
- **تحذير أمني:** لا تستخدم `1` في الإنتاج نهائيًا.

### `DEFAULT_PUSH_MAX_LINES`
- **الافتراضي:** `5000`
- **النوع:** `int`
- **الخلفية البرمجية:** الحد الافتراضي لعدد الأسطر عند سحب `/api/v1/pull/latest` عندما لا يرسل العميل `max_lines`.
- **تأثير زيادة القيمة:**
  - دفعات أكبر = عدد طلبات أقل.
  - لكن استهلاك RAM/CPU في الطلب الواحد أعلى، وزمن الاستجابة أطول.
- **تأثير تقليل القيمة:**
  - دفعات أصغر = تأخير أقل لكل طلب.
  - لكن Polling أكثر للوصول لنفس الحجم الكلي.
- **نصيحة تشغيل:**
  - أحجام كبيرة جدًا (>20000) قد تسبب latency أو timeouts عند الضغط العالي.

### `CORS_ORIGINS`
- **الافتراضي:** `*`
- **النوع:** `csv|string`
- **الخلفية البرمجية:** يحدد Origins المسموح لها من المتصفح باستدعاء API.
- **قيم شائعة:**
  - `*` (كل شيء)
  - `https://admin.example.com,https://ops.example.com`
- **التأثير:**
  - `*` أسرع إعدادًا لكنه أقل صرامة أمنيًا.
  - تحديد دومينات يقلل مخاطر استهلاك API من UIs غير مصرح بها.

### `BIND_ADDR`
- **الافتراضي:** `0.0.0.0`
- **النوع:** `str`
- **الخلفية:** عنوان الشبكة الذي تستمع عليه الخدمة عند التشغيل المباشر.
- **التأثير:**
  - `0.0.0.0` → متاح من كل الواجهات.
  - `127.0.0.1` → محلي فقط.

### `PORT`
- **الافتراضي:** `8090`
- **النوع:** `int`
- **الخلفية:** بورت خدمة Bridge.
- **ماذا يتغير عند تغييره؟**
  - يجب تحديث `PMTA_BRIDGE_PULL_URL` في Shiva لنفس البورت، وإلا يفشل السحب الدوري.

---

## 2) متغيرات تشغيل تطبيق Shiva الأساسية

### `SHIVA_HOST`
- **الافتراضي:** `0.0.0.0`
- **الخلفية:** عنوان الاستماع لتطبيق Flask.
- **التأثير:**
  - `127.0.0.1` مناسب خلف reverse proxy محلي.
  - `0.0.0.0` مطلوب إذا الوصول من شبكة أخرى/حاوية.

### `SHIVA_PORT`
- **الافتراضي:** `5001`
- **الخلفية:** بورت واجهة Shiva.
- **ملاحظة:** إذا عندك Nginx/Load balancer يجب مواءمة upstream.

### `DB_CLEAR_ON_START`
- **الافتراضي:** `0`
- **النوع:** `bool`
- **الخلفية:** عند `1` يتم تنفيذ مسح جداول SQLite مع بداية التشغيل.
- **الأثر التشغيلي:**
  - `1` = إعادة بيئة نظيفة (مفيد للاختبار).
  - لكن يمسح بيانات حملات/نتائج/مستلمين، لذلك خطر جدًا في production.
- **أفضل ممارسة:**
  - اتركه `0` دائمًا في الإنتاج.

---

## 3) Spam / SpamAssassin

### `SPAMCHECK_BACKEND`
- **الافتراضي:** `spamd`
- **القيم المتوقعة:** `spamd | spamc | spamassassin | module | off`
- **الخلفية:** يحدد آلية حساب spam score أثناء مسار الفحص.
- **تأثير القيم:**
  - `off`: تعطيل التقييم بالكامل (سرعة أعلى، حماية أقل).
  - `spamd`: اتصال daemon عبر الشبكة/localhost.
  - `spamc`/`spamassassin`: اعتماد نمط تنفيذ مختلف حسب المتاح في النظام.
- **عند اختيار backend غير متاح:**
  - يحصل فشل/تحذيرات حسب المسار، وغالبًا fallback داخل منطق التطبيق.

### `SPAMD_HOST`
- **الافتراضي:** `127.0.0.1`
- **الخلفية:** عنوان خدمة spamd.
- **سيناريوهات:**
  - localhost عندما spamd على نفس السيرفر.
  - IP داخلي عندما spamd مركزي في شبكة خاصة.

### `SPAMD_PORT`
- **الافتراضي:** `783`
- **الخلفية:** بورت spamd.
- **الأثر عند الخطأ:** port خاطئ = timeouts/failures في scoring.

### `SPAMD_TIMEOUT`
- **الافتراضي:** `5`
- **النوع:** `float`
- **الخلفية:** مهلة انتظار خدمة spam backend.
- **إذا رفعته:** دقة أفضل في شبكات بطيئة لكن زمن معالجة أعلى.
- **إذا خفضته جدًا:** throughput أعلى لكن احتمالية timeout أكبر.

---

## 4) Recipient Filtering (SMTP Probe)

### `RECIPIENT_FILTER_ENABLE_SMTP_PROBE`
- **الافتراضي:** `1`
- **الخلفية:** تشغيل فحص SMTP probe للتحقق المسبق من صلاحية المستلمين.
- **التأثير:**
  - `1`: جودة لائحة أعلى، bounce أقل، لكن زمن pre-check أعلى.
  - `0`: أسرع، لكن bounce أثناء الإرسال قد يزيد.

### `RECIPIENT_FILTER_SMTP_PROBE_LIMIT`
- **الافتراضي:** `25`
- **الخلفية:** سقف probes في الدورة الواحدة.
- **إذا رفعته:** تغطية أكبر لكل دورة، ضغط أعلى على DNS/SMTP الخارجي.
- **إذا خفضته:** استهلاك أقل لكن الدقة تظهر أبطأ على القوائم الكبيرة.

### `RECIPIENT_FILTER_SMTP_TIMEOUT`
- **الافتراضي:** `5`
- **الخلفية:** timeout لاتصالات probe.
- **توصية:**
  - بيئة WAN بطيئة: 7–10.
  - بيئة سريعة: 3–5.

---

## 5) DNSBL / DBL Reputation

### `RBL_ZONES`
- **الافتراضي:** `zen.spamhaus.org,bl.spamcop.net,cbl.abuseat.org`
- **الخلفية:** مناطق DNSBL لفحص سمعة IP.
- **كلما زادت المناطق:** دقة أعلى لكن زمن query أكبر.

### `DBL_ZONES`
- **الافتراضي:** `dbl.spamhaus.org`
- **الخلفية:** مناطق DBL لفحص الدومين/الروابط.

### `SEND_DNSBL`
- **الافتراضي:** `1`
- **الخلفية:** سياسة التعامل عند وجود listing.
- **التأثير العملي:**
  - `1`: لا يمنع الإرسال تلقائيًا (تسجيل/تحذير).
  - `0`: تشديد أكثر وقد يوقف الإرسال في حالات listing.

---

## 6) PMTA Monitor Health + Busy Gate

### `PMTA_MONITOR_TIMEOUT_S`
- **الافتراضي:** `3`
- **الخلفية:** timeout لطلبات PMTA monitor API.
- **رفع القيمة:** يقل false negatives في الشبكات المتأخرة.

### `PMTA_MONITOR_BASE_URL`
- **الافتراضي:** فارغ
- **الخلفية:** إذا وضعته، يصبح عنوان monitor صريحًا ويغلب الاشتقاق التلقائي.

### `PMTA_MONITOR_SCHEME`
- **الافتراضي:** `auto`
- **القيم:** `auto | http | https`
- **الخلفية:** تحديد بروتوكول monitor عند البناء التلقائي للرابط.

### `PMTA_MONITOR_API_KEY`
- **الافتراضي:** فارغ
- **الخلفية:** يرسل كـ `X-API-Key` عند حماية monitor.
- **تنبيه:** تعامل معه كسِر (لا تضعه في logs).

### `PMTA_HEALTH_REQUIRED`
- **الافتراضي:** `1`
- **الخلفية:** هل فشل health check يمنع بدء الإرسال؟
- **السلوك:**
  - `1`: gate صارم (الأمان التشغيلي أعلى).
  - `0`: تحذير فقط ويستمر التشغيل.

### عتبات Busy الرئيسية
> تُستخدم قبل بدء jobs لتحديد هل PMTA تحت حمل عالٍ.

#### `PMTA_MAX_SPOOL_RECIPIENTS` (200000)
- إذا `spool.recipients` تجاوزها → يعتبر Busy.

#### `PMTA_MAX_SPOOL_MESSAGES` (50000)
- إذا `spool.messages` تجاوزها → Busy.

#### `PMTA_MAX_QUEUED_RECIPIENTS` (250000)
- إذا `queued.recipients` تجاوزها → Busy.

#### `PMTA_MAX_QUEUED_MESSAGES` (60000)
- إذا `queued.messages` تجاوزها → Busy.

**مثال قرار فعلي:**
- لو `PMTA_MAX_QUEUED_RECIPIENTS=100000` والفعلي `140000` → منع start (عند تفعيل health gate).

---

## 7) Backoff العام أثناء الإرسال

### `ENABLE_BACKOFF`
- **الافتراضي:** `1`
- **الخلفية:** الحالة الافتراضية لخيار backoff في نموذج الإرسال (واجهة).
- **مهم:** هذا ليس دائمًا تعطيل/تفعيل قسري لكل الأنظمة، بل default behavior للـ send flow.

### `BACKOFF_MAX_RETRIES`
- **الافتراضي:** `3`
- **الخلفية:** أقصى retries عند منع مؤقت من policy.
- **منطقيًا في الكود:** القيمة تُقيّد ضمن نطاق آمن (0..10).

### `BACKOFF_BASE_S`
- **الافتراضي:** `60`
- **الخلفية:** زمن البداية في backoff الأسي.

### `BACKOFF_MAX_S`
- **الافتراضي:** `1800`
- **الخلفية:** سقف الانتظار مهما زادت المحاولات.

**كيف تعمل معًا؟**
- محاولات أكثر + base منخفض = استعادة أسرع لكن ضغط أعلى.
- محاولات أقل + base أعلى = سلوك محافظ لكن recovery أبطأ.

---

## 8) PMTA Live + Domain Detail Backoff

### `PMTA_DIAG_ON_ERROR`
- **الافتراضي:** `1`
- **الخلفية:** عند أخطاء SMTP يفعل جمع تشخيص PMTA.

### `PMTA_DIAG_RATE_S`
- **الافتراضي:** `1.0`
- **الخلفية:** Rate limit لأخذ التشخيص.
- **خفضه كثيرًا:** معلومات أكثر لكن ضغط أعلى على monitor endpoints.

### `PMTA_QUEUE_TOP_N`
- **الافتراضي:** `6`
- **الخلفية:** عدد queue entries المعروضة في live view.

### `PMTA_QUEUE_BACKOFF`
- **الافتراضي:** `1`
- **الخلفية:** تفعيل منطق backoff المبني على تفاصيل queue/domain.

### `PMTA_QUEUE_REQUIRED`
- **الافتراضي:** `0`
- **الخلفية:** إذا `1` يصبح توفر endpoints التفصيلية شرطًا صارمًا.
- **التأثير:**
  - `1`: أكثر صرامة، قد يوقف التقدم عند فقد البيانات التفصيلية.
  - `0`: مرونة أعلى.

### `PMTA_LIVE_POLL_S`
- **الافتراضي:** `3`
- **الخلفية:** فترة التحديث للوحة PMTA live.

### `PMTA_DOMAIN_CHECK_TOP_N`
- **الافتراضي:** `2`
- **الخلفية:** كم دومين "الأكثر تأثيرًا" يتم فحصه لكل chunk.

### `PMTA_DETAIL_CACHE_TTL_S`
- **الافتراضي:** `3`
- **الخلفية:** TTL لكاش endpoint detail لتقليل الضغط.

### عتبات سلوك الدومين

#### `PMTA_DOMAIN_DEFERRALS_BACKOFF` (80)
#### `PMTA_DOMAIN_ERRORS_BACKOFF` (6)
- تجاوز أي منهما يدفع إلى backoff/hold حسب policy.

#### `PMTA_DOMAIN_DEFERRALS_SLOW` (25)
#### `PMTA_DOMAIN_ERRORS_SLOW` (3)
- تجاوز أي منهما يفعّل slow mode (تقليل سرعة الإرسال).

#### `PMTA_SLOW_DELAY_S` (0.35)
#### `PMTA_SLOW_WORKERS_MAX` (3)
- بارامترات التخفيف عند slow mode.

**سيناريو تفصيلي:**
- `deferrals=30` و `errors=2`:
  - يتجاوز `DEFERRALS_SLOW` → Slow mode: delay أعلى + workers أقل.
- `deferrals=120` أو `errors=7`:
  - يتجاوز `*_BACKOFF` → توقف/تأخير أقوى حسب سياسة الإرسال.

---

## 9) PMTA Pressure Control (التحكم التلقائي بالحمل)

### تفعيل ومعدل الحساب

#### `PMTA_PRESSURE_CONTROL`
- **الافتراضي:** `1`
- **الخلفية:** محرك policy يقرأ queue/spool/deferred ويخرج level من 0 إلى 3.

#### `PMTA_PRESSURE_POLL_S`
- **الافتراضي:** `3`
- **الخلفية:** كل كم ثانية يُعاد حساب مستوى الضغط.

### Domain snapshot

#### `PMTA_DOMAIN_STATS` (افتراضي `1`)
- يفعّل سحب `/domains` واستخدامه في الرؤية التشغيلية.

#### `PMTA_DOMAINS_POLL_S` (افتراضي `4`)
- interval لتحديث لقطة الدومينات.

#### `PMTA_DOMAINS_TOP_N` (افتراضي `6`)
- عدد الدومينات المعروضة/المحللة في اللقطة.

### عتبات تحديد المستوى (Thresholds)

#### Queue
- `PMTA_PRESSURE_Q1=50000`
- `PMTA_PRESSURE_Q2=120000`
- `PMTA_PRESSURE_Q3=250000`

#### Spool
- `PMTA_PRESSURE_S1=30000`
- `PMTA_PRESSURE_S2=80000`
- `PMTA_PRESSURE_S3=160000`

#### Deferred
- `PMTA_PRESSURE_D1=200`
- `PMTA_PRESSURE_D2=800`
- `PMTA_PRESSURE_D3=2000`

> المستوى النهائي = أعلى مستوى ناتج من Queue/Spool/Deferred.

### سياسة كل مستوى

#### Level 1
- `PMTA_PRESSURE_L1_DELAY_MIN=0.15`
- `PMTA_PRESSURE_L1_WORKERS_MAX=6`
- `PMTA_PRESSURE_L1_CHUNK_MAX=80`
- `PMTA_PRESSURE_L1_SLEEP_MIN=0.5`

#### Level 2
- `PMTA_PRESSURE_L2_DELAY_MIN=0.35`
- `PMTA_PRESSURE_L2_WORKERS_MAX=3`
- `PMTA_PRESSURE_L2_CHUNK_MAX=45`
- `PMTA_PRESSURE_L2_SLEEP_MIN=2.0`

#### Level 3
- `PMTA_PRESSURE_L3_DELAY_MIN=0.75`
- `PMTA_PRESSURE_L3_WORKERS_MAX=2`
- `PMTA_PRESSURE_L3_CHUNK_MAX=25`
- `PMTA_PRESSURE_L3_SLEEP_MIN=4.0`

**ماذا يحدث عند التغيير؟**
- تخفيض thresholds = دخول أسرع لمستويات أعلى (محافظة أكبر).
- رفع `WORKERS_MAX` في مستوى عالٍ قد يحسن throughput مؤقتًا لكن يزيد خطر التشبع/deferrals.
- زيادة `CHUNK_MAX` تحت ضغط عالٍ قد تضر latency وتراكم الطوابير.

---

## 10) PMTA Accounting Bridge Pull (داخل Shiva)

### `PMTA_BRIDGE_PULL_ENABLED`
- **الافتراضي:** `1`
- **الخلفية:** تشغيل/إيقاف خيط السحب الدوري من bridge.
- **إذا `0`:** لن يتم ingest محاسبة PMTA تلقائيًا.

### `PMTA_BRIDGE_PULL_URL`
- **الافتراضي:** فارغ
- **الخلفية:** endpoint الذي يقرأ منه Shiva بيانات accounting.
- **الشرط:** يجب أن يطابق host/port/path الحقيقية لخدمة Bridge.

### `PMTA_BRIDGE_PULL_TOKEN`
- **الافتراضي:** فارغ
- **الخلفية:** Bearer token في طلبات السحب عند تفعيل auth بالـ bridge.
- **حالة شائعة:**
  - `ALLOW_NO_AUTH=0` وtoken فارغ → طلبات السحب سترفض (401/403).

### `PMTA_BRIDGE_PULL_S`
- **الافتراضي:** `5`
- **الخلفية:** polling interval بالثواني.
- **خفضه (مثلاً 1–2):** near-real-time أكثر، لكن load أعلى.

### `PMTA_BRIDGE_PULL_MAX_LINES`
- **الافتراضي:** `2000`
- **الخلفية:** حجم الدفعة لكل سحب.
- **الموازنة:**
  - قيمة أعلى = catch-up أسرع بعد تأخر.
  - قيمة أقل = طلبات أخف وأسرع.

---

## 11) OpenRouter (AI Rewrite)

### `OPENROUTER_ENDPOINT`
- **الافتراضي:** `https://openrouter.ai/api/v1/chat/completions`
- **الخلفية:** عنوان HTTP API الذي تُرسل له طلبات إعادة الصياغة.

### `OPENROUTER_MODEL`
- **الافتراضي:** `arcee-ai/trinity-large-preview:free`
- **الخلفية:** معرف النموذج المستخدم.
- **إذا غيّرته:**
  - قد تتغير جودة النص/السرعة/التكلفة حسب المزود.

### `OPENROUTER_TIMEOUT_S`
- **الافتراضي:** `40`
- **الخلفية:** مهلة طلب AI.
- **خفضه كثيرًا:** احتمال timeout أعلى للنماذج البطيئة.
- **رفعه كثيرًا:** انتظار أطول للمستخدم قبل الفشل.

---

## 12) ملاحظات "ما الذي يدور في الخلفية" لكل الفئات

### أ) متغيرات bool
- تُستخدم لتشغيل/تعطيل Features أو للتحول بين strict/permissive policy.
- تغييرها عادةً يعطي **فرق سلوكي مباشر** وليس مجرد tuning رقمي.

### ب) متغيرات timeout / poll
- timeout = كم ننتظر نفس العملية.
- poll = كم نكرر الفحص.
- المبالغة في تقليل poll قد تسبب load مرتفع، والمبالغة في رفعه تزيد latency في الاستجابة للأحداث.

### ج) متغيرات thresholds
- thresholds تحدد "متى" يتحول النظام من وضع طبيعي إلى slow/backoff/pressure.
- القيم المنخفضة = حماية أكبر + throughput أقل.
- القيم المرتفعة = throughput أعلى + مخاطرة أكبر تحت الضغط.

### د) متغيرات workers/chunk/delay
- `workers` أعلى = parallelism أعلى.
- `chunk` أعلى = دفعة أكبر لكل دورة.
- `delay` أعلى = تهدئة الإرسال.
- هذه الثلاثة متلازمة؛ تعديل واحد غالبًا يحتاج تعديل الآخرين.

---

## 13) مصفوفة قرارات سريعة (إذا تغيّر X ماذا يحدث؟)

- إذا زادت `PMTA_PRESSURE_* thresholds` كثيرًا → النظام يتأخر في الدخول لوضع الحماية، وقد ترى ضغطًا أكبر قبل أن يتدخل.
- إذا قللت `PMTA_DOMAIN_*_BACKOFF` جدًا → backoff يشتغل مبكرًا، ما يقلل المخاطر لكنه قد يخفض throughput بشكل واضح.
- إذا رفعت `BACKOFF_MAX_RETRIES` مع `BACKOFF_BASE_S` منخفضة → attempts أكثر في وقت أقصر (مفيد للتعافي السريع، لكنه يكرر الضغط).
- إذا عطلت `PMTA_QUEUE_BACKOFF` أو `PMTA_PRESSURE_CONTROL` مع استمرار أخطاء PMTA → لازم تعتمد على مراقبة يدوية وإلا يمكن يتفاقم الوضع.
- إذا جعلت `PMTA_BRIDGE_PULL_S` صغيرًا جدًا و`MAX_LINES` كبيرًا جدًا → عبء أعلى على Bridge وDB.

---

## 14) ملف `.env` مقترح (Production-like baseline)

```env
# --- Bridge ---
PMTA_LOG_DIR=/var/log/pmta
ALLOW_NO_AUTH=0
DEFAULT_PUSH_MAX_LINES=5000
CORS_ORIGINS=https://panel.example.com
BIND_ADDR=0.0.0.0
PORT=8090

# --- Shiva runtime ---
SHIVA_HOST=0.0.0.0
SHIVA_PORT=5001
DB_CLEAR_ON_START=0

# --- Spam ---
SPAMCHECK_BACKEND=spamd
SPAMD_HOST=127.0.0.1
SPAMD_PORT=783
SPAMD_TIMEOUT=5

# --- Recipient probe ---
RECIPIENT_FILTER_ENABLE_SMTP_PROBE=1
RECIPIENT_FILTER_SMTP_PROBE_LIMIT=25
RECIPIENT_FILTER_SMTP_TIMEOUT=5

# --- DNSBL ---
RBL_ZONES=zen.spamhaus.org,bl.spamcop.net,cbl.abuseat.org
DBL_ZONES=dbl.spamhaus.org
SEND_DNSBL=1

# --- PMTA monitor ---
PMTA_MONITOR_SCHEME=auto
PMTA_MONITOR_BASE_URL=
PMTA_MONITOR_TIMEOUT_S=3
PMTA_MONITOR_API_KEY=
PMTA_HEALTH_REQUIRED=1
PMTA_MAX_SPOOL_RECIPIENTS=200000
PMTA_MAX_SPOOL_MESSAGES=50000
PMTA_MAX_QUEUED_RECIPIENTS=250000
PMTA_MAX_QUEUED_MESSAGES=60000

# --- Backoff ---
ENABLE_BACKOFF=1
BACKOFF_MAX_RETRIES=3
BACKOFF_BASE_S=60
BACKOFF_MAX_S=1800

# --- PMTA domain/detail backoff ---
PMTA_DIAG_ON_ERROR=1
PMTA_DIAG_RATE_S=1.0
PMTA_QUEUE_TOP_N=6
PMTA_QUEUE_BACKOFF=1
PMTA_QUEUE_REQUIRED=0
PMTA_LIVE_POLL_S=3
PMTA_DOMAIN_CHECK_TOP_N=2
PMTA_DETAIL_CACHE_TTL_S=3
PMTA_DOMAIN_DEFERRALS_BACKOFF=80
PMTA_DOMAIN_ERRORS_BACKOFF=6
PMTA_DOMAIN_DEFERRALS_SLOW=25
PMTA_DOMAIN_ERRORS_SLOW=3
PMTA_SLOW_DELAY_S=0.35
PMTA_SLOW_WORKERS_MAX=3

# --- Pressure control ---
PMTA_PRESSURE_CONTROL=1
PMTA_PRESSURE_POLL_S=3
PMTA_DOMAIN_STATS=1
PMTA_DOMAINS_POLL_S=4
PMTA_DOMAINS_TOP_N=6
PMTA_PRESSURE_Q1=50000
PMTA_PRESSURE_Q2=120000
PMTA_PRESSURE_Q3=250000
PMTA_PRESSURE_S1=30000
PMTA_PRESSURE_S2=80000
PMTA_PRESSURE_S3=160000
PMTA_PRESSURE_D1=200
PMTA_PRESSURE_D2=800
PMTA_PRESSURE_D3=2000
PMTA_PRESSURE_L1_DELAY_MIN=0.15
PMTA_PRESSURE_L1_WORKERS_MAX=6
PMTA_PRESSURE_L1_CHUNK_MAX=80
PMTA_PRESSURE_L1_SLEEP_MIN=0.5
PMTA_PRESSURE_L2_DELAY_MIN=0.35
PMTA_PRESSURE_L2_WORKERS_MAX=3
PMTA_PRESSURE_L2_CHUNK_MAX=45
PMTA_PRESSURE_L2_SLEEP_MIN=2.0
PMTA_PRESSURE_L3_DELAY_MIN=0.75
PMTA_PRESSURE_L3_WORKERS_MAX=2
PMTA_PRESSURE_L3_CHUNK_MAX=25
PMTA_PRESSURE_L3_SLEEP_MIN=4.0

# --- Accounting pull in Shiva ---
PMTA_BRIDGE_PULL_ENABLED=1
PMTA_BRIDGE_PULL_URL=http://127.0.0.1:8090/api/v1/pull/latest?kind=acct
PMTA_BRIDGE_PULL_TOKEN=
PMTA_BRIDGE_PULL_S=5
PMTA_BRIDGE_PULL_MAX_LINES=2000

# --- AI ---
OPENROUTER_ENDPOINT=https://openrouter.ai/api/v1/chat/completions
OPENROUTER_MODEL=arcee-ai/trinity-large-preview:free
OPENROUTER_TIMEOUT_S=40
```

---

## 15) Checklist قبل اعتماد أي تعديل في المتغيرات

1. غيّر مجموعة صغيرة فقط (لا تغيّر 20 متغير دفعة واحدة).
2. سجّل baseline قبل/بعد (throughput, deferrals, errors, queue depth).
3. راقب 30–60 دقيقة على الأقل بعد كل تغيير.
4. تأكد هل القيمة آتية من UI أم ENV.
5. احتفظ بخطة rollback (`.env` سابق + restart procedure).

بهذا الأسلوب تستطيع ضبط النظام بأمان ووضوح، وتعرف بدقة لماذا النتيجة تغيّرت بعد أي تعديل.
