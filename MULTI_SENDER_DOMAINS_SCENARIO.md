# سيناريو توزيع الإرسال عند وجود عدة دومينات Sender

هذا الملف يشرح بشكل عملي كيف يتعامل النظام مع وجود عدة دومينات للإرسال (Sender Domains)، وما المتغيرات/الإعدادات التي تؤثر على السلوك.

## الفكرة العامة

التعامل يتم على مستويين:

1. **داخل التطبيق (Shiva):** اختيار `from_email` لكل chunk بطريقة rotation.
2. **داخل PowerMTA:** توجيه `MAIL FROM` إلى `virtual-mta`/IP مناسب بشكل strict (1:1 domain→IP).

---

## كيف يتم الإرسال بين 5 دومينات Sender؟

نفترض أنك أدخلت في خانة **Sender Email** القيم التالية (واحد في كل سطر):

- `a@mediapaypro.cloud`
- `b@mediapaypro.info`
- `c@mediapaypro.live`
- `d@mediapaypro.vip`
- `e@mediapaypro.work`

### 1) تجميع المستلمين حسب دومين المستلم

Shiva يقوم بتجميع المستلمين في buckets حسب دومين المستلم (مثل: `gmail.com`, `yahoo.com`, `outlook.com`).

> هذا يعني أن الجدولة تكون provider-aware (حسب recipient domain).

### 2) Round-robin بين buckets

التطبيق لا يرسل كل Gmail دفعة واحدة حتى النهاية؛ بل يعمل نوافذ قصيرة (chunks) ويدور بين الدومينات/المزودات.

### 3) قاعدة chunk = sender واحد

كل chunk يستخدم Sender Email واحد فقط.
ثم في chunk التالي لنفس recipient-provider يتم تدوير sender إلى التالي (rotation).

### 4) Cursor مستقل لكل recipient domain

كل provider له مؤشر (cursor) إرسال مستقل:

- Gmail له cursor
- Yahoo له cursor
- Outlook له cursor

وبالتالي قد ترى Gmail وصل الآن إلى sender #3 بينما Yahoo ما زال على sender #2.

### 5) PowerMTA يثبت Domain→IP

بعد أن يختار Shiva الـ sender، PowerMTA يقرأ domain من MAIL FROM ويطبّق strict routing:

- `@mediapaypro.cloud` → IP `194.116.172.135`
- `@mediapaypro.info`  → IP `194.116.172.136`
- `@mediapaypro.live`  → IP `194.116.172.137`
- `@mediapaypro.vip`   → IP `194.116.172.138`
- `@mediapaypro.work`  → IP `194.116.172.139`

إذا MAIL FROM لا يطابق أي دومين من الخمسة، يتم استخدام fallback `default-virtual-mta`.

---

## مثال مبسّط خطوة بخطوة

نفترض:

- `chunk_size = 50`
- `thread_workers = 5`
- recipients موزعين على:
  - Gmail: 220
  - Yahoo: 120
  - Outlook: 60

تدفق تقريبي:

1. Chunk #1 (Gmail) → sender `a@mediapaypro.cloud`
2. Chunk #2 (Yahoo) → sender `a@mediapaypro.cloud` (cursor Yahoo يبدأ من البداية)
3. Chunk #3 (Outlook) → sender `a@mediapaypro.cloud`
4. Chunk #4 (Gmail) → sender `b@mediapaypro.info`
5. Chunk #5 (Yahoo) → sender `b@mediapaypro.info`
6. Chunk #6 (Outlook) → sender `b@mediapaypro.info`
7. ... ويستمر الدوران بنفس النمط حتى انتهاء القوائم.

> ملاحظة: قد يختلف الترتيب الفعلي قليلًا حسب pause/backoff/pressure control أثناء التشغيل.

---

## ما هي Environment Variables المؤثرة؟

لا يوجد متغير ENV مباشر باسم "sender rotation strategy"، لأن قائمة senders تأتي أساسًا من الفورم (`from_email` textarea).

لكن هناك متغيرات تؤثر على **إيقاع** الإرسال وبالتالي على شكل التوزيع الزمني:

### Backoff

- `ENABLE_BACKOFF`
- `BACKOFF_MAX_RETRIES`
- `BACKOFF_BASE_S`
- `BACKOFF_MAX_S`

### PMTA Queue/Domain Backoff

- `PMTA_QUEUE_BACKOFF`
- `PMTA_DOMAIN_DEFERRALS_BACKOFF`
- `PMTA_DOMAIN_ERRORS_BACKOFF`
- `PMTA_DOMAIN_DEFERRALS_SLOW`
- `PMTA_DOMAIN_ERRORS_SLOW`
- `PMTA_SLOW_DELAY_S`
- `PMTA_SLOW_WORKERS_MAX`

### PMTA Pressure Control

- `PMTA_PRESSURE_CONTROL`
- `PMTA_PRESSURE_POLL_S`
- `PMTA_PRESSURE_L1_*`, `PMTA_PRESSURE_L2_*`, `PMTA_PRESSURE_L3_*`

---

## أولوية الإعدادات (مهم)

في هذا المشروع القيم الفعالة تُحسم بالترتيب:

1. قيمة من واجهة الإعدادات (UI)
2. ثم Environment Variable
3. ثم Default

لذلك قد تضع ENV معينة، لكن يتم تجاوزها إذا كانت هناك قيمة محفوظة من الـ UI.

---

## خلاصة سريعة

- إذا عندك 5 sender domains، فـ Shiva يدور على قائمة المرسلين chunk-by-chunk.
- الجدولة تتم provider-aware حسب recipient domains.
- كل provider له cursor مستقل.
- PowerMTA يضمن أن كل sender domain يخرج من IP الصحيح عبر strict MAIL FROM routing.
- Environment variables تتحكم أساسًا في السرعة/الـ backoff/الضغط، وليس تعريف قائمة الدومينات نفسها.
