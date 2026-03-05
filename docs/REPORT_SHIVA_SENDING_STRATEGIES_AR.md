# تقرير شامل: آلية الإرسال في Shiva (التبطيء/التسريع/تقسيم الدومينات/تقسيم القوائم)

> هذا التقرير يشرح **الاستراتيجيات الفعلية المطبقة حالياً** داخل `shiva.py` كما هي في الشفرة، مع التركيز على دورة الإرسال، توزيع الريسيبينت، توزيع السندر، التحكم بالسرعة، والـ backoff.

---

## 1) نظرة معمارية سريعة (Pipeline)

آلية الإرسال في Shiva تعمل كسلسلة مراحل مترابطة:

1. **تنظيف واستقبال القوائم**: Parsing + Normalize + Deduplicate للريسيبينت.
2. **فلترة ما قبل الإرسال**: Syntax + Route (MX/A) + SMTP probe اختياري.
3. **تقسيم المستلمين حسب provider domain** (gmail/yahoo/…)، ثم **توزيعهم على sender emails** بشكل متوازن.
4. **جدولة Provider-aware**: كل Chunk يكون موجه غالباً لدومين مستلمين واحد مع اختيار sender بحسب التقسيم.
5. **Preflight لكل Chunk**: Spam + Blacklist + PMTA queue/domain policy.
6. **الإرسال متعدد الخيوط (ThreadPool)** داخل الـ chunk مع `delay_s` بين الرسائل.
7. **Backoff تكيفي** عند الضغط أو الإشارات السلبية، مع retries provider-isolated.
8. **تحكم سرعة ديناميكي** من مصدرين:
   - سياسة صحية مبنية على outcomes + SMTP classes.
   - PMTA pressure live policy (queue/spool/deferrals).
9. **تعلم تاريخي** (learning tables) لكل provider/sender pair لتعديل retry cap ومدة الانتظار.
10. **مراقبة حيّة** للحالة الحالية (chunks/backoff/domain stats/PMTA snapshots).

---

## 2) كيف Shiva يقسم الـ Recipient List

### 2.1 Parsing + Normalize + Dedupe

- Shiva يستخرج الإيميلات من نصوص غير منظمة، ويقبل separators متعددة.
- يطبع الدومين Lowercase، ويحافظ على local-part.
- يمنع التكرار case-insensitive.
- يحسب:
  - `invalid_count`
  - `deduplicated_count`
  - `valid_total`

**النتيجة:** قائمة نظيفة deterministic-ready قبل الجدولة.

### 2.2 تجميع حسب domain (Provider Buckets)

- يتم تجميع كل recipient داخل bucket حسب domain (`gmail.com`, `yahoo.com`, ...).
- ترتيب ظهور الدومينات محفوظ (first-seen order).
- كل bucket يمثل queue منطقية لمزود واحد.

### 2.3 توزيع كل Domain على السندرات بشكل متوازن

الوظيفة الأساسية تستخدم توزيعًا حتميًا (deterministic balancing):

- لكل domain:
  - يحصل shuffle deterministic باستخدام seed مبني على `campaign_id/job_id + domain`.
  - ثم يقسم هذا الدومين على عدد السندرات `k` بحيث الفروقات تكون <= 1.
- ينتج عنها بنية:
  - `buckets[sender_email][recipient_domain] = list(recipients)`

**الفائدة:**
- تجنب skew على sender واحد.
- توزيع عادل domain-by-domain وليس فقط إجماليًا.

---

## 3) كيف Shiva يقسم الـ Sender Mail ويختار sender أثناء الإرسال

### 3.1 التقسيم المبدئي

- بعد توزيع المستلمين، كل sender يصبح لديه map خاص به من provider domains.
- يوجد `sender_cursor` round-robin للتنقل بين السندرات.

### 3.2 اختيار sender/domain التالي (Scheduler)

خوارزمية الانتقاء تجمع بين:

1. **Round-robin على السندرات** لضمان العدالة.
2. **أولوية retries الجاهزة** (إذا domain لديه chunk جاهز retry الآن).
3. **Weighted domain pick** إذا لا يوجد retry فوري:
   - وزن كل domain = عدد الريسيبينت المتبقين فيه.
   - اختيار عشوائي موزون (deterministic RNG seeded).

**النتيجة:** مزيج بين العدالة والفعالية (يستهلك الدومينات الثقيلة تدريجياً).

### 3.3 استنفاد sender domains

- Shiva يستخدم recommendation من learning layer لاختيار domains الممكنة للسندر.
- إذا انتهت كل الخيارات لدومين مزود معين، chunk يمكن وضعه كـ `abandoned` مع تسجيل السبب.

---

## 4) استراتيجية تقسيم الـ Chunks

### 4.1 Dynamic Chunking

- `chunk_size` ليس ثابتاً تماماً؛ يمكن تعديله runtime من campaign form أو سياسات التكيّف.
- `chunks_total` يعاد تقديره حسب المتبقي.

### 4.2 Provider-isolated chunk retry

- عند فشل preflight/سياسة PMTA، لا يتم إيقاف كل الجوب فوراً دائماً.
- يتم جدولة chunk في `provider_retry_chunks` مع `next_retry_ts` على مستوى `(sender_idx|domain)`.
- عند عدم وجود provider جاهز، الحالة تصبح `backoff` وينتظر حتى أقرب نافذة retry.

---

## 5) استراتيجيات التبطيء والتسريع (Throttle/Speed Control)

Shiva يستخدم **عدة طبقات** للتبطيء والتسريع، تعمل فوق بعضها:

### 5.1 ضبط يدوي/أساسي

مدخلات المستخدم الأساسية:
- `thread_workers`
- `delay_s` (بين الرسائل)
- `chunk_size`
- `sleep_chunks` (بين الـ chunks)

### 5.2 Runtime Overrides (Live Tuning)

قبل كل chunk/attempt:
- يقرأ Shiva إعدادات الحملة من SQLite (`campaign_form`) ويطبق التغييرات مباشرة بدون إعادة تشغيل job.
- يمكن تعديل السرعة أثناء التشغيل الفعلي.

### 5.3 Adaptive Health Policy (من نتائج التسليم)

سياسة تعتمد على:
- Delivered/Bounced/Deferred/Complained
- تحليل SMTP classes من الأخطاء الأخيرة (4xx / 5xx)

وتحدد مستوى `0..3`:
- **L1**: تبطيء خفيف
- **L2**: تبطيء متوسط
- **L3**: تبطيء قوي
- **L0 healthy**: يمكن عمل **speed_up** تدريجي (زيادة workers/chunk وتقليل delay)

### 5.4 PMTA Pressure Control (Global)

يعتمد على live metrics من PMTA:
- `queued_recipients`
- `spool_recipients`
- `deferred_total`

ويحوّلها لمستويات ضغط 0..3 مع caps جاهزة:
- حد أدنى للـ delay
- حد أقصى للـ workers
- حد أقصى للـ chunk_size
- حد أدنى للـ sleep_chunks

### 5.5 PMTA Domain/Queue Policy (Per Chunk)

قبل إرسال chunk، Shiva قد يطبق:
- **Block** كامل للـ attempt إن مؤشرات queue/domain خطيرة.
- **Slow mode** للـ attempt الحالي (رفع delay وخفض workers).

### 5.6 Backoff الحسابي (Exponential-ish + Jitter)

عند block/failure:
- يحسب `wait_s` بزيادة تدريجية حتى `max_backoff_s`.
- يضيف تمييز حسب نوع الفشل (spam/blacklist/pmta/...)
- يسجل الحدث في `backoff_items` و`chunk_states`.

---

## 6) استراتيجيات ما قبل الإرسال (Preflight / Safety)

### 6.1 Recipient Filter

- Syntax check
- Route check (MX أو A fallback)
- SMTP probe اختياري (ومحدود بعدد domains)

النتيجة:
- قائمة `ok` للإرسال
- قائمة `bad` مرفوضة
- تقرير domain-level يوضح أسباب الرفض

### 6.2 Spam Score Gate

- فحص spam score قبل البدء.
- إذا المحتوى single-variant وخطير فوق threshold: block للبدء.
- إذا multi-variant: يسمح بالبدء لكن preflight per-chunk يدير المخاطر.

### 6.3 DNSBL/DBL Blacklist Gate

- فحص domain الخاص بالسندر + SMTP host IPs.
- إذا listed: يدخل ضمن blocked reasons للـ backoff.

---

## 7) طريقة الإرسال داخل الـ Chunk

### 7.1 تقسيم المستلمين على workers

- `wc = min(workers, len(chunk))`
- توزيع round-robin بسيط داخل مجموعات workers.

### 7.2 SMTP Session لكل Worker

كل worker:
- يفتح SMTP connection (`ssl` أو `starttls` أو none)
- login إذا credentials موجودة
- يرسل مجموعته sequentially

### 7.3 Personalization/Templating

- placeholders داخل subject/body:
  - `[URL]`
  - `[SRC]`
  - `[MAIL]`/`[EMAIL]`
- header tracing مثل `X-Job-ID`, `X-Campaign-ID`, و`Message-ID` غني بالمعلومات.

### 7.4 Delay بين الرسائل

- `delay_s` يطبق بعد كل رسالة داخل worker.
- يستخدم sleep متقطع (checked sleep) لدعم pause/stop أثناء الانتظار.

---

## 8) الاستراتيجيات الخاصة بالمحتوى (Subject/Body Rotation + AI)

### 8.1 Rotation تلقائي

على مستوى chunk/attempt:
- اختيار subject/body variant يعتمد على `(sender_idx + attempt)`.
- retry يغير variant تلقائياً بدل إعادة نفس الصياغة دائماً.

### 8.2 AI Rewrite Chain (اختياري)

إذا مفعّل:
- قبل chunk جديد (غير retry) يتم إعادة صياغة subjects/body.
- ناتج chunk السابق يصبح أساس chunk اللاحق (chain).
- fallback آمن: إذا فشل AI يستمر بآخر محتوى صالح.

---

## 9) استراتيجية التعلم (Learning) والتكيّف مع المزودات

Shiva يسجل تاريخ محاولات chunk-level:
- `email_attempt_logs`
- `email_attempt_learning`
- `sender_provider_stats`

ثم يولد سياسة ديناميكية لكل provider:
- `retry_cap` معدل
- `backoff_base_s` معدل
- `backoff_max_s` معدل

باستخدام recency-weighted quality trend:
- `fast_success`
- `stable`
- `mixed`
- `degrading`
- `slow_or_failing`

**الفكرة:** كل مزود (gmail/yahoo/...) قد يحصل على سلوك retry مختلف حسب أدائه الأخير فعلياً.

---

## 10) جميع استراتيجيات الإرسال الموجودة حالياً في Shiva (قائمة حصرية)

1. **Normalize + dedupe** للريسيبينت قبل أي إرسال.
2. **Domain bucketing** حسب recipient provider.
3. **Deterministic per-domain balancing** على sender emails.
4. **Round-robin sender scheduling** مع cursor.
5. **Weighted domain selection** حسب حجم المتبقي لكل domain.
6. **Provider-isolated retry queues** بدل إيقاف شامل دائم.
7. **Runtime live overrides** من campaign form.
8. **Accounting-based adaptive health throttling** (speed_up/slowdown/hard_slowdown).
9. **PMTA global pressure policy** (queued/spool/deferred-driven caps).
10. **PMTA per-domain/per-queue chunk policy** (block أو slow).
11. **Spam gate** قبل الإرسال + preflight لكل chunk.
12. **Blacklist gate** (sender domain + smtp IPs).
13. **Adaptive backoff timing** مع max cap وتصنيف نوع الفشل.
14. **Learning-driven provider policy** لتعديل retries/backoff.
15. **Sender/subject/body variant rotation** خصوصاً أثناء retries.
16. **AI rewrite chain** اختياري لتحسين التباين بين chunks.
17. **Multi-threaded per-chunk sending** مع توزيع round-robin داخل workers.
18. **Per-message delay control** (throttle دقيق).
19. **Inter-chunk sleep control**.
20. **Pause/stop-safe sleep loops** لمنع التجمّد أثناء الانتظار.
21. **Recipient pre-send route/smtp probing** لتقليل الارتداد المبكر.
22. **Live telemetry + chunk/backoff history** لدعم القرارات أثناء التشغيل.

---

## 11) ملاحظات تشغيلية عملية

- أفضل أداء يكون عند تفعيل PMTA monitor endpoints حتى تستفيد سياسات الضغط بالكامل.
- في حملات كبيرة، يفضّل وجود أكثر من sender domain/ip مع توزيع سمعة جيد.
- تفعيل SMTP probe مفيد للجودة لكن يجب موازنته مع حد probe limit.
- لا تعتمد على fixed speed فقط؛ القيمة الحقيقية في Shiva هي المزج بين:
  - static controls
  - adaptive health
  - PMTA pressure
  - provider learning

---

## 12) خلاصة تنفيذية

Shiva لا يعمل كـ "مرسل bulk بسيط"؛ بل كـ **محرك إرسال تكيّفي متعدد الطبقات**:

- يقسم البيانات domain-first.
- يوزع الحمل sender-aware.
- يغير السرعة آليًا حسب جودة النتائج وضغط PMTA.
- يعزل retries على مستوى provider بدلاً من تعطيل الحملة كلها.
- يتعلم من التاريخ ليضبط backoff/retry مستقبلًا.

هذا يجعل الإرسال أكثر استقرارًا وجودة مقارنة بنهج ثابت السرعة أو عشوائي التوزيع.
