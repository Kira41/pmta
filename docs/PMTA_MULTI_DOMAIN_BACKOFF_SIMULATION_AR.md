# تقرير محاكاة شامل: توزيع الإرسال متعدد Sender Domains مع Backoff على Provider محدد

## 1) الهدف
هذا التقرير يشرح **كيف يعمل الإرسال في Shiva/PMTA** عندما يكون لدينا:
- عدة Sender Domains.
- عدة Recipient Domains/Providers (Gmail / Yahoo / Hotmail / AOL).
- وضع Provider واحد في حالة **Backoff** (تم اختيار Yahoo في هذه المحاكاة).

المحاكاة نفسها قابلة لإعادة التشغيل عبر السكربت:

```bash
python tools/simulate_provider_backoff.py
```

---

## 2) كيف يقسم النظام الإرسال (بناءً على الكود)
في الكود الفعلي داخل `shiva.py`، المنطق كالتالي:

1. **تجميع المستلمين حسب recipient-domain** داخل buckets (كل domain = queue مستقلة).  
2. **جدولة Round-Robin بين الـ domains**: يأخذ Chunk من domain1 ثم domain2 ثم domain3 ... لضمان توزيع الضغط.  
3. **كل Chunk يُرسل من Sender واحد** (مع تدوير sender عند كل chunk/attempt).  
4. قبل الإرسال لكل Chunk، يتم فحص:
   - Spam score.
   - Blacklist.
   - PMTA domain/queue policy (قد ترجع block أو slow mode).
5. إذا chunk blocked: يدخل **Backoff أسي** (Exponential Backoff) مع retries محددة.

---

## 3) إعداد السيناريو المحاكى

### Sender Domains (3)
- `ops@alpha-mail.com`
- `mailer@beta-delivery.net`
- `notify@gamma-send.org`

### Recipient Domains
- Gmail: 5
- Yahoo: 4
- Hotmail: 3
- AOL: 3

### إعدادات التحكم
- `chunk_size=3`
- `max_backoff_retries=3`
- `backoff_base_s=60`
- `backoff_max_s=1800`

### فرضية الضغط (Backoff)
تم حقن سلوك: **Yahoo** تُعتبر غير مستقرة في أول محاولتين لكل chunk (`attempt 0` و`attempt 1`) وبالتالي:
- attempt 1 => backoff 60s
- attempt 2 => backoff 120s
- attempt 3 => successful send

---

## 4) نتيجة المحاكاة

### ملخص رقمي
- إجمالي المستلمين: 15
- Delivered: 15
- Deferred (أثناء التذبذب قبل النجاح): 8
- Chunks done: 6
- Backoff events: 4
- Abandoned chunks: 0

### تسلسل زمني مختصر
1. Chunk Gmail يُرسل مباشرة.
2. Chunk Yahoo يدخل backoff مرتين (60s ثم 120s)، ثم ينجح بالمحاولة الثالثة.
3. Hotmail وAOL يستمران طبيعيًا.
4. Chunk Yahoo الأخير (حجم 1) يكرر نفس سلوك backoff ثم ينجح.

**ملاحظة مهمة:** أثناء backoff لـ Yahoo، النظام لا “يكسر” مبدأ العزل لكل provider chunk؛ أي لا يخلط chunk domains داخل نفس المحاولة، وهذا يقلل أثر الخطأ على باقي المزودين.

---

## 5) ماذا يحدث عمليًا عندما يدخل Provider في Backoff؟
عند block على Chunk:
1. تتغير حالة الـ Job إلى `backoff`.
2. يتم تسجيل سبب المنع (spam/blacklist/pmta).
3. تُزاد عدادات `chunks_backoff`.
4. انتظار أسي: `base * 2^(attempt-1)` مع سقف `backoff_max_s`.
5. إعادة محاولة نفس الـ chunk مع **تدوير sender** (إزاحة sender cursor مع كل retry).
6. إذا تجاوز retries المسموحة ⇒ `abandoned` ويُحتسب على skipped.

في محاكاتنا، Yahoo لم تتجاوز الحد، فتمت الاستعادة بدون abandon.

---

## 6) كيف يتم تحسين الإرسال (Tuning) في هذا النموذج؟

### A) على مستوى التقسيم Scheduling
- الحفاظ على `chunk_size` متوسط (مثل 20–100 بالحمل الحقيقي) لتقليل blast radius.
- Round-robin بين providers يمنع احتكار مزود واحد للاتصال والزمن.

### B) على مستوى الـ Backoff
- تقليل `BACKOFF_BASE_S` إذا كانت الأعطال عابرة جدًا.
- رفعه تدريجيًا عند مزودات حساسة لتقليل معدل re-attempt.
- إبقاء `BACKOFF_MAX_RETRIES` متزن (لا منخفض جدًا فيضيع التسليم، ولا مرتفع جدًا فيطيل queue).

### C) على مستوى جودة المحتوى والسمعة
- استخدام preflight spam scoring قبل كل chunk.
- تدوير sender domains + subject/body variants بحذر.
- تجنب القفز الحاد في throughput عند مزود واحد.

### D) على مستوى PMTA health/policy
- تفعيل PMTA queue/domain policy لتطبيق slow mode مبكرًا قبل الوصول لحالة block.
- الاستفادة من `workers_max` و`delay_min` عند ضغط provider.

---

## 7) آليات تقليل الخطر (Risk Reduction) الموجودة بالنظام

1. **Pre-send recipient filtering** (syntax + mx/probe) لتقليل invalids قبل الإرسال.
2. **Spam threshold gate** (منع/تحذير حسب السيناريو) قبل وأثناء التنفيذ.
3. **Blacklist checks** لكل chunk.
4. **PMTA adaptive policy**:
   - Block عند مؤشرات خطرة.
   - Slow mode عند مؤشرات متوسطة.
5. **Chunk isolation**: أي مشكلة في domain لا توقف بالضرورة domains الأخرى.
6. **Live runtime overrides** من DB أثناء التشغيل (delay/workers/chunk_size/threshold).
7. **Structured job telemetry** (chunk states + backoff items + counters) لتحليل ما بعد الحادثة.

---

## 8) خلاصة تنفيذية
- عند وجود عدة sender domains وعدة recipient domains، التصميم الحالي يعتمد **Provider-aware Round-Robin** مع **Chunk-level controls**.  
- عند وضع مزود مثل Yahoo في backoff، الإرسال لا ينهار بالكامل؛ بل يتم **احتواء المشكلة على chunks الخاصة به** وإعادة المحاولة أسيًا حتى التعافي.  
- أفضل توازن للتحسين يكون عبر: ضبط chunk/workers/delay + سياسات PMTA + ضبط backoff + تحسين المحتوى/السمعة.

هذا يحقق ثلاثة أهداف معًا:
1. الاستمرارية (Continuity) لباقي providers.
2. تقليل المخاطر reputational/operational.
3. رفع نسبة التسليم النهائية مع تحكم أدق في السلوك وقت التذبذب.
