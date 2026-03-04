# تقرير شامل: BRIDGE_MODE

هذا المستند يشرح المتغيّر `BRIDGE_MODE` في Shiva، دوره، القيم المسموحة، وتأثير كل وضع تشغيل على مسار جلب بيانات Accounting من Bridge.

## 1) ما هو BRIDGE_MODE؟

`BRIDGE_MODE` هو متغيّر إعداد (Environment Variable / Runtime Config) يحدد **طريقة التكامل بين Shiva وBridge** عند جلب نتائج PowerMTA Accounting.

يتم تحميله عند بدء الخدمة بهذه الصيغة:

- القيمة الافتراضية: `counts`
- أي قيمة خارج المسموح يتم إرجاعها تلقائياً إلى `counts`

عملياً:

- مصدر أولي من البيئة: `os.getenv("BRIDGE_MODE", "counts")`
- ثم `strip().lower()`
- ثم تحقق الصلاحية: `{"counts", "legacy"}` فقط

## 2) القيم المسموحة (Allowed Values)

القيم المقبولة حصراً:

1. `counts`
2. `legacy`

أي قيمة أخرى مثل `count`, `pull`, `new`, `v2`... إلخ تعتبر غير صالحة ويتم **fallback إلى `counts`**.

## 3) السلوك عند القيم غير الصالحة

إذا كانت قيمة `BRIDGE_MODE` غير موجودة أو غير صالحة:

- يتم إجبار الوضع إلى `counts`.
- هذا يحصل عند الإقلاع، وكذلك عند إعادة تحميل الإعدادات من API/UI.

بالتالي `counts` هو الوضع الآمن والافتراضي.

## 4) تقرير كل Mode

### A) Mode = `counts` (الوضع الافتراضي والمُوصى به)

هذا الوضع يجعل Shiva يعتمد على مسار **عدّادات لكل Job** عبر:

- `/api/v1/job/count`
- و(اختيارياً) `/api/v1/job/outcomes` إذا كان `OUTCOMES_SYNC/BRIDGE_POLL_FETCH_OUTCOMES` مفعلاً.

#### ماذا يحدث في هذا الوضع؟

- يمر Shiva على الـ active jobs (queued/running/backoff/paused).
- لكل job يطلب `job/count`.
- يحدّث عدادات `delivered/deferred/bounced/complained` مباشرة على job.
- يمكنه أيضاً مزامنة outcomes التفصيلية (emails + event type) عند التفعيل.

#### ماذا يتوقف في هذا الوضع؟

عناصر legacy-based pull يتم تعطيلها عملياً:

- URL الخاص بـ `/api/v1/pull` لا يُبنى (يرجع فارغ).
- Normalization لقنوات pull القديمة يرجع قائمة فارغة.
- Cursor في DB (`bridge_pull_state`) لا يُقرأ ولا يُكتب.

#### متى نستخدمه؟

- في التشغيل الحديث المستقر.
- عندما تريد دقة counters لكل job بشكل مباشر.
- عندما تريد تقليل تعقيد cursor/offset في ingestion.

### B) Mode = `legacy`

هذا الوضع يبقي أدوات مسار pull القديم متاحة (cursor و URL بناء `/api/v1/pull`).

#### ماذا يبقى مفعلاً؟

- `_resolve_bridge_pull_url_runtime()` يُرجع URL فعلي إلى `/api/v1/pull?kinds=acct&limit=...`.
- `_normalize_bridge_pull_urls()` تُنتج صيغ pull/latest للتوافق.
- قراءة/كتابة cursor من جدول `bridge_pull_state` تظل مفعّلة.

#### ملاحظة مهمة

حتى مع `legacy`، حلقة الـ poller الأساسية الحالية في Shiva ما زالت تعتمد على base URL + job endpoints (`/job/count` و`/job/outcomes`) في المسار الأساسي.

بالتالي `legacy` هنا يُستخدم غالباً للتوافق الخلفي (compatibility helpers) وليس كنموذج تشغيل أساسي جديد.

#### متى نستخدمه؟

- عند الحاجة لتوافق مع تكامل قديم يعتمد cursor/pull helpers.
- في حالات انتقالية أثناء الترحيل من pull stream إلى job-count model.

## 5) كيف يختار النظام القيمة؟

### عند بدء التشغيل

1. يقرأ من `BRIDGE_MODE` في البيئة.
2. يحوّل lowercase.
3. يحقق ضمن `{counts, legacy}`.
4. إن فشل: يضع `counts`.

### عند reload runtime settings

نفس القاعدة تتكرر من مخزن الإعدادات (cfg).

## 6) العلاقة مع متغيرات أخرى

- `PMTA_BRIDGE_PULL_ENABLED`: تشغيل/إيقاف poller بالكامل.
- `BRIDGE_BASE_URL`: إذا لم يحدد، Shiva يبني base URL من `smtp_host` + `PMTA_BRIDGE_PULL_PORT`.
- `OUTCOMES_SYNC` و `BRIDGE_POLL_FETCH_OUTCOMES`: تفعيل/تعطيل جلب outcomes مع counts.
- `PMTA_BRIDGE_PULL_MAX_LINES`: مؤثر في URL الخاص بمسار pull القديم (مهم أكثر مع legacy).

## 7) توصية تشغيل عملية

للغالبية:

- استخدم `BRIDGE_MODE=counts`
- فعّل `OUTCOMES_SYNC=1` إذا أردت تفاصيل outcomes لكل مستلم
- اضبط `PMTA_BRIDGE_PULL_PORT` و/أو `BRIDGE_BASE_URL` بشكل صحيح

## 8) أمثلة

### مثال 1: الإعداد الموصى به

```bash
BRIDGE_MODE=counts
PMTA_BRIDGE_PULL_ENABLED=1
OUTCOMES_SYNC=1
PMTA_BRIDGE_PULL_PORT=8090
```

### مثال 2: تشغيل legacy للتوافق

```bash
BRIDGE_MODE=legacy
PMTA_BRIDGE_PULL_ENABLED=1
PMTA_BRIDGE_PULL_MAX_LINES=2000
```

## 9) خلاصة سريعة

- القيم المسموحة فقط: `counts` و `legacy`.
- الافتراضي والـ fallback: `counts`.
- `counts`: يعتمد job count (+ optional outcomes) ويعطل legacy cursor/pull.
- `legacy`: يُبقي أدوات pull/cursor للتوافق، لكن مسار polling الأساسي ما زال job-centric.
