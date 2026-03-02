# تقرير دورة حياة بيانات PMTA Bridge داخل Shiva

هذا التقرير يشرح **ماذا يفعل Shiva بالبيانات بعد سحبها من الـ Bridge** من البداية حتى آخر نقطة مؤثرة في النظام، اعتماداً على الكود الفعلي.

## 1) نقطة البداية: كيف يحدد Shiva عنوان السحب من الـ Bridge

- Shiva يبني رابط السحب ديناميكياً عبر `_resolve_bridge_pull_url_runtime` باستخدام:
  - `host` (قادماً من إعدادات الحملة/البيئة)
  - `PMTA_BRIDGE_PULL_PORT`
  - المسار `/api/v1/pull`
  - المعلمات `kinds=acct` و `limit`.
- قبل البناء، يتم تنظيف اسم المضيف عبر `_normalize_bridge_host` لإزالة scheme والمنفذ إذا كانت قيمة SMTP Host بشكل URL أو `host:port`.

الدوال الأساسية:
- `def _normalize_bridge_host(...)`
- `def _resolve_bridge_pull_url_runtime(...)`

## 2) تشغيل آلية السحب الدوري

- إذا كان `PMTA_BRIDGE_PULL_ENABLED` مفعلاً، يبدأ ثريد poller عبر `start_accounting_bridge_poller_if_needed`.
- الثريد ينفذ حلقة لا نهائية: يستدعي `_poll_accounting_bridge_once` ثم ينام لمدة `PMTA_BRIDGE_PULL_S`.

الدوال الأساسية:
- `def _accounting_bridge_poller_thread(...)`
- `def start_accounting_bridge_poller_if_needed(...)`

## 3) خطوة السحب الواحدة من الـ Bridge (Pull Cycle)

داخل `_poll_accounting_bridge_once`:

1. تحديث حالة debug (`_bridge_debug_update`) وتسجيل زمن المحاولة.
2. التحقق من توفر URL؛ إن لم يوجد يرجع خطأ `bridge_pull_url_not_configured`.
3. تجهيز بدائل URL عبر `_normalize_bridge_pull_urls` لدعم:
   - `/api/v1/pull`
   - `/api/v1/pull/latest` (توافق رجعي)
4. تحميل cursor السابق من SQLite عبر `_db_get_bridge_cursor`.
5. إرسال HTTP GET مع `Accept: application/json`، وتطبيق retry حتى 3 محاولات.
6. فك JSON؛ عند الفشل: `invalid_bridge_json`.
7. استخراج الصفوف من `lines` أو أي key بديل (`events/outcomes/results/messages/items/rows/data`).
8. التحقق من صحة payload؛ عند الفشل: `invalid_bridge_payload`.

**الخلاصة:** في هذه المرحلة Shiva لم يحدّث job counters بعد؛ فقط جلب payload وتجهيزه للمعالجة.

## 4) معالجة كل حدث وارد من الـ Bridge

داخل الحلقة على `bridge_rows` في `_poll_accounting_bridge_once`:

- كل صف يمر إلى `process_pmta_accounting_event`:
  - إذا الصف dict يُستخدم كما هو.
  - إذا نص خام، يحاول Shiva تفكيكه عبر `_parse_accounting_line` (path="bridge").

ثم يتم عدّ النتائج:
- `duplicate` عند تكرار event-id
- `job_not_found` عند عدم القدرة على ربط الحدث بوظيفة
- `accepted` عند نجاح التطبيق على job

## 5) داخل `process_pmta_accounting_event`: قلب دورة الحياة

هذه أهم مرحلة:

1. **توحيد نوع النتيجة**
   - يقرأ `type/event/kind/...` ثم يمررها إلى `_normalize_outcome_type` لتوحيدها إلى:
     - `delivered`
     - `bounced`
     - `deferred`
     - `complained`
   - وإذا فشل، يحاول من `dsnAction/dsnStatus/dsnDiag`.

2. **استخراج recipient**
   - من `rcpt/recipient/email/to/rcpt_to`.

3. **استخراج job_id/campaign_id**
   - job-id من headers (`x-job-id`...)
   - fallback من Message-ID عبر `_extract_job_id_from_text`
   - fallback أخير من `raw`.

4. **بناء event row ثابت للـ dedupe**
   - `_build_accounting_event_row` ينشئ `event_id` (SHA256) باستخدام مفاتيح مستقرة (source/offset/rcpt/type/time/message-id).

5. **إدخال الحدث في SQLite كمرحلة dedupe**
   - `db_insert_accounting_event` إدخال متزامن.
   - إذا موجود مسبقاً: يرجع `duplicate=True` ويتوقف عن تحديث counters.

6. **التحقق من الحقول الأساسية**
   - إذا `rcpt` ناقص أو النوع غير معتمد: `missing_fields`.

7. **ربط الحدث بالـ job المناسب**
   - أولوية الربط:
     1) `JOBS[job_id]`
     2) `_find_job_by_campaign(campaign_id)`
     3) `_find_job_by_recipient(rcpt)`
   - إذا لم يجد: `job_not_found`.

8. **تطبيق النتيجة على job**
   - `_apply_outcome_to_job` يطبق transition منظم ومتفرد لكل recipient:
     - يقرأ outcome السابق من cache/DB
     - يمنع التحولات غير المسموح بها
     - يزيد/ينقص counters (`delivered/bounced/deferred/complained`)
     - يخزن outcome النهائي في DB (`db_set_outcome`)
     - يحدّث `job.accounting_last_ts`

9. **تصنيف الأثر كـ error semantics وتخزينه**
   - `_record_accounting_error` يستدعي `_classify_accounting_response`
   - التصنيف النهائي: `accepted` أو `temporary_error` أو `blocked`
   - التراكم في `job.accounting_error_counts`
   - إضافة سجل في `job.accounting_last_errors` مع trim.

10. **Persist**
   - `job.maybe_persist()` لتثبيت التغييرات.

## 6) ماذا يحدث للـ cursor بعد كل batch

- إذا رد الـ Bridge يحتوي `cursor/next_cursor/has_more`:
  - Shiva يفعّل نمط cursor الحديث.
  - يخزن `next_cursor` في SQLite عبر `_db_set_bridge_cursor`.
  - يعيد polling الفوري لنفس الدورة إذا `has_more=true`.
- إذا `has_more=true` بدون `next_cursor`: يسجل warning ويتوقف لتجنب التكرار.
- إذا الـ Bridge لا يدعم cursor fields، Shiva يدخل وضع legacy (مع تحذير عن احتمال فقدان أحداث عند truncation).

## 7) ماذا يبقى متاحاً للمراقبة بعد المعالجة

Shiva يحدّث حالة debug شاملة عبر `_bridge_debug_update` مثل:
- `last_processed`
- `last_accepted`
- `events_received`
- `events_ingested`
- `duplicates_dropped`
- `job_not_found`
- `db_write_failures`

ويمكن قراءة هذه الحالة عبر API:
- `GET /api/accounting/bridge/status`
- وكذلك سحب يدوي فوري عبر `POST /api/accounting/bridge/pull`.

## 8) ماذا يفعل الـ Bridge نفسه قبل أن تصل البيانات إلى Shiva (السياق السابق)

في `pmta_accounting_bridge.py`:

1. يقرأ الملفات الحديثة المطابقة (`acct-*.csv`) عبر `_recent_matching_files`.
2. يدير resume بواسطة cursor (`_decode_cursor` + `_read_from_cursor`).
3. لكل سطر:
   - `_parse_accounting_line` (JSON/CSV + header memory)
   - `_structured_event` لتحويله لشكل موحد يتضمن `outcome/job_id/campaign_id/rcpt/...`.
4. يعيد payload يحوي:
   - `items`
   - `next_cursor`
   - `has_more`
   - `stats`.

هذا هو payload الذي يسحبه Shiva ويعالج كل عنصر منه كما سبق.

## 9) آخر نقطة في دورة الحياة (Final State)

بعد اكتمال الدورة:
- الحدث الخام محفوظ deduplicated في جدول accounting events.
- outcome النهائي لكل recipient محفوظ في job_outcomes.
- عدادات job المجمّعة محدّثة داخل Shiva (`delivered/bounced/deferred/complained`).
- آخر أخطاء accounting محفوظة مع تصنيفها.
- cursor محفوظ لاستئناف السحب دون فقد/تكرار.
- حالة debug العامة محدّثة ويمكن عرضها من API.

بالتالي: Shiva لا يكتفي بعرض البيانات؛ هو **يحوّلها إلى حالة تشغيلية stateful** (counters + transitions + dedupe + diagnostics + resume cursor).
