# تقرير شامل: أخطاء مزودي الخدمة (Gmail وغيرهم) ودورة حياتها بين PMTA Bridge وShiva

## ملخص تنفيذي سريع
- نعم، الأخطاء القادمة من المزودين (مثل Gmail/Yahoo/Outlook) **يتم التقاطها ومعالجتها** في النظام، لكن المعالجة هنا تعني: 
  1) **تصنيفها** إلى (delivered / deferred / bounced / complained)، 
  2) **ربطها** بالـ job والـ recipient، 
  3) **تحديث العدادات** وحفظ تفاصيل DSN/diagnostic، 
  4) **إظهارها** في APIs والحالة والواجهة.
- في الوضع الافتراضي الحالي (`BRIDGE_MODE=counts`) Shiva يعتمد أساسًا على Bridge endpoints: `/api/v1/job/count` (إجباري) و `/api/v1/job/outcomes` (اختياري حسب الإعداد) بدل السحب الخام `/api/v1/pull` legacy. 
- لذلك “بريج كيف يأخذها؟” = من ملفات PMTA accounting CSV/JSON، و“شيفا كيف يأخذها؟” = عبر HTTP pull من bridge، ثم إدخال/مزامنة النتائج في SQLite وذاكرة الـ job.

---

## 1) من أين تأتي أخطاء Gmail/المزوّدين أصلًا؟
1. PMTA يكتب أحداث التسليم في accounting logs (`acct-*.csv`) مثل:
   - `type` (مثل d/t/b/c)
   - `dsnStatus` (مثل 2.x / 4.x / 5.x)
   - `dsnDiag` (نص تشخيصي من المزود)
   - `rcpt`, `header_x-job-id`, `header_message-id`.
2. Bridge يقرأ هذه الملفات من `PMTA_LOG_DIR`، ويدعم parsing لأسطر JSON أو CSV مع header memory لكل ملف.
3. Bridge يخرج event منظم (structured event) يحتوي outcome + dsn fields + job/campaign ids.

هذا يعني: خطأ Gmail (مثلاً 421/451/550/5.7.1) يظهر غالبًا في `dsnStatus` أو `dsnDiag`، ثم ينعكس كتَصنيف outcome داخل pipeline.

---

## 2) كيف يتم تصنيف الأخطاء تقنيًا؟

### 2.1 في Bridge
Bridge يطبّق تطبيع outcome بطبقتين:
- طبقة lexical/alias (`_normalize_outcome_type`) لتحويل كلمات كثيرة إلى buckets موحدة.
- طبقة DSN rule-based (`_normalized_outcome`) تعتمد على:
  - `type=d` أو `dsnStatus` يبدأ بـ2 => delivered
  - `type=t` أو `dsnStatus` يبدأ بـ4 => deferred
  - `type=b` أو `dsnStatus` يبدأ بـ5 => bounced
  - وجود complaint/fbl/abuse في التشخيص => complained
  - غير ذلك => unknown.

وهنا يظهر مصير السطر “غير المفهوم”: يظل unknown ويُحتسب في `unknown_outcome` بإحصائيات pull.

### 2.2 في Shiva
Shiva عند معالجة event يستخدم `_normalize_outcome_type` مرة أخرى لحماية إضافية، وإذا لم ينجح يأخذ إشارات من `dsnAction / dsnStatus / dsnDiag`.
ثم يقيّد النتائج على 4 حالات نهائية فقط:
- delivered
- deferred
- bounced
- complained

أي شيء خارجها لن يُطبق على counters (يرجع missing_fields/غير مقبول كـ outcome نهائي).

---

## 3) كيف “بريج يأخذها”؟ وأين يأخذها؟

### 3.1 المصدر المكاني
- المصدر الفعلي: directory `PMTA_LOG_DIR` (افتراضيًا `/var/log/pmta`).
- الملفات المستهدفة: خصوصًا `acct-*.csv` للـ accounting.

### 3.2 آلية القراءة
يوجد مساران رئيسيان في bridge:
1. **Cursor Pull (`/api/v1/pull`)**:
   - يبحث ملفات حديثة ضمن نافذة عمر/عدد (`RECENT_PULL_MAX_AGE_HOURS`, `RECENT_PULL_MAX_FILES`).
   - يفك cursor (base64 json) ويكمل من inode/path/offset.
   - يقرأ حتى limit، ويبني `next_cursor`، ويعيد `has_more` + stats (`parsed`, `skipped`, `unknown_outcome`).
2. **Latest Pull (`/api/v1/pull/latest`)**:
   - alias متوافق للخلفية، ويقرأ آخر ملف أو حسب `x-job-id` بالهيدر.

في كِلَا المسارين، bridge يستخرج job_id إمّا من header_x-job-id أو من message-id pattern عندما الحقول المباشرة ناقصة.

---

## 4) كيف Shiva يأخذ هذه الأخطاء من Bridge؟

## 4.1 الوضع الحالي الافتراضي: Counts Mode
عند `BRIDGE_MODE=counts`:
- Shiva لا يستخدم cursor legacy.
- لكل job فعّال يعمل fetch إلى:
  - `/api/v1/job/count?job_id=...` (العدادات المجمعة)
  - `/api/v1/job/outcomes?job_id=...` (قوائم recipients per outcome) إذا `BRIDGE_POLL_FETCH_OUTCOMES=1`.
- ثم يقوم **بتعيين** counters مباشرة (authoritative replace) وليس جمعًا تراكميًا؛ لمنع drift.

## 4.2 Legacy Mode (عند تفعيله)
- Shiva يبني URL `/api/v1/pull` ديناميكياً من smtp_host/based config.
- يقرأ rows/events ويعالج كل حدث بـ `process_pmta_accounting_event`.
- يحفظ `next_cursor` في جدول `bridge_pull_state` للاستكمال بعد restart.

---

## 5) أين تُخزَّن هذه الأخطاء/النتائج داخل Shiva؟

1. **جدول `accounting_events`**:
   - سجل append-only للأحداث مع `event_id` hash ثابت لمنع التكرار (idempotent ingestion).
   - يخزن: job_id, rcpt, outcome, message_id, dsn_status, dsn_diag, source location, raw_json.

2. **جدول `job_outcomes`** (حالة recipient النهائية لكل job):
   - مفتاح مركب `(job_id, rcpt)`.
   - يحتفظ status + آخر message_id + dsn details.

3. **كائن SendJob في الذاكرة + snapshot**:
   - counters: delivered/bounced/deferred/complained.
   - `accounting_error_counts` مصنفة إلى accepted/temporary_error/blocked.
   - `accounting_last_errors` (آخر سجلات خطأ accounting مع تقليم size).

---

## 6) ما تأثير أخطاء المزود على الإرسال؟

## 6.1 على مستوى العدادات والمعاينة
- deferred تزيد عداد deferred (غالبًا مؤقتة 4xx، لم تُحسم نهائيًا بعد).
- bounced تزيد عداد bounced (غالبًا 5xx نهائي/رفض).
- complained تزيد complained (Feedback loop/abuse).
- delivered تزيد delivered (قبول/relay).

## 6.2 على مستوى “حقيقة النجاح”
- النظام يوضح أن “sent” = accepted من جهة SMTP client/PMTA، وليس دائمًا delivered نهائيًا؛ إذ قد يتحول لاحقًا إلى deferred أو bounced أو complained عبر accounting.
- لذلك monitoring الحقيقي يكون من accounting outcomes وليس فقط sent counter.

## 6.3 على مستوى اتخاذ القرار
- Shiva يبني snapshots وواجهات status للوظائف، ويعرض last errors والتوزيع per outcome.
- إذا bridge فشل مؤقتًا، Shiva يحافظ على آخر counters الناجحة ولا يصفرها قسرًا (وفق اختبارات الهارنس).

---

## 7) دورة حياة خطأ مزود الخدمة (Lifecycle) خطوة بخطوة

1. **SMTP attempt** يتم عبر PMTA إلى مزود (مثل Gmail).
2. **Provider response** يُسجل في PMTA accounting (type/dsnStatus/dsnDiag).
3. **Bridge ingestion**:
   - parse line
   - normalize outcome
   - build structured event
   - expose عبر API (pull أو job/count + job/outcomes).
4. **Shiva polling**:
   - counts mode: يجلب count/outcomes لكل job
   - legacy mode: يسحب rows خام ويعالجها event-by-event.
5. **Dedupe + Persist** داخل Shiva:
   - event_id hash لمنع التكرار.
   - job_outcomes upsert لكل recipient.
6. **Transition rules**:
   - deferred يمكن أن يتحول إلى delivered/bounced/complained.
   - delivered يمكن أن يتحول إلى complained.
   - transitions غير المسموحة لا تغيّر الحالة النهائية.
7. **Counters update** بآلية unique per recipient.
8. **Error classification** إلى accepted / temporary_error / blocked اعتمادًا على أكواد 2xx/4xx/5xx أو fallback.
9. **Visibility** عبر endpoints:
   - bridge status/count/outcomes
   - shiva bridge status + jobs metrics.
10. **Recovery**:
   - legacy: cursor resume من SQLite.
   - counts: polling دوري + failure bookkeeping في debug state.

---

## 8) إجابة مباشرة على أسئلتك (بشكل صريح)

## س: هل هذه الأخطاء يتم معالجتها أم لا؟
نعم، تُعالج على مستوى التصنيف والتخزين والتأثير على العدادات والعرض، وليس بمعنى “إصلاح خطأ Gmail نفسه”. النظام يستهلك ردود المزود ويحوّلها إلى حالة تشغيلية قابلة للمتابعة.

## س: كيف يتمكن Bridge من أخذها؟
Bridge يقرأ accounting files مباشرة من PMTA log dir، يحلل CSV/JSON، يستنتج job/campaign/message ids، ثم يقدّم النتائج عبر APIs.

## س: أين يتم أخذها؟
من ملفات `acct-*.csv` تحت `PMTA_LOG_DIR` (والنظام يدعم أيضًا أنماط log/diag عند الطلب، لكن جوهر outcomes من accounting).

## س: ما تأثيرها على الإرسال؟
- تؤثر على صورة النجاح الفعلية post-send: delivered/deferred/bounced/complained.
- تؤثر على تقارير job ومؤشرات الجودة واتخاذ قرارات الإيقاف/التحسين.
- لا ترجع الرسائل المرسلة للخلف، لكنها تغيّر تقييم النتيجة النهائية لكل recipient.

## س: ما دورة حياتها؟
من response في PMTA → parsing في bridge → sync/poll في Shiva → dedupe/persist → counter transition → status/reporting/debug.

---

## 9) ماذا تؤكد الاختبارات (Harness + CSV fixture)؟
الاختبارات الحالية تثبت نقاط مهمة جدًا عمليًا:
1. replay لعينة CSV ينتج 4 outcomes صحيحة + unknown واحد.
2. الاستكمال بالـ cursor لا يضيّع outcomes.
3. poller في counts mode يستخدم `/job/count` و `/job/outcomes`.
4. outcomes sync يعمل flatten/upsert ويحذف stale recipients.
5. عند فشل bridge لاحقًا لا يتم تصفير counters السابقة.
6. lock يمنع تداخل دورات poll المتزامنة (busy behavior واضح).

والـ fixture يحتوي حالة d/t/b/c مع سطر `x` unknown لتأكيد سلوك unknown_outcome.

---

## 10) توصيات تشغيلية دقيقة (لتقليل مشاكل Gmail وغيرها)
1. اعتمد متابعة outcome وليس sent فقط.
2. فعّل `BRIDGE_POLL_FETCH_OUTCOMES=1` حتى تمتلك recipient-level truth داخل Shiva.
3. راقب `last_error_message`, `last_error_ts`, و `jobs_failed` في bridge status.
4. حلّل `dsn_diag` نصيًا (خصوصًا Gmail) لاستخراج أسباب rate-limit/policy/auth/unknown-user.
5. لا تعتبر deferred فشل نهائي؛ راقب تحوله لاحقًا عبر transition المسموح.
6. راقب drift بين PMTA dashboard وShiva counters؛ في counts mode المصدر authoritative هو bridge count.

---

## 11) مرجع الدوال/المكونات التي تم تغطيتها في هذا التقرير
- Bridge:
  - `_parse_accounting_line`, `_normalized_outcome`, `_structured_event`, `_read_from_cursor`, `pull_accounting`, `get_job_outcomes`, `get_job_count`, `bridge_status`.
- Shiva:
  - `_poll_accounting_bridge_once`, `_bridge_fetch_json`, `_bridge_sync_job_outcomes`, `_replace_job_accounting_from_bridge_count`,
  - `process_pmta_accounting_event`, `_apply_outcome_to_job`, `_record_accounting_error`, `_classify_accounting_response`,
  - `_transition_allowed`, `api_accounting_bridge_status`, `api_accounting_bridge_pull_once`.
- Tests/fixtures:
  - `tests/test_bridge_shiva_harness.py`
  - `tests/fixtures/acct-sample.csv`

