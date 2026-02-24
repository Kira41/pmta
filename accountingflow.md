# Accounting Flow (bridge.py ↔ shiva.py)

> هذا الملف إضافة توضيحية بنفس محتوى `ACCOUNTING_FLOW.md` لكن باسم lowercase لتسهيل العثور عليه.

## الفكرة الأساسية

- `shiva.py` **لا يتصل** مباشرةً بـ `pmta_accounting_bridge.py`.
- `shiva.py` فقط يستقبل Webhook على:
  - `POST /pmta/accounting`
- `pmta_accounting_bridge.py` يقرأ ملفات PMTA (accounting/logs) ثم يرسل NDJSON إلى Webhook الخاص بـ Shiva.

## المتغيرات الصحيحة لكل طرف

### داخل Shiva (`shiva.py`)

- `PMTA_ACCOUNTING_WEBHOOK_TOKEN` (توكن التحقق في `X-Webhook-Token` أو `?token=`)
- `PMTA_ACCOUNTING_WEBHOOK` لتفعيل/تعطيل Endpoint
- (اختياري) متغيرات file tailing داخل Shiva مثل `PMTA_ACCOUNTING_FILES` و `PMTA_ACCOUNTING_DIRS`

### داخل Bridge (`pmta_accounting_bridge.py`)

- `SHIVA_ACCOUNTING_URL`  
  الرابط الكامل لـ Shiva webhook (مثلاً `http://127.0.0.1:5000/pmta/accounting`)
- `SHIVA_WEBHOOK_TOKEN`  
  نفس السر المشترك المعرّف في Shiva داخل `PMTA_ACCOUNTING_WEBHOOK_TOKEN`

## لماذا لم تجد `SHIVA_ACCOUNTING_URL` داخل `shiva.py`؟

لأن هذا المتغير **خاص بالـ bridge** وليس Shiva.  
Shiva يستقبل فقط؛ bridge هو الذي "يعرف أين يرسل".

## تسلسل التبادل

1. bridge يحدد أحدث ملف accounting.
2. bridge يقرأ السطور ويبني NDJSON.
3. bridge يرسل `POST` إلى `SHIVA_ACCOUNTING_URL` مع:
   - `Content-Type: application/x-ndjson`
   - `X-Webhook-Token: SHIVA_WEBHOOK_TOKEN`
4. Shiva يتحقق من التوكن ويحوّل الأحداث إلى job/campaign outcomes.

## سؤالك المباشر: أين أضع الرابط `http://194.116.172.135:8090/`؟

- هذا العنوان (مع المنفذ `8090`) هو غالبًا عنوان **خدمة bridge نفسها**.
- لا تضعه داخل `shiva.py` أو كمتغير `PMTA_ACCOUNTING_WEBHOOK_TOKEN`.

### إذا كان 8090 هو Port الخاص بالـ bridge

- bridge يعرف المنفذ من متغير البيئة `PORT`.
- إذا لم تضبطه يدويًا، القيمة الافتراضية في `pmta_accounting_bridge.py` هي `8090`.

مثال:

```bash
# تشغيل bridge على 8090 (افتراضيًا)
export PORT=8090
python3 pmta_accounting_bridge.py
```

### أين يوضع رابط Shiva الحقيقي؟

يوضع في bridge داخل:

```bash
export SHIVA_ACCOUNTING_URL="http://<shiva-host>:<shiva-port>/pmta/accounting"
export SHIVA_WEBHOOK_TOKEN="<same-value-as-PMTA_ACCOUNTING_WEBHOOK_TOKEN-in-shiva>"
```

> مهم: `SHIVA_ACCOUNTING_URL` يجب أن يشير إلى **Shiva endpoint** وليس إلى bridge endpoint.

### كيف ترسل للـ bridge من الخارج؟

إذا bridge شغّال على `194.116.172.135:8090` فاستدعِ endpoint الخاص به مثل:

```bash
curl -X POST "http://194.116.172.135:8090/api/v1/push/latest?kind=acct&token=<API_TOKEN>"
```

هذا الطلب يذهب إلى bridge؛ والـ bridge بعدها يرسل النتائج إلى Shiva عبر `SHIVA_ACCOUNTING_URL`.


## محاكاة عملية كاملة (Shiva على localhost + Bridge/PMTA على سيرفر خارجي)

نفترض السيناريو التالي:

- Shiva يعمل محليًا على جهازك: `http://127.0.0.1:5000`
- Bridge + PowerMTA + accounting files على السيرفر: `194.116.172.135`
- bridge يعمل على: `http://194.116.172.135:8090`

### 1) تفعيل endpoint في Shiva (المستقبِل)

على جهاز Shiva المحلي:

```bash
export PMTA_ACCOUNTING_WEBHOOK=1
export PMTA_ACCOUNTING_WEBHOOK_TOKEN="MY_SHARED_SECRET"
# ثم شغّل shiva.py على بورتك المحلي (مثلاً 5000)
```

الآن Shiva جاهز ليستقبل `POST /pmta/accounting`.

### 2) جعل bridge يعرف عنوان Shiva

على السيرفر الذي فيه bridge:

```bash
export PORT=8090
export SHIVA_ACCOUNTING_URL="http://PUBLIC_OR_VPN_IP_OF_SHIVA:5000/pmta/accounting"
export SHIVA_WEBHOOK_TOKEN="MY_SHARED_SECRET"
python3 pmta_accounting_bridge.py
```

> إن كان Shiva فقط على `127.0.0.1` فلن يستطيع السيرفر الخارجي الوصول له مباشرة.
> تحتاج أحد الحلول: (a) تشغيل Shiva على عنوان شبكي يمكن الوصول له، أو (b) VPN، أو (c) reverse tunnel (مثل ngrok/cloudflared/ssh tunnel).

### 3) طلب دفع النتائج من bridge (يدويًا أو Cron)

```bash
curl -X POST "http://194.116.172.135:8090/api/v1/push/latest?kind=acct&token=<API_TOKEN>"
```

ماذا يفعل bridge داخليًا؟

1. يختار أحدث ملف accounting مناسب.
2. يقرأ آخر السطور (NDJSON/CSV parsing line by line).
3. يرسل NDJSON إلى `SHIVA_ACCOUNTING_URL` مع `X-Webhook-Token`.

### 4) مثال Response من Shiva إلى bridge

عند نجاح webhook، Shiva يرجع JSON مشابه:

```json
{
  "ok": true,
  "processed": 120,
  "accepted": 118,
  "errors": 2
}
```

الـ bridge يعيد لك (كعميل ناديت `/push/latest`) Response فيه:

```json
{
  "ok": true,
  "file": "acct-2026-02-24.ndjson",
  "pushed": 120,
  "upstream": {
    "status": 200,
    "response": {
      "ok": true,
      "processed": 120,
      "accepted": 118,
      "errors": 2
    }
  }
}
```

### 5) ماذا يفعل Shiva بهذه الأحداث؟

Shiva يعالج كل event بهذا المنطق:

1. يحاول ربط الحدث بـ `job_id` مباشرةً (`x-job-id` أو `job-id`...).
2. إن لم يجد، يحاول استخراج `job_id` من Message-ID.
3. إن لم يجد، fallback على `campaign_id`.
4. عند نجاح الربط: يحدّث حالة المستلم (`delivered` / `bounced` / `deferred` / `complained`) ويزيد العدادات.

### 6) كيف تظهر على الداشبورد؟

بعد تحديث العدادات داخل job/campaign state:

1. APIs الداخلية في Shiva ترجع الحقول المحدثة.
2. واجهة الداشبورد تقرأ `outcomes` و `accounting_last_ts` وغيرها.
3. ترى مباشرة الأرقام مثل delivered/bounced/deferred/complained محدثة.

### 7) أهم نقطة تمنع الالتباس

- Shiva **لا يسحب** من bridge.
- bridge هو الذي **يدفع Push** إلى Shiva webhook.
- لذلك الرابط الذي تضعه في bridge يجب أن يكون رابط Shiva (`/pmta/accounting`) وليس العكس.
