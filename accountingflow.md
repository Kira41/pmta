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
