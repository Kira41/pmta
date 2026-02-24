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
