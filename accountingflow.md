# Accounting Flow (Shiva Pulls from Bridge)

التدفق الصحيح الآن أصبح **اتجاه واحد**:

1. `pmta_accounting_bridge.py` يقرأ ملفات PMTA accounting على السيرفر.
2. `shiva.py` هو الذي يطلب (Pull) من bridge API بشكل دوري عبر IP السيرفر.
3. bridge يرجّع السطور فقط، وShiva يعالجها ويُحدّث الـ outcomes داخل الـ jobs.

> مهم: لم يعد مطلوبًا أن يكون لـ Shiva `public IP` حتى يستقبل push من bridge.

---

## إعدادات Shiva (وضع السحب Pull)

فعّل المتغيرات التالية في `shiva.py` environment:

```bash
export PMTA_BRIDGE_PULL_ENABLED=1
export PMTA_BRIDGE_PULL_URL="http://194.116.172.135:8090/api/v1/pull/latest?kind=acct"
export PMTA_BRIDGE_PULL_TOKEN="<API_TOKEN>"
export PMTA_BRIDGE_PULL_S=5
export PMTA_BRIDGE_PULL_MAX_LINES=2000
```

- `PMTA_BRIDGE_PULL_URL`: endpoint الخاص بالـ bridge على السيرفر.
- `PMTA_BRIDGE_PULL_TOKEN`: نفس `API_TOKEN` الخاص بالـ bridge (Bearer).
- `PMTA_BRIDGE_PULL_S`: كل كم ثانية يعمل Shiva طلب جديد.

يمكنك أيضًا السحب يدويًا من Shiva:

```bash
curl -X POST "http://127.0.0.1:5000/api/accounting/bridge/pull"
```

---

## إعدادات Bridge

الـ bridge يحتاج فقط:

```bash
export API_TOKEN="<API_TOKEN>"
export PMTA_LOG_DIR="/var/log/pmta"
python3 pmta_accounting_bridge.py
```

واستخدم endpoint الجديد الذي يُرجع البيانات بدل دفعها:

```bash
GET /api/v1/pull/latest?kind=acct&max_lines=2000
Authorization: Bearer <API_TOKEN>
```

الـ response يحتوي `lines` (NDJSON lines) + معلومات offsets.

---

## النتيجة

- Shiva هو الذي يطلب دائمًا من bridge.
- bridge يلبّي الطلب فقط.
- التحديث دوري، وتظهر النتائج داخل لوحة Shiva ضمن Outcomes.
