# Operational Guides

هذا الملف يجمع ملفات الشرح التشغيلية في المشروع (باستثناء ملف `ENVIRONMENT_VARIABLES.md` الذي يبقى مستقلاً).

---

## 1) Accounting Flow (Shiva Pull Model)

التدفق الحالي يعمل بنمط **Pull** من Shiva إلى bridge:

1. Bridge (`pmta_accounting_bridge.py`) يقرأ ملفات PMTA accounting.
2. Shiva (`shiva.py`) ينفّذ طلبات دورية إلى bridge API عبر IP السيرفر.
3. Bridge يعيد سطور البيانات فقط.
4. Shiva يفسّر السطور ويحدّث outcomes الخاصة بالـ jobs/campaigns.

> بهذه الطريقة لا يحتاج Shiva إلى public IP ليستقبل push.

### Bridge API endpoint

- `GET /api/v1/pull/latest?kind=acct&max_lines=<N>`
- المصادقة: `Authorization: Bearer <API_TOKEN>` (أو `?token=` كخيار بديل)

### مثال استجابة

```json
{
  "ok": true,
  "kind": "acct",
  "file": "acct-2026-02-24.csv",
  "from_offset": 12345,
  "to_offset": 14789,
  "has_more": false,
  "count": 120,
  "lines": ["{...}", "{...}"]
}
```

### إعدادات Shiva (Pull Mode)

```bash
export PMTA_BRIDGE_PULL_ENABLED=1
export PMTA_BRIDGE_PULL_URL="http://194.116.172.135:8090/api/v1/pull/latest?kind=acct"
export PMTA_BRIDGE_PULL_TOKEN="<API_TOKEN>"
export PMTA_BRIDGE_PULL_S=5
export PMTA_BRIDGE_PULL_MAX_LINES=2000
```

### إعدادات Bridge

```bash
export API_TOKEN="<API_TOKEN>"
export PMTA_LOG_DIR="/var/log/pmta"
python3 pmta_accounting_bridge.py
```

### فحوصات الجاهزية

```bash
# 1) اختبار endpoint على bridge
curl -i -H "Authorization: Bearer <API_TOKEN>" \
  "http://194.116.172.135:8090/api/v1/pull/latest?kind=acct&max_lines=5"

# 2) حالة إعدادات bridge داخل Shiva
curl -s "http://127.0.0.1:5000/api/accounting/bridge/status"

# 3) تنفيذ سحب يدوي من Shiva
curl -s -X POST "http://127.0.0.1:5000/api/accounting/bridge/pull"
```

الإشارات المتوقعة:

- `pull_enabled=true`
- `pull_url` مضبوط على endpoint السحب
- نجاح طلب السحب اليدوي وتحديث outcomes

---

## 2) Multi Sender Domains Scenario

هذا القسم يشرح سلوك التوزيع عند استخدام عدة Sender Domains.

### الفكرة العامة

التوزيع يتم على مستويين:

1. **داخل Shiva:** اختيار `from_email` بطريقة rotation لكل chunk.
2. **داخل PowerMTA:** ربط `MAIL FROM` مع `virtual-mta`/IP مناسب (strict 1:1 domain→IP).

### مثال عملي (5 دومينات Sender)

إذا كانت القيم في Sender Email كالتالي (كل سطر مرسل مختلف):

- `a@mediapaypro.cloud`
- `b@mediapaypro.info`
- `c@mediapaypro.live`
- `d@mediapaypro.vip`
- `e@mediapaypro.work`

فالسلوك يكون:

1. تجميع المستلمين حسب recipient domain (مثل `gmail.com`, `yahoo.com`, `outlook.com`).
2. الإرسال بنمط round-robin عبر buckets بدلاً من إنهاء provider واحد بالكامل.
3. تدوير المرسل (`from_email`) بشكل عادل أثناء العمل.

### النتيجة المتوقعة

- توزيع أكثر توازنًا على providers.
- تقليل الاندفاع على provider واحد.
- الحفاظ على سياسة الربط الصارم domain→IP داخل PMTA.

---

## ملاحظات تنظيمية

- الملف `ENVIRONMENT_VARIABLES.md` متروك بشكل مستقل لأنه ملف مرجعي خاص بالمتغيرات.
- جميع الشروحات التشغيلية الأخرى تم تجميعها هنا لتسهيل الوصول.
