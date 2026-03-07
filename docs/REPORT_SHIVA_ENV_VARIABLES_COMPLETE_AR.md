# تقرير شامل وعميق لمتغيرات البيئة في Shiva

## 1) الملفات المرجعية الخاصة بـ Environment Variables في المستودع

- `ENVIRONMENT_VARIABLES.md`
- `docs/REPORT_SHIVA_ENV_VARIABLES_MASTER.md`
- `docs/REPORT_SHIVA_ENV_VARIABLES_SCENARIOS_AR.md`

## 2) منهجية الـ Deep Search داخل `shiva.py`

- تم حصر جميع استدعاءات `os.getenv("...")` المباشرة: **60 متغير فريد**.
- تم ربط كل متغير بموضع القراءة الأول، مجموعة التشغيل، lifecycle (startup/reloadable/mixed)، والدور الوظيفي.
- تم استخدام `APP_CONFIG_SCHEMA` لاستخراج الـ group والقيم الافتراضية الرسمية وسلوك restart.

## 3) سيناريوهات تشغيلية عامة (If/Else)

- **إذا كانت قيمة المتغير صالحة وقابلة للتحويل** (int/float/bool) => Shiva يطبّقها مباشرة.
- **إذا كانت القيمة غير صالحة** => Shiva يرجع غالبًا إلى fallback/default آمن (مثال: `SPAMD_PORT`, `SPAMD_TIMEOUT`, `SHIVA_PORT`).
- **إذا المتغير Reloadable** => يمكن تعديله من إعدادات runtime (عبر schema/reload) بدون restart كامل.
- **إذا المتغير Startup-only** => يلزم restart حتى يظهر التأثير.
- **إذا المتغير Mixed** => جزء من السلوك startup-only وجزء runtime dynamic (مثال `SHIVA_HOST`).

## 4) المجموعات التشغيلية + كل المتغيرات

### المجموعة: Accounting

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `BRIDGE_BASE_URL` | `` | `str` | Reloadable | `False` | `pmta_chunk_policy@L13635` | إعدادات Bridge |
| `BRIDGE_MODE` | `counts` | `str` | Reloadable | `False` | `pmta_chunk_policy@L13625` | إعدادات Bridge |
| `BRIDGE_POLL_FETCH_OUTCOMES` | `1` | `bool` | Reloadable | `False` | `pmta_chunk_policy@L13652` | إعدادات Bridge |
| `BRIDGE_POLL_INTERVAL_S` | `5` | `float` | Reloadable | `False` | `pmta_chunk_policy@L13647` | إعدادات Bridge |
| `OUTCOMES_SYNC` | `1` | `bool` | Reloadable | `False` | `pmta_chunk_policy@L13650` | مزامنة outcomes |
| `PMTA_BRIDGE_PULL_ENABLED` | `1` | `bool` | Reloadable | `True` | `pmta_chunk_policy@L13624` | سحب بيانات Accounting عبر Bridge |
| `PMTA_BRIDGE_PULL_MAX_LINES` | `2000` | `int` | Reloadable | `False` | `pmta_chunk_policy@L13656` | سحب بيانات Accounting عبر Bridge |
| `PMTA_BRIDGE_PULL_PORT` | `8090` | `int` | Reloadable | `False` | `pmta_chunk_policy@L13629` | سحب بيانات Accounting عبر Bridge |
| `PMTA_BRIDGE_PULL_S` | `5` | `float` | Reloadable | `False` | `pmta_chunk_policy@L13643` | سحب بيانات Accounting عبر Bridge |

### المجموعة: Accounting/Bridge

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `BRIDGE_TIMEOUT_S` | `"20"` | `auto` | Startup-only | `True` | `pmta_chunk_policy@L13637` | إعدادات Bridge |

### المجموعة: App

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `DB_CLEAR_ON_START` | `0` | `bool` | Startup-only | `True` | `_resolve_db_path@L3579` | تنظيف جداول عند الإقلاع |
| `SHIVA_DB_PATH` | `` | `str` | Startup-only | `True` | `_resolve_db_path@L3535` | مسار/تدفق كتابة SQLite |
| `SHIVA_HOST` | `0.0.0.0` | `str` | Mixed (startup + runtime fallback) | `True` | `_resolve_bridge_pull_host_from_campaign@L13718` | Host للتشغيل + fallback للـ bridge host |
| `SHIVA_PORT` | `5001` | `int` | Startup-only | `True` | `start@L20126` | Port تشغيل Flask |
| `SMTP_SENDER_DB_PATH` | `` | `str` | Startup-only | `True` | `_resolve_db_path@L3536` | alias لمسار DB |

### المجموعة: App/DB

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `SHIVA_DB_WRITE_BATCH_SIZE` | `"500"` | `auto` | Startup-only | `True` | `_resolve_db_path@L3556` | مسار/تدفق كتابة SQLite |
| `SHIVA_DB_WRITE_QUEUE_MAX` | `"50000"` | `auto` | Startup-only | `True` | `_resolve_db_path@L3560` | مسار/تدفق كتابة SQLite |

### المجموعة: Backoff

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `SHIVA_BACKOFF_JITTER` | `off` | `str` | Reloadable | `False` | `pmta_health_check@L12827` | سياسة jitter/backoff |
| `SHIVA_BACKOFF_JITTER_DEBUG` | `0` | `bool` | Reloadable | `False` | `pmta_health_check@L12843` | سياسة jitter/backoff |
| `SHIVA_BACKOFF_JITTER_EXPORT` | `0` | `bool` | Reloadable | `False` | `pmta_health_check@L12842` | سياسة jitter/backoff |
| `SHIVA_BACKOFF_JITTER_MAX_S` | `120` | `float` | Reloadable | `False` | `pmta_health_check@L12835` | سياسة jitter/backoff |
| `SHIVA_BACKOFF_JITTER_MIN_S` | `0` | `float` | Reloadable | `False` | `pmta_health_check@L12839` | سياسة jitter/backoff |
| `SHIVA_BACKOFF_JITTER_PCT` | `0.15` | `float` | Reloadable | `False` | `pmta_health_check@L12831` | سياسة jitter/backoff |
| `SHIVA_DISABLE_BACKOFF` | `0` | `bool` | Reloadable | `False` | `pmta_health_check@L12826` | تعطيل backoff |

### المجموعة: DKIM

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `DKIM_SELECTOR` | `""` | `auto` | Startup-only | `True` | `_dkim_selectors_from_env@L11861` | اختيار DKIM selector |
| `DKIM_SELECTORS` | `""` | `auto` | Startup-only | `True` | `_dkim_selectors_from_env@L11862` | اختيار DKIM selector |

### المجموعة: DNS

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `DNS_RESOLVER_NAMESERVERS` | `"1.1.1.1,8.8.8.8,9.9.9.9"` | `auto` | Startup-only | `True` | `(module scope)@L109` | خوادم DNS Resolver |

### المجموعة: DNSBL

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `DBL_ZONES` | `dbl.spamhaus.org` | `str` | Reloadable | `False` | `compute_spam_score@L11346` | فحص DNSBL/DBL |
| `DISABLE_BLACKLIST` | `None` | `auto` | Startup-only | `True` | `compute_spam_score@L11349` | تعطيل/تفعيل blacklist checks |
| `RBL_ZONES` | `zen.spamhaus.org,bl.spamcop.net,cbl.abuseat.org` | `str` | Reloadable | `False` | `compute_spam_score@L11345` | فحص DNSBL/DBL |
| `SHIVA_DISABLE_BLACKLIST` | `0` | `bool` | Reloadable | `False` | `compute_spam_score@L11347` | تعطيل/تفعيل blacklist checks |

### المجموعة: Other

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `DEFAULT_DKIM_SELECTOR` | `""` | `auto` | Startup-only | `True` | `_dkim_selectors_from_env@L11863` | سلوك عام |

### المجموعة: PMTA Backoff

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `PMTA_DETAIL_CACHE_TTL_S` | `3` | `float` | Reloadable | `False` | `pmta_health_check@L12856` | سلوك عام |
| `PMTA_DOMAIN_CHECK_TOP_N` | `2` | `int` | Reloadable | `False` | `pmta_health_check@L12851` | سلوك عام |
| `PMTA_QUEUE_BACKOFF` | `1` | `bool` | Reloadable | `False` | `pmta_health_check@L12824` | سلوك عام |
| `PMTA_QUEUE_REQUIRED` | `0` | `bool` | Reloadable | `False` | `pmta_health_check@L12825` | سلوك عام |

### المجموعة: PMTA Diag

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `PMTA_DIAG_ON_ERROR` | `1` | `bool` | Reloadable | `False` | `pmta_health_check@L12795` | سلوك عام |
| `PMTA_DIAG_RATE_S` | `1.0` | `float` | Reloadable | `False` | `pmta_health_check@L12797` | سلوك عام |

### المجموعة: PMTA Domains

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `PMTA_DOMAINS_POLL_S` | `4` | `float` | Reloadable | `False` | `_env_float@L12891` | سلوك عام |
| `PMTA_DOMAINS_TOP_N` | `6` | `int` | Reloadable | `False` | `_env_float@L12895` | سلوك عام |
| `PMTA_DOMAIN_STATS` | `1` | `bool` | Reloadable | `False` | `_env_float@L12889` | سلوك عام |

### المجموعة: PMTA Live

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `PMTA_LIVE_POLL_S` | `3` | `float` | Reloadable | `False` | `pmta_health_check@L12846` | سلوك عام |
| `PMTA_QUEUE_TOP_N` | `6` | `int` | Reloadable | `False` | `pmta_health_check@L12801` | سلوك عام |

### المجموعة: PMTA Monitor

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `PMTA_HEALTH_REQUIRED` | `1` | `bool` | Reloadable | `False` | `db_find_job_ids_by_recipient@L12114` | سلوك عام |
| `PMTA_MONITOR_API_KEY` | `` | `str` | Reloadable | `False` | `db_find_job_ids_by_recipient@L12113` | مراقبة PMTA health |
| `PMTA_MONITOR_BASE_URL` | `` | `str` | Reloadable | `False` | `db_find_job_ids_by_recipient@L12108` | مراقبة PMTA health |
| `PMTA_MONITOR_SCHEME` | `auto` | `str` | Reloadable | `False` | `db_find_job_ids_by_recipient@L12109` | مراقبة PMTA health |
| `PMTA_MONITOR_TIMEOUT_S` | `3` | `float` | Reloadable | `False` | `db_find_job_ids_by_recipient@L12100` | مراقبة PMTA health |

### المجموعة: PMTA Pressure

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `PMTA_PRESSURE_CONTROL` | `1` | `bool` | Reloadable | `False` | `_env_float@L12883` | سلوك عام |
| `PMTA_PRESSURE_POLL_S` | `3` | `float` | Reloadable | `False` | `_env_float@L12885` | سلوك عام |

### المجموعة: Recipient Filter

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `RECIPIENT_FILTER_ENABLE_ROUTE_CHECK` | `1` | `bool` | Reloadable | `False` | `(module scope)@L152` | فلترة المستلمين قبل الإرسال |
| `RECIPIENT_FILTER_ENABLE_SMTP_PROBE` | `"1"` | `auto` | Startup-only | `True` | `(module scope)@L151` | فلترة المستلمين قبل الإرسال |
| `RECIPIENT_FILTER_ROUTE_THREADS` | `"24"` | `auto` | Startup-only | `True` | `(module scope)@L162` | فلترة المستلمين قبل الإرسال |
| `RECIPIENT_FILTER_SMTP_PROBE_LIMIT` | `"25"` | `auto` | Startup-only | `True` | `(module scope)@L154` | فلترة المستلمين قبل الإرسال |
| `RECIPIENT_FILTER_SMTP_THREADS` | `"8"` | `auto` | Startup-only | `True` | `(module scope)@L167` | فلترة المستلمين قبل الإرسال |
| `RECIPIENT_FILTER_SMTP_TIMEOUT` | `"5"` | `auto` | Startup-only | `True` | `(module scope)@L158` | فلترة المستلمين قبل الإرسال |

### المجموعة: Spam

| المتغير | القيمة الافتراضية | النوع | Lifecycle | Restart مطلوب | أين يُقرأ أول مرة | الفائدة الدقيقة |
|---|---:|---|---|---|---|---|
| `SPAMCHECK_BACKEND` | `spamd` | `str` | Reloadable | `False` | `(module scope)@L71` | فحص SpamAssassin/SpamD |
| `SPAMD_HOST` | `127.0.0.1` | `str` | Reloadable | `False` | `(module scope)@L72` | فحص SpamAssassin/SpamD |
| `SPAMD_PORT` | `783` | `int` | Reloadable | `False` | `(module scope)@L74` | فحص SpamAssassin/SpamD |
| `SPAMD_TIMEOUT` | `5` | `float` | Reloadable | `False` | `(module scope)@L78` | فحص SpamAssassin/SpamD |

## 5) سيناريوهات تفصيلية حسب مجموعات رئيسية

### A) Spam & Spamd
- إذا `SPAMCHECK_BACKEND=off` => تعطيل مسار spam scoring (سرعة أعلى/فلترة أقل).
- إذا `SPAMCHECK_BACKEND=spamd` و`SPAMD_HOST/PORT` صحيحة => scoring فعال.
- إذا `SPAMD_TIMEOUT` منخفض جدًا => timeouts متكررة؛ إذا عالي جدًا => زيادة latency.

### B) Recipient Filter
- إذا `RECIPIENT_FILTER_ENABLE_SMTP_PROBE=1` => يتم probe قبل الإرسال مع استخدام `RECIPIENT_FILTER_SMTP_TIMEOUT/LIMIT/THREADS`.
- إذا `RECIPIENT_FILTER_ENABLE_SMTP_PROBE=0` => إلغاء probe والاكتفاء بالتحقق الأساسي (أسرع لكن مخاطرة bounce أعلى).
- إذا `RECIPIENT_FILTER_ENABLE_ROUTE_CHECK=0` => تعطيل route/MX checks.

### C) PMTA Health/Backoff
- إذا `PMTA_HEALTH_REQUIRED=1` وفشل monitor => يمكن منع/إبطاء الإرسال بحسب بقية الضوابط.
- إذا `SHIVA_DISABLE_BACKOFF=1` => تجاوز backoff safeguards.
- إذا `SHIVA_BACKOFF_JITTER=off|deterministic|random` => تغيير طريقة jitter؛ القيم غير المعروفة تُعاد إلى `off`.

### D) Accounting Bridge
- إذا `PMTA_BRIDGE_PULL_ENABLED=1` => poller يسحب بيانات accounting دوريًا.
- إذا `BRIDGE_BASE_URL` فارغ => Shiva يحاول توليد URL تلقائيًا عبر host/port.
- إذا `BRIDGE_POLL_FETCH_OUTCOMES=0` أو `OUTCOMES_SYNC=0` => تقليل/إيقاف مزامنة outcomes.

### E) DB/App
- إذا `SHIVA_DB_PATH` مضبوط وصالح => جميع عمليات SQLite تذهب لهذا الملف.
- إذا `SHIVA_DB_PATH` فارغ و`SMTP_SENDER_DB_PATH` موجود => يُستخدم كمسار بديل.
- إذا `DB_CLEAR_ON_START=1` => تنظيف جداول عند الإقلاع (خطر فقدان بيانات).
- إذا `SHIVA_DB_WRITE_BATCH_SIZE` أكبر => throughput أعلى لكن معاملات أكبر/أبطأ في الـ commit.

## 6) أهم الدوال التي تستهلك المتغيرات مباشرة أو عبر إعادة التحميل

- تعريفات module-scope المبكرة (Spam + Recipient filter + DNS).
- `_resolve_db_path()` لمسار DB وbatch/queue.
- `_dkim_selectors_from_env()` لسلاسل DKIM selectors.
- `pmta_health_check()` لضبط PMTA/backoff/live poll/pressure knobs.
- `pmta_chunk_policy()` لضبط bridge/accounting envs.
- `reload_runtime_config()` لتطبيق المتغيرات reloadable أثناء التشغيل.
- `start()` لالتقاط `SHIVA_HOST` و`SHIVA_PORT` عند تشغيل Flask.

## 7) توصيات تشغيلية نهائية
- ثبّت القيم الحساسة في ملف env واضح + versioned runbook.
- افصل بين متغيرات Startup-only وReloadable لتجنب تغييرات لا تظهر إلا بعد restart.
- راقب Bridge/PMTA metrics بعد أي تعديل على polling/backoff/timeout.
- لا تفعّل `DB_CLEAR_ON_START` في production إلا ضمن نافذة صيانة واعية.
