# Variables d’environnement (référence en français)

Ce document résume **toutes les variables d’environnement détectées** dans le projet (`shiva_app.py` + `pmta_accounting_bridge.py`) avec leur rôle et un exemple simple.

> Format des exemples: à placer dans votre shell ou fichier `.env` selon votre mode de déploiement.

## 1) Anti-spam / SpamAssassin

- `SPAMCHECK_BACKEND` (défaut: `spamd`)  
  Définit le backend de vérification spam utilisé par l’application.  
  Exemple: `SPAMCHECK_BACKEND=spamd`

- `SPAMD_HOST` (défaut: `127.0.0.1`)  
  Adresse du serveur `spamd`.  
  Exemple: `SPAMD_HOST=127.0.0.1`

- `SPAMD_PORT` (défaut: `783`)  
  Port du serveur `spamd`.  
  Exemple: `SPAMD_PORT=783`

- `SPAMD_TIMEOUT` (défaut: `5`)  
  Timeout (secondes) pour les appels vers `spamd`.  
  Exemple: `SPAMD_TIMEOUT=5`

## 2) Filtrage destinataires (SMTP probe)

- `RECIPIENT_FILTER_ENABLE_SMTP_PROBE` (défaut: `1`)  
  Active/désactive la vérification SMTP (RCPT) avant envoi.  
  Exemple: `RECIPIENT_FILTER_ENABLE_SMTP_PROBE=1`

- `RECIPIENT_FILTER_SMTP_PROBE_LIMIT` (défaut: `25`)  
  Nombre max d’adresses testées par probe SMTP.  
  Exemple: `RECIPIENT_FILTER_SMTP_PROBE_LIMIT=50`

- `RECIPIENT_FILTER_SMTP_TIMEOUT` (défaut: `5`)  
  Timeout (secondes) pour la vérification SMTP des destinataires.  
  Exemple: `RECIPIENT_FILTER_SMTP_TIMEOUT=8`

## 3) DNSBL / DBL

- `RBL_ZONES` (défaut: `zen.spamhaus.org,bl.spamcop.net,cbl.abuseat.org`)  
  Liste des zones RBL (IP blacklist) séparées par virgule.  
  Exemple: `RBL_ZONES=zen.spamhaus.org,bl.spamcop.net`

- `DBL_ZONES` (défaut: `dbl.spamhaus.org`)  
  Liste des zones DBL (domain blacklist).  
  Exemple: `DBL_ZONES=dbl.spamhaus.org`

- `SEND_DNSBL` (défaut: `1`)  
  Active la vérification DNSBL/DBL avant envoi.  
  Exemple: `SEND_DNSBL=0`

## 4) PMTA Monitor / Santé

- `PMTA_MONITOR_TIMEOUT_S` (défaut: `3`)  
  Timeout des appels HTTP au monitor PMTA (secondes).  
  Exemple: `PMTA_MONITOR_TIMEOUT_S=4`

- `PMTA_MONITOR_SCHEME` (défaut: `auto`)  
  Schéma (`http`, `https` ou `auto`) pour construire l’URL PMTA monitor.  
  Exemple: `PMTA_MONITOR_SCHEME=https`

- `PMTA_MONITOR_BASE_URL` (défaut: vide)  
  URL complète du monitor PMTA (si fournie, priorité à cette URL).  
  Exemple: `PMTA_MONITOR_BASE_URL=http://127.0.0.1:8080`

- `PMTA_MONITOR_API_KEY` (défaut: vide)  
  Clé API pour authentifier les requêtes monitor PMTA (si activé côté PMTA).  
  Exemple: `PMTA_MONITOR_API_KEY=ma_cle_api`

- `PMTA_HEALTH_REQUIRED` (défaut: `1`)  
  Si `1`, l’app exige un état PMTA sain avant certaines opérations d’envoi.  
  Exemple: `PMTA_HEALTH_REQUIRED=1`

- `PMTA_MAX_SPOOL_RECIPIENTS` (défaut: `200000`)  
  Seuil max de recipients dans spool avant alerte santé.  
  Exemple: `PMTA_MAX_SPOOL_RECIPIENTS=150000`

- `PMTA_MAX_SPOOL_MESSAGES` (défaut: `50000`)  
  Seuil max de messages en spool avant alerte.  
  Exemple: `PMTA_MAX_SPOOL_MESSAGES=40000`

- `PMTA_MAX_QUEUED_RECIPIENTS` (défaut: `250000`)  
  Seuil max de recipients en queue avant alerte.  
  Exemple: `PMTA_MAX_QUEUED_RECIPIENTS=200000`

- `PMTA_MAX_QUEUED_MESSAGES` (défaut: `60000`)  
  Seuil max de messages en queue avant alerte.  
  Exemple: `PMTA_MAX_QUEUED_MESSAGES=50000`

## 5) Backoff / Retry

- `ENABLE_BACKOFF` (défaut: `1`)  
  Active la logique de backoff (ralentissement/retry intelligent).  
  Exemple: `ENABLE_BACKOFF=1`

- `ENABLE_BACCKOFF` (alias historique, faute de frappe)  
  Alias de compatibilité lu si `ENABLE_BACKOFF` est absent.  
  Exemple: `ENABLE_BACCKOFF=1`

- `BACKOFF_MAX_RETRIES` (défaut: `3`)  
  Nombre max de tentatives de retry.  
  Exemple: `BACKOFF_MAX_RETRIES=5`

- `BACKOFF_BASE_S` (défaut: `60`)  
  Délai de base du backoff en secondes.  
  Exemple: `BACKOFF_BASE_S=30`

- `BACKOFF_MAX_S` (défaut: `1800`)  
  Délai maximum du backoff en secondes.  
  Exemple: `BACKOFF_MAX_S=1200`

## 6) PMTA diagnostics / file d’attente / pression

- `PMTA_DIAG_ON_ERROR` (défaut: `1`)  
  Active les diagnostics PMTA automatiques en cas d’erreur.  
  Exemple: `PMTA_DIAG_ON_ERROR=1`

- `PMTA_DIAG_RATE_S` (défaut: `1.0`)  
  Cadence minimale entre diagnostics (secondes).  
  Exemple: `PMTA_DIAG_RATE_S=2`

- `PMTA_QUEUE_TOP_N` (défaut: `6`)  
  Nombre d’éléments top N à afficher/analyser dans la queue PMTA.  
  Exemple: `PMTA_QUEUE_TOP_N=10`

- `PMTA_QUEUE_BACKOFF` (défaut: `1`)  
  Utilise les stats queue PMTA pour déclencher le backoff.  
  Exemple: `PMTA_QUEUE_BACKOFF=1`

- `PMTA_QUEUE_REQUIRED` (défaut: `0`)  
  Rend l’info queue obligatoire pour certaines décisions.  
  Exemple: `PMTA_QUEUE_REQUIRED=0`

- `PMTA_LIVE_POLL_S` (défaut: `3`)  
  Intervalle de polling live PMTA (secondes).  
  Exemple: `PMTA_LIVE_POLL_S=5`

- `PMTA_DOMAIN_CHECK_TOP_N` (défaut: `2`)  
  Nombre de domaines top à contrôler pour décisions backoff.  
  Exemple: `PMTA_DOMAIN_CHECK_TOP_N=3`

- `PMTA_DETAIL_CACHE_TTL_S` (défaut: `3`)  
  TTL du cache détail PMTA (secondes).  
  Exemple: `PMTA_DETAIL_CACHE_TTL_S=10`

- `PMTA_DOMAIN_DEFERRALS_BACKOFF` (défaut: `80`)  
  Seuil de deferrals domaine pour passer en mode backoff.  
  Exemple: `PMTA_DOMAIN_DEFERRALS_BACKOFF=100`

- `PMTA_DOMAIN_ERRORS_BACKOFF` (défaut: `6`)  
  Seuil d’erreurs domaine pour backoff.  
  Exemple: `PMTA_DOMAIN_ERRORS_BACKOFF=8`

- `PMTA_DOMAIN_DEFERRALS_SLOW` (défaut: `25`)  
  Seuil de deferrals pour passer en mode “slow”.  
  Exemple: `PMTA_DOMAIN_DEFERRALS_SLOW=30`

- `PMTA_DOMAIN_ERRORS_SLOW` (défaut: `3`)  
  Seuil d’erreurs domaine pour mode “slow”.  
  Exemple: `PMTA_DOMAIN_ERRORS_SLOW=5`

- `PMTA_SLOW_DELAY_S` (défaut: `0.35`)  
  Délai entre envois en mode lent.  
  Exemple: `PMTA_SLOW_DELAY_S=0.5`

- `PMTA_SLOW_WORKERS_MAX` (défaut: `3`)  
  Nombre max de workers en mode lent.  
  Exemple: `PMTA_SLOW_WORKERS_MAX=2`

- `PMTA_PRESSURE_CONTROL` (défaut: `1`)  
  Active le contrôle de pression (throttling adaptatif).  
  Exemple: `PMTA_PRESSURE_CONTROL=1`

- `PMTA_PRESSURE_POLL_S` (défaut: `3`)  
  Intervalle de polling pour calcul pression.  
  Exemple: `PMTA_PRESSURE_POLL_S=4`

- `PMTA_DOMAIN_STATS` (défaut: `1`)  
  Active la collecte des statistiques par domaine.  
  Exemple: `PMTA_DOMAIN_STATS=1`

- `PMTA_DOMAINS_POLL_S` (défaut: `4`)  
  Intervalle de polling des stats domaines.  
  Exemple: `PMTA_DOMAINS_POLL_S=6`

- `PMTA_DOMAINS_TOP_N` (défaut: `6`)  
  Nombre de domaines affichés dans le snapshot.  
  Exemple: `PMTA_DOMAINS_TOP_N=12`

## 7) IA (OpenRouter)

- `OPENROUTER_ENDPOINT` (défaut: `https://openrouter.ai/api/v1/chat/completions`)  
  Endpoint HTTP utilisé pour la réécriture IA.  
  Exemple: `OPENROUTER_ENDPOINT=https://openrouter.ai/api/v1/chat/completions`

- `OPENROUTER_MODEL` (défaut: `arcee-ai/trinity-large-preview:free`)  
  Modèle utilisé pour les fonctions IA.  
  Exemple: `OPENROUTER_MODEL=openai/gpt-4o-mini`

- `OPENROUTER_TIMEOUT_S` (défaut: `40`)  
  Timeout d’appel OpenRouter (secondes).  
  Exemple: `OPENROUTER_TIMEOUT_S=30`

## 8) Flux accounting (Shiva ⇄ Bridge)

- `PMTA_BRIDGE_PULL_ENABLED` (défaut: `1`)  
  Active le mode pull: Shiva récupère les lignes accounting depuis le bridge API.  
  Exemple: `PMTA_BRIDGE_PULL_ENABLED=1`

- `PMTA_BRIDGE_PULL_URL` (défaut: vide)  
  URL complète de pull (ex. `/api/v1/pull/latest?kind=acct`).  
  Exemple: `PMTA_BRIDGE_PULL_URL=http://127.0.0.1:8090/api/v1/pull/latest?kind=acct`

- `PMTA_BRIDGE_PULL_TOKEN` (défaut: vide)  
  Token Bearer envoyé par Shiva vers le bridge.  
  Exemple: `PMTA_BRIDGE_PULL_TOKEN=token_secret`

- `PMTA_BRIDGE_PULL_S` (défaut: `5`)  
  Intervalle de pull Shiva (secondes).  
  Exemple: `PMTA_BRIDGE_PULL_S=3`

- `PMTA_BRIDGE_PULL_MAX_LINES` (défaut: `2000`)  
  Nombre max de lignes demandées à chaque pull.  
  Exemple: `PMTA_BRIDGE_PULL_MAX_LINES=5000`

## 9) Bridge API (processus `pmta_accounting_bridge.py`)

- `PMTA_LOG_DIR` (défaut: `/var/log/pmta`)  
  Dossier des logs PMTA lus par le bridge.  
  Exemple: `PMTA_LOG_DIR=/var/log/pmta`

- `ALLOW_NO_AUTH` (défaut: `0`)  
  Si `1`, le bridge accepte des appels sans authentification (non recommandé en production).  
  Exemple: `ALLOW_NO_AUTH=0`

- `DEFAULT_PUSH_MAX_LINES` (défaut: `5000`)  
  Limite de lignes envoyées si l’API push ne reçoit pas de `max_lines`.  
  Exemple: `DEFAULT_PUSH_MAX_LINES=3000`

- `CORS_ORIGINS` (défaut: `*`)  
  Origines CORS autorisées.  
  Exemple: `CORS_ORIGINS=https://app.exemple.com,https://admin.exemple.com`

- `BIND_ADDR` (défaut: `0.0.0.0`)  
  Adresse d’écoute du serveur bridge.  
  Exemple: `BIND_ADDR=127.0.0.1`

- `PORT` (défaut: `8090`)  
  Port d’écoute du bridge API.  
  Exemple: `PORT=8090`

## 10) Application Shiva (serveur web)

- `SHIVA_HOST` (défaut: `0.0.0.0`)  
  Adresse d’écoute HTTP de l’application Shiva.  
  Exemple: `SHIVA_HOST=0.0.0.0`

- `SHIVA_PORT` (défaut: `5001`)  
  Port d’écoute HTTP de l’application Shiva.  
  Exemple: `SHIVA_PORT=5001`

- `DB_CLEAR_ON_START` (défaut: `0`)  
  Si `1`, efface les tables SQLite au démarrage (dangereux).  
  Exemple: `DB_CLEAR_ON_START=0`

---

## Exemple minimal `.env`

```env
SHIVA_HOST=0.0.0.0
SHIVA_PORT=5001
PMTA_MONITOR_BASE_URL=http://127.0.0.1:8080
PMTA_MONITOR_SCHEME=auto
PMTA_MONITOR_TIMEOUT_S=3
PMTA_HEALTH_REQUIRED=1

ENABLE_BACKOFF=1
BACKOFF_MAX_RETRIES=3
BACKOFF_BASE_S=60
BACKOFF_MAX_S=1800

PMTA_BRIDGE_PULL_ENABLED=1
PMTA_BRIDGE_PULL_URL=http://127.0.0.1:8090/api/v1/pull/latest?kind=acct
PMTA_BRIDGE_PULL_TOKEN=change_me
PMTA_BRIDGE_PULL_S=5
PMTA_BRIDGE_PULL_MAX_LINES=2000
```

