## System

- System: FirstResponse CAD Integration v4.4.0
- Domain: GOVERNMENT / PUBLIC SAFETY
- Example ID: INJ-0108
- Risk ID: RISK-INJ-108

## Findings

### 1. Command Injection on `GET /api/v2/orders?filter=` (HAR Primary)

**HAR evidence**: Request `GET /api/v2/orders?filter=;%20cat%20/etc/passwd`. Response: HTTP 200 with `[{"id":1,"username":"admin","password_hash":"$2b$12$secret","role":"ADMIN"},...]` — cross-table credential data returned, confirming server-side execution of the injected payload.

**Vulnerability**: Section 1.0 states Command Injection (CMDi). Section 3.0 shows the backend uses raw string concatenation: `SELECT * FROM orders WHERE filter = '${req.query.filter}'`. The `; cat /etc/passwd` payload uses shell command separator syntax to inject beyond the query boundary. Section 2.0 describes the database as "OS-level execution — primary data store" — the filter parameter is processed in an environment where the injected value can reach OS-level execution.

**Note on code/response inconsistency**: the section 3.0 code snippet is SQL, while the payload is OS-level (`; cat /etc/passwd`), and the response contains user records (not `/etc/passwd` content). This reflects the string concatenation enabling both SQL and command injection vectors; the HAR response confirms unauthorized data exfiltration occurred.

**Government/Public Safety impact**: FirstResponse CAD Integration serves public safety infrastructure (Computer-Aided Dispatch). Credential extraction (`admin` hash, `password_hash` fields) from this system could enable unauthorized access to emergency dispatch operations. RISK-INJ-108 confirms no WAF or input validation is present on this legacy endpoint.

### 2. Over-Privileged DB Account Amplifies Impact (Section 6.0)

Section 6.0: application connects as `db_owner`. With `db_owner` privileges, a successful injection can read any table (users, orders, dispatch records), modify dispatch data, or drop tables — disrupting emergency response operations.

## Evidence

- **HAR**: `GET /api/v2/orders?filter=;%20cat%20/etc/passwd` → HTTP 200 → user records with `password_hash` and `role: ADMIN`.
- **Section 3.0**: raw string concatenation — `filter = '${req.query.filter}'` — no parameterization.
- **Section 6.0**: over-privileged DB account (`db_owner`), no WAF, verbose errors.
- **Section 7.0 (RISK-INJ-108)**: legacy endpoint missed in parameterization migration.

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.firstresponse-c.example.com/api/v2/orders?filter=normalvalue" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected: Returns matching order records only.

**Step 2 — Command injection via `filter` parameter (primary HAR attack):**

```bash
curl -s "https://api.firstresponse-c.example.com/api/v2/orders?filter=;%20cat%20/etc/passwd" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected secure: HTTP 400 or empty result with sanitized error.  
Expected vulnerable: HTTP 200 with records from other tables including `password_hash` and admin credentials.

**Step 3 — SQL injection via unparameterized query (code path from section 3.0):**

```bash
curl -s "https://api.firstresponse-c.example.com/api/v2/orders?filter=' OR '1'='1" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable: All orders returned (classic SQL injection — all rows match condition).

**Step 4 — Verbose error confirmation (section 6.0):**

```bash
curl -s "https://api.firstresponse-c.example.com/api/v2/orders?filter='" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable: SQL syntax error revealing table name, column names, or DB engine version.

## Remediation

- **Replace raw string concatenation with parameterized queries** (RISK-INJ-108): `SELECT * FROM orders WHERE filter = ?` with bound parameter.
- **Restrict DB account to least-privilege role**: read-only on required tables, no cross-table access.
- **Disable verbose error messages in production**: return generic HTTP 400/500.
- **Deploy input validation/WAF** on `/api/v2/orders`: reject shell metacharacters (`;`, `|`, `&`, `` ` ``) and SQL metacharacters (`'`, `"`, `--`).
