# Analysis Explanation — INJ-0134-SSTI-B2B-SAAS

## What was wrong

### 1. Wrong API version throughout

Original response used `/api/v1/users`. Section 3.0 and HAR both specify `/api/v3/users`. Fixed.

### 2. Generic host URL in Steps 3/4

Steps 3 and 4 used `api.example.com`. Fixed to `api.pipelinepro-sal.example.com`.

### 3. SSTI mechanics not demonstrated — only SQL-like "all rows returned" shown

SSTI is fundamentally different from SQLi. The original response described SSTI as "evaluates to true for all rows" — this is a SQLi description, not SSTI. SSTI works by injecting template expressions (`{{7*7}}`) that the template engine evaluates. Proper SSTI testing requires:
1. Arithmetic probe: `{{7*7}}` → `49` confirms template execution (added as Step 2 check)
2. Config dump: `{{config}}` to extract secret keys and DB connection strings (added Step 3)
3. RCE via subclass traversal: Python Jinja2 `__subclasses__` path to OS command execution (added Step 4)

Without these escalation steps, the example does not teach SSTI — only a generic injection.

### 4. Context inconsistency acknowledged

Section 2.0 declares Jinja2/Nunjucks template engine as the "primary data store" (SSTI vector), but Section 3.0 shows raw SQL concatenation (SQLi vector). The HAR response contains SQL-structured data. Both vectors are demonstrated because the context documents both risks and `db_owner` privileges make SQLi particularly severe.

### 5. SSTI remediation added

Original remediation was generic "parameterized queries" (SQLi fix only). Added Jinja2-specific fixes: sandbox environment, never rendering user input as template source. Both SQLi and SSTI remediations included.

## Domain context

PipelinePro is a B2B SaaS / CRM platform. `users` contains sales rep accounts, customer contacts, and admin credentials. SSTI RCE would allow full server compromise and mass customer pipeline data exfiltration. Config dump via `{{config}}` in Jinja2 exposes all API keys and database credentials stored as environment variables — enabling lateral movement across the SaaS infrastructure.
