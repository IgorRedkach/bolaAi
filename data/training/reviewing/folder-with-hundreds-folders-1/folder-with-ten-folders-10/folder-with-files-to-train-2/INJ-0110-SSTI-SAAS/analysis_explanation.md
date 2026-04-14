# Analysis Explanation — INJ-0110-SSTI-SAAS

## What was wrong

### 1. Wrong endpoint, parameter, and table throughout

Original response used `/api/v1/users?search=`. Section 3.0 and HAR both specify `/api/v2/orders?username=`. Fixed all steps. Table is `orders`, not `users`.

### 2. Generic host URL in Steps 3/4

Steps 3 and 4 used `api.example.com`. Fixed to `api.taskflow-collab.example.com`.

### 3. SSTI mechanics not demonstrated

Original Step 2 described SSTI as "evaluates to true for all rows" — a SQLi description. SSTI requires demonstrating template expression evaluation (`{{7*7}}` → `49`), config dump (`{{config}}`), and RCE via subclass traversal. Added Steps 3 and 4.

### 4. Context inconsistency acknowledged

Section 2.0 declares Jinja2/Nunjucks SSTI but Section 3.0 shows SQL concatenation. HAR response shows SQL-structured data. Both vectors demonstrated.

### 5. SSTI-specific remediation added

Original remediation was generic "parameterized queries" (SQLi only). Added Jinja2 sandbox, template input isolation.

## Domain context

TaskFlow is a SaaS / Project Management platform. `orders` table represents project task orders or work orders. Admin credential exposure enables full platform takeover and access to all customer project data. SSTI RCE on a SaaS platform compromises not just one customer's data but potentially the entire multi-tenant infrastructure.
