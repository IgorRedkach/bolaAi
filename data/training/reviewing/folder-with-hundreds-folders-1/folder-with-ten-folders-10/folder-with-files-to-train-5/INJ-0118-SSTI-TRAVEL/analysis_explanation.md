# Analysis Explanation — INJ-0118-SSTI-TRAVEL

## Changes Made

### 1. context.txt — Removed Vulnerability Label
- Removed "**Vulnerability Type:** SSTI" from spec header
- Section 2.0 "Database" corrected from "Jinja2/Nunjucks template engine — primary data store" to PostgreSQL (actual database) + separate "Template Engine" field
- Added Nunjucks `renderString` code snippet to show the template injection surface (previously absent)
- RISK-INJ-118 updated to mention both template and SQL injection surfaces

### 2. expected_response.md — Corrected Endpoint and Parameter
Original used `/api/v1/users?search=`. Context Section 3.0 and HAR specify `/api/v2/accounts?filter=`. Corrected throughout.

### 3. Corrected Hostname
Original Step 3-4 used generic `api.example.com`. HAR specifies `api.skyport-global-.example.com`. Corrected.

### 4. SSTI Primary with Nunjucks/Jinja2 Escalation
SSTI is the declared vulnerability. Added Nunjucks environment variable dump (Step 2), Nunjucks RCE via constructor chain (Step 3), and Jinja2 RCE (Step 4). The HAR payload `{{7*7}}` confirms the SSTI probe matches the declared vulnerability.

### 5. HAR Inconsistency Addressed
HAR response returns SQL account records rather than template-evaluated output. This indicates the filter flows into both SQL concatenation and template rendering. Both paths documented as dual injection surfaces in the same endpoint.

### 6. SQL Injection Secondary
Code snippet shows raw SQL concatenation. Made this Secondary (Steps 5-7) after SSTI primary. Added UNION SELECT and verbose error steps based on `db_owner` context.

### 7. SSTI-Specific Remediations
Replaced generic SQL remediations with SSTI-specific ones (template escaping, metacharacter rejection) alongside SQL remediation.
