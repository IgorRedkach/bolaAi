# Analysis Explanation — INJ-0117-ORMi-REAL-ESTAT

## Changes Made

### 1. Corrected Endpoint, Parameter, API Version, and Table
Original used `/api/v1/users?search=` with table `users`. Context Section 3.0 specifies `GET /api/v2/claims?filter=` with code `SELECT * FROM claims WHERE filter = '...'`. HAR confirms `api.estateflow-prop.example.com/api/v2/claims?filter=`. Corrected throughout:
- API version: v1 → v2
- Endpoint: `/users` → `/claims`
- Parameter: `search` → `filter`
- Table: `users` → `claims`

### 2. Fixed Generic Hostname
Steps 3-4 used `api.example.com`. All curl commands now use `api.estateflow-prop.example.com` from HAR.

### 3. Removed Conditional Qualifier from db_owner Step
Original Step 3 used "if DB over-privileged" qualifier. Section 6.0 explicitly documents `db_owner`. Removed qualifier.

### 4. Made DDL Primary, Added ORM-Specific Context
The HAR payload `1; DROP TABLE claims--` is a stacked DDL injection. The primary impact is destruction of the `claims` table — all real estate property transaction records. Emphasized this as the primary attack since it represents the most severe impact (irreversible data loss, regulatory recordkeeping violation in Real Estate/PropTech).

### 5. Added ORM-Specific Remediation
Replaced generic SQL remediations with ORM-specific fixes: Hibernate named parameters, Sequelize `replacements`/`bind` options, audit of `sequelize.query()` and `createNativeQuery()` calls.

### 6. Added Tautology Injection Step
Added Step 4 demonstrating `OR 1=1` tautology to enumerate all claims (full property database exposure), complementing the DDL attack.
