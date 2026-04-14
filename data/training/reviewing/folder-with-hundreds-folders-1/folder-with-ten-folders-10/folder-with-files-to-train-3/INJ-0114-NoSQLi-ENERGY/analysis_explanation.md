# Analysis Explanation — INJ-0114-NoSQLi-ENERGY

## Changes Made

### 1. Corrected Endpoint, Parameter, and API Version
Original `expected_response.md` used `/api/v1/users?search=`. Context.txt Section 3.0 specifies `GET /api/v2/orders?category=` and code snippet confirms `SELECT * FROM orders WHERE category = '${req.query.category}'`. HAR confirms URL `api.powergrid-custo.example.com/api/v2/orders?category=`. Corrected throughout, including API version v2 (not v1).

### 2. Fixed Generic Hostname
Steps 3-4 in original used `api.example.com`. All curl commands now use `api.powergrid-custo.example.com` from HAR.

### 3. Addressed Internal Inconsistency (NoSQLi declared vs. SQL code)
Context has a conflict: Section 2.0 declares MongoDB/document store; Section 3.0 shows SQL string concatenation. The payload (`{ "$gt": "" }`) is a MongoDB operator injection. Acknowledged the inconsistency in the finding note, and made the primary demonstration NoSQLi (declared vulnerability) while noting SQL as a secondary code-path debt.

### 4. Replaced SQLi Escalation with NoSQLi-Specific Attacks
Original Step 3 showed SQLi `UNION SELECT load_file('/etc/passwd')` — completely wrong for MongoDB NoSQLi. Replaced with:
- `$ne` operator injection (Step 3): another common NoSQLi bypass
- `$where` JavaScript injection (Step 4): escalation path if `$where` is enabled in MongoDB, enables server-side arbitrary JS

### 5. Corrected Description of `$gt` Injection Mechanism
Original: "The query `SELECT * FROM users WHERE search = '{ "$gt": "" }'` evaluates to true for all rows" — this is incorrect (SQL tautology description, wrong for this vulnerability). Corrected: MongoDB `$gt: ""` makes `category > ""` true for all non-empty strings, returning all documents.

### 6. Added NoSQLi-Specific Remediations
Replaced generic SQL remediations with MongoDB-specific fixes: input type enforcement, typed query building, disabling `$where`, blocking `$` operator characters in input validation.

### 7. Removed Conditional Qualifier on db_owner Step
Original Step 3 used "if DB over-privileged" qualifier. Section 6.0 explicitly documents `db_owner` as a known misconfiguration. The `$where` escalation note covers the equivalent MongoDB privilege escalation path.
