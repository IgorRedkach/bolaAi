# Analysis Explanation — INJ-0113-SQLi-LOGISTICS

## Changes Made

### 1. Corrected Endpoint and Parameter
Original `expected_response.md` used `/api/v1/users?search=`. Context.txt Section 3.0 specifies `GET /api/v1/products?tag=` and code snippet confirms `SELECT * FROM products WHERE tag = '${req.query.tag}'`. HAR confirms URL `api.freightlens-tra.example.com/api/v1/products?tag=`. Corrected throughout.

### 2. Corrected Table Name
Original used `users` table in UNION SELECT. Context code snippet uses `products` as the target table. Corrected the DDL step to `DROP TABLE products`.

### 3. Fixed Generic Hostname
Steps 3-4 in original used `api.example.com`. All curl commands now use `api.freightlens-tra.example.com` from HAR.

### 4. Removed Conditional Qualifier on db_owner Step
Original Step 3 used "if DB over-privileged" qualifier. Section 6.0 explicitly documents `db_owner` as a known misconfiguration. Removed conditional qualifier.

### 5. Added DDL Attack Step
`db_owner` privilege enables `DROP TABLE`. Added Step 4 demonstrating `DROP TABLE products` — directly relevant to Logistics/Supply Chain domain where losing `products` table destroys shipment tracking capability (operational sabotage).

### 6. Clarified HAR Tautology
Corrected description of the SQL query evaluation from "evaluates to true for all rows when the payload is `http://...`" (SSRF description from template) to the correct tautology injection description: `'' OR 1=1 --` makes the WHERE clause always true.
