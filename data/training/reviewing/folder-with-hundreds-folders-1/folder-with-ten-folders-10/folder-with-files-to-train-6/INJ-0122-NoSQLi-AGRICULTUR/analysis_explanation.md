# Analysis Explanation — INJ-0122-NoSQLi-AGRICULTUR

## Changes Made

### 1. context.txt — Removed Vulnerability Label, Fixed Architecture, Added MongoDB Snippet
- Removed "**Vulnerability Type:** NoSQL Injection" from spec header
- Section 2.0 updated to reflect MongoDB as the primary database
- Added MongoDB `find()` code snippet showing `JSON.parse()` without operator sanitization (the NoSQLi surface)
- Legacy SQL path added as secondary code snippet to explain HAR response showing SQL-structured data
- RISK-INJ-122 updated to describe MongoDB operator injection and legacy SQL path

### 2. expected_response.md — Corrected Endpoint and Parameter
Original used `/api/v1/users?search=`. Context Section 3.0 and HAR specify `/api/v3/products?username=`. Corrected throughout.

### 3. Corrected Hostname
Original Steps 3-4 used generic `api.example.com`. HAR specifies `api.harvestiq-iot-p.example.com`. Corrected.

### 4. NoSQL Injection Primary with MongoDB Operators
Added MongoDB-specific operator escalation:
- `$gt: ""` — dump all records (HAR payload)
- `$ne: null` — full collection dump
- `$regex: "^admin"` — admin enumeration
- `$where: "this.role=='ADMIN'"` — server-side JavaScript execution

### 5. HAR Inconsistency Addressed
HAR response shows SQL-structured records despite NoSQL database. Acknowledged: legacy SQL path active on same endpoint. SQL path added as Finding 2.

### 6. NoSQL-Specific Remediations
Added `$`-key stripping, JSON.parse rejection, and Joi/Zod schema validation as NoSQLi-specific remediations.
