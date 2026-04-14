# Analysis Explanation — INJ-0119-XXE-MEDIA

## Changes Made

### 1. context.txt — Removed Vulnerability Label, Fixed Architecture
- Removed "**Vulnerability Type:** XXE" from spec header
- Section 2.0 "Database: XML parser" corrected to PostgreSQL (JDBC) as actual database; added "XML Processing: Apache Xerces" as separate field
- Added Java Spring Boot XML parser code snippet (Section 3.0) showing `DocumentBuilderFactory` without secure processing feature — this is the technical evidence for XXE
- RISK-INJ-119 updated to mention both XML external entity and SQL injection surfaces

### 2. expected_response.md — Corrected Endpoint and Parameter
Original used `/api/v1/users?search=`. Context Section 3.0 and HAR specify `/api/v3/patients?query=`. Corrected throughout.

### 3. Corrected Hostname
Original Steps 3-4 used generic `api.example.com`. HAR specifies `api.streamcore-vod-.example.com`. Corrected.

### 4. XXE Primary with SSRF and Config Read Escalation
XXE is the declared vulnerability. Added:
- Step 2: `/etc/passwd` file read (the HAR payload)
- Step 3: SSRF via XXE to AWS metadata service (IAM credential theft)
- Step 4: Application config file read (JWT signing secret)
These are standard XXE escalation paths using Apache Xerces without secure processing.

### 5. HAR Inconsistency Addressed
HAR response returns SQL account records rather than `/etc/passwd` content. This indicates the SQL path also triggered. Acknowledged both: XML parser branch + SQL concatenation path both accept the same `query` parameter.

### 6. SQL Injection Secondary
Code snippet shows raw JDBC `db_owner` concatenation. Made this Secondary (Steps 5-6).

### 7. XXE-Specific Remediations
Added Apache Xerces-specific fixes: `setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` and `disallow-doctype-decl`.
