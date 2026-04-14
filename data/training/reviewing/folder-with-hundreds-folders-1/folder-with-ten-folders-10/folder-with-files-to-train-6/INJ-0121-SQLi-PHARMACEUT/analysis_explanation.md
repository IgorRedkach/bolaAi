# Analysis Explanation — INJ-0121-SQLi-PHARMACEUT

## Changes Made

### 1. context.txt — Removed Vulnerability Label
Removed "**Vulnerability Type:** SQL Injection" from spec header. All other content consistent.

### 2. expected_response.md — Corrected Endpoint and Parameter
Original used `/api/v1/users?search=`. Context Section 3.0 and HAR specify `/api/v3/patients?search=`. Corrected. Table corrected from `users` to `patients`.

### 3. Corrected Hostname
Original Steps 3-4 used generic `api.example.com`. HAR specifies `api.trialvault-clin.example.com`. Corrected.

### 4. Added DDL Escalation (db_owner)
Original Step 3 used `load_file('/etc/passwd')` which is MySQL-specific and unrelated to clinical data. Added `DROP TABLE patients` DDL via `db_owner` — destroys the clinical trial dataset. In Pharmaceutical context: destroying Phase III trial data triggers FDA audit and regulatory liability.

### 5. No Inconsistency
This example has consistent declared vulnerability (SQL Injection), code (raw string concatenation), payload (`' OR 1=1 --`), and HAR (all records returned). No contradiction to address.
