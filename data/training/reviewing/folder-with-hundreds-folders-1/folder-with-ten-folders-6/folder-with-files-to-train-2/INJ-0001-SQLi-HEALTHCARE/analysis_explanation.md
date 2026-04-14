# Analysis Explanation
**Example:** INJ-0001-SQLi-HEALTHCARE — PatientCore EHR API
**Pattern:** SQL Injection

---

## Why This Is a Vulnerability

SQL injection is the most prevalent and well-understood injection vulnerability: user input is concatenated directly into a SQL query string, allowing the attacker to modify the query's structure. The payload `' OR 1=1 --` works by: (1) `'` — closes the string literal that wraps the original `id` value; (2) ` OR 1=1` — adds a condition that is always true, causing the WHERE clause to match every row; (3) ` --` — SQL single-line comment that nullifies the rest of the original query. The result: `SELECT * FROM users` (without any filter), returning all rows.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for INJ-0001.

- **System Name:** PatientCore EHR API (§1.0)
- **Domain:** Healthcare / EHR Platform
- **Host:** `api.patientcore-ehr.example.com` (§5.0 HAR)
- **Vulnerable endpoint:** `GET /api/v3/users` (§3.0, §5.0 HAR)
- **Vulnerable parameter:** `id` (§3.0, §4.0)
- **Injection payload:** `' OR 1=1 --` (§4.0)
- **Database:** Enterprise DBMS (§2.0)
- **Vulnerable code:** raw string concatenation `${req.query.id}` in Node.js (§3.0)
- **Data exposed:** admin credentials (`username: admin`, `password_hash: $2b$12$secret`, `role: ADMIN`), user2 credentials (§5.0 response)
- **Compounding factors:** over-privileged DB account (`db_owner`), no WAF on legacy endpoints (§6.0)
- **Known risk:** `RISK-INJ-001` — `/api/v3/users` missed in parameterization migration (§7.0)

## Domain Risk

Healthcare / EHR platforms store PHI and are subject to HIPAA. Extracting admin credentials from the user table allows full administrative access — potentially enabling bulk patient record export (a major HIPAA breach), modification of medical records, or destruction of audit trails. The `db_owner` privilege means the attacker could also execute DDL statements (DROP, ALTER) affecting clinical data.

## What the Model Should Learn

- SQL injection via `' OR 1=1 --` is the canonical SQL injection test payload: single-quote breaks out of the string context, `OR 1=1` is the always-true bypass, `--` comments out the trailing quote/remainder.
- The fix for all SQL injection is parameterized queries (prepared statements) with bound parameters — never string concatenation.
- In healthcare EHR, SQL injection against a user table not only exposes credentials but also constitutes a HIPAA security incident requiring mandatory breach notification.
- Legacy endpoints that were "missed" in migrations remain the most common source of SQL injection in production systems.
