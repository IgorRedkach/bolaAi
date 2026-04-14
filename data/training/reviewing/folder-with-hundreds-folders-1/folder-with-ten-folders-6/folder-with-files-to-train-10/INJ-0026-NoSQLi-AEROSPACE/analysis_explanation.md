# Analysis Explanation
**Example:** INJ-0026-NoSQLi-AEROSPACE — WingTech Maintenance Portal
**Pattern:** NoSQL Injection (MongoDB operator injection)

---

## Why This Is a Vulnerability

NoSQL Injection via MongoDB operator injection exploits the fact that MongoDB uses JSON documents for query specifications. If a user-supplied string is directly interpolated into a MongoDB query without sanitization, the attacker can supply a MongoDB operator object (`{"$gt": ""}`) instead of a literal value. The `$gt` operator causes MongoDB to match any document where the field value is greater than an empty string — effectively matching all documents. The root cause is raw string concatenation: `${req.query.query}` is directly embedded in the query without parameterization or input validation.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for INJ-0026.

- **System Name:** WingTech Maintenance Portal (§1.0)
- **Domain:** Aerospace / MRO
- **Host:** `api.wingtech-mainte.example.com` (§5.0 HAR)
- **Vulnerable endpoint:** `GET /api/v1/users` (§3.0, §5.0 HAR)
- **Vulnerable parameter:** `query` (§3.0, §4.0)
- **Injection payload:** `{ "$gt": "" }` (§4.0)
- **Database:** MongoDB / document store (§2.0)
- **Vulnerable code:** raw string concatenation `${req.query.query}` in Node.js (§3.0)
- **Data exposed:** admin credentials (`username: admin`, `password_hash: $2b$12$secret`, `role: ADMIN`), user2 credentials (§5.0 HAR response)
- **Compounding factors:** over-privileged DB account (`db_owner`), no WAF on legacy endpoints (§6.0)
- **Known risk:** `RISK-INJ-026` — `/api/v1/users` missed in parameterization migration (§7.0)

## Domain Risk

Aerospace / MRO (Maintenance, Repair, Overhaul) platforms store safety-critical maintenance records, component certifications, and personnel credentials. Extracting admin credentials from the user table allows an attacker to escalate to full administrative access, potentially modifying maintenance records, falsifying airworthiness certifications, or accessing classified component data — with direct aviation safety implications.

## What the Model Should Learn

- NoSQL injection is distinct from SQL injection: the attacker injects MongoDB query operators (e.g., `$gt`, `$where`, `$regex`) rather than SQL syntax.
- The `{"$gt": ""}` payload works specifically because MongoDB's `$gt` comparison operator matches any non-empty string, effectively bypassing equality filters.
- The root cause is always string concatenation without parameterization — parameterized queries or ORM bound parameters prevent injection by treating input as data, not query structure.
- Legacy endpoints that were "missed" in a migration are a high-risk pattern — they retain the old vulnerable code path while newer endpoints are patched.
- Over-privileged DB accounts amplify injection impact: `db_owner` access means the attacker can do more than just read.
