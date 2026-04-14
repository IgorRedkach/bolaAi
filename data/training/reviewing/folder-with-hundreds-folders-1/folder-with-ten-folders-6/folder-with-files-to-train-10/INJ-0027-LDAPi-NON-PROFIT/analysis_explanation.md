# Analysis Explanation
**Example:** INJ-0027-LDAPi-NON-PROFIT — GrantFlow CRM API
**Pattern:** LDAP Injection

---

## Why This Is a Vulnerability

LDAP injection exploits unsanitized user input that is concatenated into an LDAP filter string. LDAP filters use a specific syntax: `(attribute=value)` with boolean operators `&` (AND), `|` (OR), `!` (NOT). If the user-supplied `filter` value contains unescaped LDAP metacharacters — particularly `)`, `(`, `*`, `\` — the attacker can break out of the intended filter and construct an arbitrary one. The payload `admin)(&(password=*))` closes the current filter group, then adds `&(password=*)` — "AND password matches any value" — which is always true, causing the directory to return all matching entries regardless of the original filter intent.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for INJ-0027.

- **System Name:** GrantFlow CRM API (§1.0)
- **Domain:** Non-Profit / Grant Management
- **Host:** `api.grantflow-crm-a.example.com` (§5.0 HAR)
- **Vulnerable endpoint:** `GET /api/v2/patients` (§3.0, §5.0 HAR)
- **Vulnerable parameter:** `filter` (§3.0, §4.0)
- **Injection payload:** `admin)(&(password=*))` (§4.0)
- **Database:** corporate directory services / LDAP (§2.0)
- **Vulnerable code:** raw string concatenation in Node.js (§3.0)
- **Data exposed:** admin credentials (`username: admin`, `password_hash: $2b$12$secret`, `role: ADMIN`), user2 credentials (§5.0 HAR response)
- **Compounding factors:** over-privileged DB account (`db_owner`), no WAF on legacy endpoints (§6.0)
- **Known risk:** `RISK-INJ-027` — `/api/v2/patients` missed in parameterization migration (§7.0)

**Context.txt inconsistency noted:** §3.0 vulnerable code snippet uses SQL-style syntax (`SELECT * FROM patients`) while §2.0 states the backend is "corporate directory services" and the vulnerability type is LDAP Injection. The SQL snippet appears to be a template artifact. The vulnerability type and backend description from §1.0, §2.0, and the example ID (`LDAPi`) are authoritative — this is LDAP injection.

**Additional context.txt note:** The endpoint path is `/api/v2/patients` in a non-profit grant management system — the path name (`patients`) is unusual for grant management and appears to be a template artifact.

## Domain Risk

Non-profit grant management platforms manage donor PII, grant recipient data, and organizational financial records. Access to admin credentials from the corporate directory allows full organizational access — donor databases, grant fund management, beneficiary records, and financial accounts. LDAP injection in a directory service can also expose all employee credentials in a single query.

## What the Model Should Learn

- LDAP injection is distinct from SQL injection and NoSQL injection: the attacker manipulates LDAP filter syntax (`(`, `)`, `*`, `&`, `|`, `!`, `\`).
- The payload `admin)(&(password=*))` works by: closing the current group with `)`, then adding an AND-TRUE condition `(&(password=*))`, making the filter match all entries.
- Prevention: use LDAP escaping functions (e.g., `ldap.escape()` in Node.js, `LdapEncoder.filterEncode()` in Java) to treat user input as data, never as filter syntax.
- Over-privileged directory bind DN amplifies the impact — a read-only, scoped bind DN limits what can be retrieved even if injection succeeds.
