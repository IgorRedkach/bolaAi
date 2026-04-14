# Analysis Explanation — INJ-0123-LDAPi-RETAIL

## Changes Made

### 1. context.txt — Removed Vulnerability Label, Fixed Architecture, Added LDAP Snippet
- Removed "**Vulnerability Type:** LDAP Injection" from spec header
- Section 2.0 "Database: corporate directory services" updated to Active Directory (LDAP) + PostgreSQL
- Added LDAP filter construction code snippet showing `cn=${filter}` interpolation — this is the evidence for LDAP injection
- Legacy SQL path added as secondary code snippet
- RISK-INJ-123 updated to describe LDAP filter injection and SQL legacy path

### 2. expected_response.md — Corrected Endpoint and Parameter
Original used `/api/v1/users?search=`. Context Section 3.0 and HAR specify `/api/v3/orders?filter=`. Corrected throughout.

### 3. Corrected Hostname
Original Steps 3-4 used generic `api.example.com`. HAR specifies `api.rewardcore-loya.example.com`. Corrected.

### 4. LDAP Injection Primary with Directory Enumeration
Added LDAP-specific attacks:
- Step 2: `admin)(&(password=*))` — auth bypass (HAR payload), explained constructed filter
- Step 3: `*)((objectClass=*)` — wildcard enumerate all directory entries
- Step 4: Blind injection to extract attribute values character by character

### 5. HAR Inconsistency Addressed
HAR response shows SQL-structured records despite LDAP database. Acknowledged: legacy SQL path active on same endpoint. SQL path added as Finding 2.

### 6. LDAP-Specific Remediations
Added `ldapjs.escapeFiler()`, LDAP metacharacter input validation, and service account privilege restriction.
