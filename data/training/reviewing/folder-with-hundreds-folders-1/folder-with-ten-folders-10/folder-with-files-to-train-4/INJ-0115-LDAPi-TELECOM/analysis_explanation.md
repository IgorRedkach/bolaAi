# Analysis Explanation — INJ-0115-LDAPi-TELECOM

## Changes Made

### 1. Corrected Endpoint and Parameter
Original used `/api/v1/users?search=`. Context Section 3.0 specifies `GET /api/v1/records?username=` and HAR confirms `api.spectrenet-poli.example.com/api/v1/records?username=`. Corrected throughout.

### 2. Fixed Generic Hostname
Steps 3-4 used `api.example.com`. All curl commands now use `api.spectrenet-poli.example.com` from HAR.

### 3. Addressed Internal Inconsistency (LDAP declared vs. SQL code)
Context has a conflict: Section 2.0 declares "corporate directory services" (LDAP); Section 3.0 shows SQL string concatenation. The HAR payload is `admin)(&(password=*))` — an LDAP filter operator injection. Acknowledged the inconsistency and made LDAP Injection the primary demonstration (as declared), noting SQL as a secondary code-path.

### 4. Replaced SQLi Escalation with LDAPi-Specific Attacks
Original Step 3 showed SQLi `UNION SELECT load_file('/etc/passwd')` — completely wrong for LDAP Injection. Replaced with:
- Wildcard enumeration `*` (Step 3): return all directory entries
- Blind injection `admin)(cn=*` (Step 4): attribute existence testing for schema discovery

### 5. Corrected LDAP Filter Description
Original: "The query `SELECT * FROM users WHERE search = 'admin)(&(password=*))'` evaluates to true for all rows" — this is an SQL description, not LDAP. Corrected: The LDAP filter `(&(username=admin)(&(password=*)))` causes password wildcard match (always true), returning the admin account.

### 6. Added LDAP-Specific Remediations
Replaced generic SQL remediations with LDAP-specific fixes: LDAP SDK input escaping, parameterized LDAP filter construction, LDAP account privilege restriction, wildcard search disabling.

### 7. Contextualized for Telecom/5G Core Domain
In a 5G Core policy control system, the LDAP directory contains subscriber identities, network policy records, and infrastructure service account credentials. Full directory enumeration via wildcard injection could expose IMSI/IMEI data and network configuration secrets.
