# Analysis Explanation — INJ-0116-CMDi-EDUCATION

## Changes Made

### 1. Corrected Endpoint, Parameter, and API Version
Original used `/api/v1/users?search=`. Context Section 3.0 specifies `GET /api/v3/records?username=` (API version v3, parameter `username`, table `records`). HAR confirms `api.learnpath-asses.example.com/api/v3/records?username=`. Corrected throughout.

### 2. Fixed Generic Hostname
Steps 3-4 used `api.example.com`. All curl commands now use `api.learnpath-asses.example.com` from HAR.

### 3. Addressed Internal Inconsistency (CMDi declared vs. SQL code)
Context conflict: Section 2.0 declares "OS-level execution" (CMDi backend); Section 3.0 shows SQL string concatenation. HAR payload is `; cat /etc/passwd` (CMDi shell separator). HAR response is SQL user records. Acknowledged inconsistency and made CMDi the primary demonstration (declared vulnerability), with SQL as secondary.

### 4. Replaced SQLi Escalation with CMDi-Specific Attacks
Original Step 3 showed SQLi `UNION SELECT load_file('/etc/passwd')` — wrong for CMDi. Replaced with:
- `; id; whoami` (Step 3): identity enumeration, confirms OS execution
- `; env` (Step 4): environment variable dump for credential exfiltration

### 5. Corrected CMDi Description
Original: "The query `SELECT * FROM users WHERE search = '; cat /etc/passwd'` evaluates to true for all rows" — this is an SQL tautology description, not CMDi. Corrected: `;` is a shell separator that terminates the current command and executes `cat /etc/passwd` as a separate OS command.

### 6. Added CMDi-Specific Remediations
Replaced generic SQL remediations with CMDi-specific fixes: safe OS API (`execFile` with argument array), allowlisted values, OS process privilege restriction, shell metacharacter blocking.

### 7. Contextualized for Education/EdTech LMS Domain
`env` exfiltration in an LMS context exposes student PII database credentials, LMS admin API keys, and potentially FERPA-regulated student data access credentials.
