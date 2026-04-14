# Analysis Explanation — INJ-0112-SSRF-INSURANCE

## Changes Made

### 1. Corrected Endpoint and Parameter
Original `expected_response.md` used `/api/v1/users?search=`. Context.txt Section 3.0 specifies endpoint `GET /api/v1/records?filter=`. HAR confirms `api.claimsflow-unde.example.com/api/v1/records?filter=`. Corrected throughout.

### 2. Fixed Generic Hostname
Steps 3-4 in original used `api.example.com`. All curl commands now use `api.claimsflow-unde.example.com` from HAR.

### 3. Acknowledged Internal Inconsistency
Context.txt has a three-way conflict:
- Declared vulnerability: SSRF
- Section 2.0 database: "backend HTTP fetch"
- Code snippet (Section 3.0): raw SQL string concatenation
- HAR payload: `http://169.254.169.254/latest/meta-data/` (SSRF URL)
- HAR response: SQL user records with `password_hash` (not AWS metadata)

The primary declared vulnerability is SSRF, so the primary reproduction steps demonstrate SSRF. The SQLi path (from code snippet) is shown as a secondary vector since it is evidenced by the HAR response.

### 4. Added SSRF-Specific Escalation Steps
The original response described SSRF as "bypass authentication" which is incorrect. SSRF allows the server to issue HTTP requests to unintended destinations. Added:
- AWS EC2 metadata endpoint (`169.254.169.254/latest/meta-data/`)
- IAM role credentials escalation (`/iam/security-credentials/`)
- Internal service enumeration (port scan via SSRF)

### 5. Corrected SSRF Description
Original claimed "The query evaluates to true for all rows" — this is a SQLi (tautology injection) description, not SSRF. Rewrote to correctly describe SSRF as server-side outbound HTTP request forgery.

### 6. Added SQLi as Secondary Path
Since the HAR response shows SQL user records (not AWS metadata), the `db_owner` SQL path is also present. Added UNION SELECT data exfiltration as Step 5 (secondary path from code snippet evidence).

### 7. Remediation Expanded
Added SSRF-specific remediations (URL allowlist, metadata endpoint blocking, network egress controls) alongside the SQLi parameterized query fix.
