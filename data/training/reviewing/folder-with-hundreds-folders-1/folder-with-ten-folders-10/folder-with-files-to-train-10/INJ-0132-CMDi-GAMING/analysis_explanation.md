# Analysis Explanation — INJ-0132-CMDi-GAMING

## What was wrong

### 1. Wrong endpoint and parameter throughout

Original response used `/api/v1/users?search=` throughout. Section 3.0 and HAR both specify `/api/v2/patients?name=`. Fixed all steps.

### 2. Generic host URL in Steps 3/4

Steps 3 and 4 used `api.example.com` instead of `api.realmforge-game.example.com`. Fixed.

### 3. Internal inconsistency: CMDi declaration vs SQL code vs HAR response

The context declares CMDi (Command Injection) but:
- Section 3.0 shows raw SQL string concatenation: `SELECT * FROM patients WHERE name = '${req.query.name}'`
- Section 4.0 payload `; cat /etc/passwd` is an OS command separator / SQL statement terminator
- HAR response contains SQL-structured data: `username`, `password_hash`, `role: "ADMIN"`

This is the same class of inconsistency found in INJ-0108. The HAR response confirms SQLi is the active vulnerability (user records returned via SQL injection). The OS-level CMDi payload syntax terminates the WHERE clause and causes all-rows return. Both SQLi and CMDi vectors are demonstrated since the context explicitly calls out `db_owner` privileges that enable escalation.

### 4. Original "Step 3" used wrong URL and speculative UNION

Step 3 was on `api.example.com` (wrong). Fixed to use correct host and realistic UNION payload against `users` table matching the HAR response structure.

## Domain context

RealmForge is a Gaming / MMO backend. The `patients` table name is an artifact of the data generation process — it represents backend user/player account records in the MMO context. Cross-table access via `db_owner` UNION injection allows exfiltration of all player credentials. Admin account compromise (`role: "ADMIN"`) enables full game server takeover, player ban manipulation, and in-game economy fraud.
