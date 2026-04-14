# Analysis Explanation
**Example:** INJ-0028-CMDi-CONSTRUCTI — BuildCore BIM Collaboration
**Pattern:** Command Injection

---

## Why This Is a Vulnerability

Command injection occurs when user-supplied data is passed to a system shell or OS-level execution context without sanitization. The `;` character is a shell command separator — `cmd1; cmd2` executes `cmd2` regardless of `cmd1`'s exit status. By injecting `; cat /etc/passwd` into the `filter` parameter, the attacker appends an arbitrary OS command to the application's existing command, causing the server to execute `cat /etc/passwd` and potentially expose system user credentials. The root cause is raw string interpolation of `req.query.filter` into an executed command string.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for INJ-0028.

- **System Name:** BuildCore BIM Collaboration (§1.0)
- **Domain:** Construction / BIM Platform
- **Host:** `api.buildcore-bim-c.example.com` (§5.0 HAR)
- **Vulnerable endpoint:** `GET /api/v2/products` (§3.0, §5.0 HAR)
- **Vulnerable parameter:** `filter` (§3.0, §4.0)
- **Injection payload:** `; cat /etc/passwd` (§4.0)
- **Backend:** OS-level execution (§2.0)
- **Vulnerable code:** raw string concatenation `${req.query.filter}` (§3.0)
- **HAR response:** Database records (template artifact) — actual exploit reads `/etc/passwd` per §4.0 payload and §2.0 OS-level context
- **Compounding factors:** over-privileged DB account (`db_owner`), no WAF on legacy endpoints (§6.0)
- **Known risk:** `RISK-INJ-028` — `/api/v2/products` missed in parameterization migration (§7.0)

**Context.txt inconsistency noted:** §5.0 HAR response contains DB user records instead of `/etc/passwd` output. Per §2.0 ("OS-level execution") and §4.0 (command injection payload `; cat /etc/passwd`), the HAR response is a template artifact. The actual OS command injection impact per the vulnerability type is reading system files. Both are documented.

## Domain Risk

Construction / BIM (Building Information Modelling) platforms contain 3D building models, structural engineering data, contractor PII, and project financial information. OS command injection on a BIM server grants an attacker shell access to the application server — enabling file system traversal, credential extraction from configuration files (database connection strings, API keys), and potentially lateral movement within the construction firm's infrastructure.

## What the Model Should Learn

- Command injection is one of the most severe injection categories: it grants arbitrary OS-level code execution, not just data access.
- The `;` separator (`cmd1; cmd2`) is the simplest command chaining technique. Other separators: `&&`, `||`, `|`, backticks, `$()`.
- Prevention: never pass user input to `exec()`, `shell()`, `spawn()` as part of a shell string — use argument arrays (`exec("cat", [filename])` never `exec("cat " + filename)`).
- Even if the immediate effect is hidden (response shows DB data), the injection still executes on the server — blind command injection.
- BIM platforms running as `db_owner` with command injection represent a path to full server compromise and potentially to accessing structural safety data.
