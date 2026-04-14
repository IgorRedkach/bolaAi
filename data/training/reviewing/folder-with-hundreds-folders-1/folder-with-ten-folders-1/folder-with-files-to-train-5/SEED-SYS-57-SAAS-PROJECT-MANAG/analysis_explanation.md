## Analysis reasoning

I reviewed the TaskFlow Project Management API v6.0.0 architecture specification, Python Django resolver code, schema, and HAR trace.

1. **Three-vulnerability chain**: sequential IDs (1.8) + soft null fail (9.1 side-channel) + alias batching (9.1 rate-limit bypass) together enable mass enumeration. Each vulnerability is individually insufficient: sequential IDs alone require many separate HTTP requests (blocked by rate limits); alias batching alone requires a guessable ID space; soft null alone requires the ability to send many probes. Combined, they create a single-request mass enumeration attack.

2. **HAR `x-resolver-count: 2000` as primary evidence**: this header confirms the Django resolver executed 2,000 times within one HTTP request. The response size of 74.5KB for 2,000 queries is relatively small — most entries return `null` (a few bytes), but non-null entries add more data. The two non-null entries (`p10003` and `p10156`) are separated by ~150 IDs — consistent with a multi-tenant platform where not every sequential ID belongs to a project visible to the attacker.

3. **Soft fail vs. hard fail trade-off documented**: section 4.0 explains: "The core authorization check returns a soft `null` on failure to prevent verbose error leakage (Pattern 6.2)." This is a case where the developer chose soft null to avoid error information disclosure, but inadvertently created a worse side-channel — the response structure itself (null vs. populated object) is more informative than a generic 403 error would be.

4. **Confidential data exposed**: `confidentialNotes` is a `TEXT` column on the project that contains strategic business information. The HAR response includes funding plans ("Need to secure $5M") and engineering strategy ("Pivot to Go-lang"). This is corporate IP and trade secret material — cross-tenant access is a data breach.

5. **SERIAL PRIMARY KEY as compounding factor**: the schema comment explicitly labels `project_id SERIAL PRIMARY KEY` as "VULNERABILITY 1.8: Predictable ID". The system debt note (section 4.0) acknowledges: "We intentionally used simple sequential IDs for historical reasons." The combination of acknowledged ID predictability and acknowledged soft-fail behavior is documented in RISK-GRPH-903 as the compounding risk.
