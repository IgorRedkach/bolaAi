## Analysis reasoning

1. **Wrong endpoint and ID format in original**: the original expected_response.md used `/api/v1/resources/RES-*` — the context.txt specifies `/api/v2/entitys/ENT-*` and the HAR uses `ENT-2073`. All references corrected.

2. **Pattern 2.4 (Privilege escalation via parameter tampering) must demonstrate write escalation**: the pattern is specifically about escalating privileges beyond the authorized level — not just reading unauthorized data (that is Pattern 1.1). Section 4.0 explicitly lists GET/PATCH/DELETE. Demonstrating a PATCH that modifies another retailer's loyalty status is what makes Pattern 2.4 distinct from a simple BOLA read. The original expected_response.md had "Step 3 — Variant tests based on Pattern 2.4: No specific variant documented" — this is wrong, the write path should be demonstrated.

3. **RISK-24-073 provides key context**: the risk is documented and remediation is blocked pending DB migration #DB-173. This confirms the handler was written before the tenant isolation policy and is a known gap — important context for impact assessment.

4. **Database schema comment is the strongest evidence**: section 3.0 includes an explicit SQL comment "Application code does NOT use tenant_id in authorization checks" — this is the definitive evidence for the root cause.

5. **Loyalty programme context**: `status: "suspended"` via PATCH could disable another retailer's customer's loyalty account, causing customer service harm and financial disputes.
