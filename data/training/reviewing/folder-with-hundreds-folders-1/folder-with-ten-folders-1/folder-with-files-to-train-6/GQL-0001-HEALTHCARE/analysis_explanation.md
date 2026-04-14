## Analysis reasoning

I reviewed the PatientCore EHR API v2.5.1 architecture specification, GraphQL schema, and HAR trace.

1. **BOLA root cause documented explicitly**: section 4.0 (RISK-GQL-001) states "The `getPatient` resolver fetches by `patientId` only. The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`. Tracked internally as a known gap pending remediation." This is the canonical documentation of the vulnerability — no inference required.

2. **HAR request/response discrepancy — mutation vs. query**: the HAR request `postData` shows `updatePatient(id: "P-2001", input: {status: "approved", ownerId: "attacker-2922cf40"})` — a mutation. The response body shows `getPatient: {...}` data structure. This inconsistency in the synthetic HAR does not invalidate the evidence — the response `"tenantId": "tenant-cf40"` with the attacker's `x-tenant-id: tenant-2922` header confirms cross-tenant access regardless of which operation triggered it. Both the read and write paths are vulnerable per the documented resolver flaw.

3. **Write BOLA impact**: the mutation injects `ownerId: "attacker-2922cf40"` — this means the attacker attempted to change the ownership of a cross-tenant patient record. In a healthcare context, changing a patient's `ownerId` (likely the responsible clinician or facility) is a significant data integrity violation — it would redirect care management responsibility.

4. **Bulk lookup adds enumeration surface**: section 4.0 documents the `bulkPatientLookup` gap separately from RISK-GQL-001. This is a Pattern 1.9 (bulk endpoint without per-ID ownership filtering) secondary finding. Combined with sequential or guessable patient IDs (`P-2001`, `P-3001`, etc.), this enables mass enumeration.

5. **Redis cache keyed by `patientId` only**: section 2.0 notes: "Redis cache keyed by `patientId` (NOTE: no user dimension in cache key)." This is a secondary vulnerability — if Dr. Jones queries `P-2001` and it caches successfully, a subsequent request from `tenant-2922` for the same ID would receive the cached `tenant-cf40` response, even if the resolver was later fixed to enforce tenant checks for fresh fetches.

6. **HIPAA relevance**: `sensitiveField` and `internalNotes` are PHI under HIPAA. Cross-tenant access constitutes a breach — both under the Minimum Necessary Rule (accessing more than needed) and the tenant isolation requirement (accessing another covered entity's patient data).
