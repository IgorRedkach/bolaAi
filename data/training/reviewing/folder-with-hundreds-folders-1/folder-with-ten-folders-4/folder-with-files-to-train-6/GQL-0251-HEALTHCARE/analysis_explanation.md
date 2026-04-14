# Analysis Explanation

**Folder:** GQL-0251-HEALTHCARE
**Context source:** This folder's context.txt only. No other example was consulted.

---

## Step-by-step Analysis

### 1. Architecture Review (§2.0)
PatientCore EHR API (v2.4.0) is a healthcare electronic health record platform. Redis caching is keyed by `patientId` only — no tenant dimension. In a healthcare context, this means a cache miss by one tenant's lookup can populate a cache entry readable by another tenant querying the same `patientId`.

### 2. Schema Inspection (§3.0)
`getPatient(id: ID!)` accepts a bare ID with no ownership constraint. The `Patient` type includes `patientId`, `tenantId`, `ownerId`, and `data { sensitiveField, internalNotes }` — all returned when a valid ID is provided.

### 3. Risk Assessment (§4.0)
RISK-GQL-251 states: "The `getPatient` resolver fetches by `patientId` only." Pattern 1.10 highlights that the vulnerability specifically involves identity drift across internal service calls — the propagated JWT or forwarded header is not re-validated at the downstream resolver.

### 4. Vulnerability Pattern (§5.0)
Pattern 1.10 — Cross-service identity propagation drift: The attacker's valid JWT is forwarded to downstream services that trust `x-tenant-id` without re-checking the JWT tenant claim against the requested resource's owning tenant.

### 5. HAR Trace Analysis
- **Request headers (§6.0):** `:authority: api.patientcore-ehr-api.example.com`, `authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...`, `x-tenant-id: tenant-b355` (attacker's tenant), `content-type: application/json`
- **Request body:** `getPatient(id: "P-2251")` — attacker supplies a patient ID owned by `tenant-5f01`
- **`x-request-id: req-b3555f01`** is a **response header** (§6.0 response.headers), NOT a request header. The curl reproduction does not include it.
- **Response:** PHI returned — `tenantId: tenant-5f01`, `ownerId: other-user-b3555f01`, `sensitiveField: CONFIDENTIAL-b3555f01`, `internalNotes: Internal data exposed`

### 6. Healthcare-Specific Impact
PHI exposure in an EHR platform constitutes a HIPAA violation. The finding was elevated to CRITICAL severity because the exposed data (`sensitiveField`, `internalNotes`) in a healthcare EHR context directly maps to protected health information.

### 7. Reproduction Construction
The curl command was built from the HAR request headers and body in §6.0 of this context.txt: host `api.patientcore-ehr-api.example.com`, JWT, `x-tenant-id: tenant-b355`, GraphQL query with `id: "P-2251"`. The `x-request-id` header was deliberately omitted because it is a server-assigned response header, not a client request header.

### 8. Remediation Justification
Cross-service identity drift requires fixes at two layers: the resolver (post-fetch tenant assertion) and the service boundary (JWT re-validation rather than header trust). The audit logging requirement reflects HIPAA compliance obligations for EHR access.

---

**Consistency Guard:** All details (system name, domain, version, patient ID P-2251, JWT, x-request-id, CONFIDENTIAL value, RISK code, pattern number) are sourced exclusively from this folder's context.txt.
