# Expected Response

## System
- Domain: Telemedicine / Remote Care
- System: TeleCare Consultation API
- Example ID: GQL-0136

## Priority Findings

### Finding 1: Telemedicine — Cross-Tenant PHI Exposure via updateResource (Pattern 1.5)
**Severity:** Critical
**Category:** BOLA / Multi-Tenant / Cross-Tenant Access

**Summary:**
Per §5.0 (Pattern 1.5 — multi-tenant / cross-tenant access): The `updateResource` resolver does not validate that the resource belongs to the caller's tenant. An attacker from `tenant-7000` submitted `updateResource(id: "R-2136", input: {status: "approved", ownerId: "attacker-70005d15"})` against a remote care consultation belonging to `tenant-5d15`, gaining cross-tenant write access to patient consultation data including `CONFIDENTIAL-70005d15`. In Telemedicine, this constitutes unauthorized access to Protected Health Information (PHI), violating HIPAA and exposing patient diagnoses, treatment plans, and clinician notes.

**Evidence from HAR:**
- Request: `POST https://api.telecare-consultatio.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-7000`
- Mutation: `updateResource(id: "R-2136", input: {status: "approved", ownerId: "attacker-70005d15"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-5d15"`, `ownerId: "other-user-70005d15"`, `sensitiveField: "CONFIDENTIAL-70005d15"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-70005d15`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.5 | updateResource, no cross-tenant guard |
| HAR request | x-tenant-id | Attacker tenant-7000 |
| HAR request | input.ownerId | attacker-70005d15 (client-injected) |
| HAR response | tenantId | Cross-tenant PHI tenant-5d15 |

## Steps to Reproduce

### Step 1 — updateResource cross-tenant PHI (HAR)
```bash
curl -s -X POST https://api.telecare-consultatio.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-7000" \
  -d '{"query": "mutation { updateResource(id: \"R-2136\", input: {status: \"approved\", ownerId: \"attacker-70005d15\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-5d15` PHI mutated. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput`.
3. PHI fields must be encrypted at rest and in transit; audit all access with `x-request-id`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
