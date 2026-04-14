# Expected Response

## System
- Domain: Agriculture / AgriTech IoT
- System: HarvestIQ IoT Platform
- Example ID: GQL-0122

## Priority Findings

### Finding 1: AgriTech IoT Client-Assumed Authority — Server Trusts Client ID Without Ownership Verification (Pattern 3.1)
**Severity:** Critical
**Category:** Insecure Design / Client-Assumed Authority

**Summary:**
Per §5.0 (Pattern 3.1 — client-assumed authority): The server accepts client-supplied resource IDs as authority without server-side ownership verification. An attacker from `tenant-f0d1` submitted `updateResource(id: "R-2122", input: {status: "approved", ownerId: "attacker-f0d17852"})` against an agricultural IoT resource belonging to `tenant-7852`. The system was designed assuming clients only send IDs they own, but lacks enforcement. In AgriTech IoT, this enables unauthorized modification of soil sensors, irrigation controls, and crop monitoring systems.

**Evidence from HAR:**
- Request: `POST https://api.harvestiq-iot-plat.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-f0d1`
- Mutation: `updateResource(id: "R-2122", input: {status: "approved", ownerId: "attacker-f0d17852"}) { resourceId status }`
- Response `200 OK`; `tenantId: "tenant-7852"`, `sensitiveField: "CONFIDENTIAL-f0d17852"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-f0d17852`

## Steps to Reproduce

### Step 1 — Client-assumed authority IoT mutation (HAR)
```bash
curl -s -X POST https://api.harvestiq-iot-plat.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-f0d1" \
  -d '{"query": "mutation { updateResource(id: \"R-2122\", input: {status: \"approved\", ownerId: \"attacker-f0d17852\"}) { resourceId status } }"}'
```
**Vulnerable:** AgriTech IoT resource from `tenant-7852` mutated. **Secure:** FORBIDDEN.

## Remediation
1. Server must verify ownership — never trust client-supplied IDs.
2. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Strip `ownerId` from `ResourceInput`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
