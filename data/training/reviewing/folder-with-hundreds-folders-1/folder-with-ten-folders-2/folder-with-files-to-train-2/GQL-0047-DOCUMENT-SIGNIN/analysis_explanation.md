# Analysis Explanation

**System analysed:** SignFlow eSign Platform — GQL-0047 (Document Signing / eSign)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read §5.0** — Pattern 1.3. "`listResources` returns all objects when `tenantId` is omitted or supplied from client without JWT validation." Two attack vectors: omitted tenantId and attacker-supplied tenantId.
2. **Read §3.0** — `listResources(tenantId: ID)` accepts optional caller-supplied tenantId. `bulkResourceLookup` in mutations.
3. **Read §4.0** — RISK-GQL-047: no tenantId cross-check. `bulkResourceLookup` no per-ID filter.
4. **Read HAR** — `getResource(id: "R-2047")` from `tenant-3cd7`. Response `tenant-1095`: `CONFIDENTIAL-3cd71095`. `x-request-id: req-3cd71095`.
5. **Two list attack vectors** — Step 1 (omit tenantId) and Step 2 (supply cross-tenant tenantId) both documented from §5.0. Step 3 (HAR direct ID) is the demonstrated evidence.

## Consistency Guard
- Tenant IDs: `tenant-3cd7`, `tenant-1095`. Resource: `R-2047`. ownerId: `other-user-3cd71095`. Leaked: `CONFIDENTIAL-3cd71095`. Request ID: `req-3cd71095`. All from this folder only.
