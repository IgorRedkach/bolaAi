# Analysis Explanation
**Folder:** GQL-0308-GOVERNMENT | **Context source:** This folder's context.txt only.
- System: FirstResponse CAD Integration (GraphQL), Government/Public Safety
- Host: `api.firstresponse-cad-in.example.com`
- Attacker tenant: `tenant-5984`, victim tenant: `tenant-5a8f`
- HAR query: `listResources(tenantId: "tenant-5a8f")`, response key: `getResource` — **INCONSISTENCY**: HAR uses `listResources` but response key is `getResource`. HAR operation is authoritative.
- Response: `ownerId: "other-user-59845a8f"`, `sensitiveField: "CONFIDENTIAL-59845a8f"`, `internalNotes: "Internal data exposed"`
- Redis cache keyed by `resourceId` only (no tenant dimension — secondary vulnerability, emergency dispatch data cache poisoning risk)
- `x-request-id: req-59845a8f` is a response header (not a request header)
- Pattern 10.5: Draft/non-published resource access (Single-User) — `listResources` accepts client-supplied `tenantId`; resolver does not validate against JWT tenantId; exposes CAD dispatch records potentially including draft/non-published status records that should be completely inaccessible cross-tenant
- §4.0 RISK-GQL-308: `getResource` fetches by `resourceId` only; `bulkResourceLookup` lacks per-ID ownership filtering
- Critical domain context: government/public safety — exposing draft CAD records reveals active emergency response operations
**Consistency Guard:** All values from this folder's context.txt only.
