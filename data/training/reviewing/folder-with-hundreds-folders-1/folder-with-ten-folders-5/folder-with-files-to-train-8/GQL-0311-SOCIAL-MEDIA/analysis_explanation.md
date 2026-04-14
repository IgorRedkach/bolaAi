# Analysis Explanation
**Folder:** GQL-0311-SOCIAL-MEDIA | **Context source:** This folder's context.txt only.
- System: Horizon Social Graph API (GraphQL), Social Media/Identity Graph
- Host: `api.horizon-social-graph.example.com`
- Attacker tenant: `tenant-79b1`, victim tenant: `tenant-558d`
- HAR query: `listPosts(tenantId: "tenant-558d")`, response key: `getPost` — **INCONSISTENCY**: HAR uses `listPosts` but response key is `getPost`. HAR operation is authoritative.
- Response: `ownerId: "other-user-79b1558d"`, `sensitiveField: "CONFIDENTIAL-79b1558d"`, `internalNotes: "Internal data exposed"`
- Redis cache keyed by `postId` only (no tenant dimension — secondary vulnerability)
- `x-request-id: req-79b1558d` is a response header (not a request header)
- Pattern 1.3: Bulk or list endpoints (BOLA) — `listPosts` returns bulk results when `tenantId` is client-supplied; resolver does not validate against JWT tenantId; entire victim tenant's social content exposed through a single list query
- §5.0 explicitly: "`listPosts` resolver returns all objects when `tenantId` is supplied from the client without JWT-level validation"
- §4.0 RISK-GQL-311: `getPost` also fetches by `postId` only without `tenantId` cross-check; `bulkPostLookup` lacks per-ID ownership filtering
**Consistency Guard:** All values from this folder's context.txt only.
