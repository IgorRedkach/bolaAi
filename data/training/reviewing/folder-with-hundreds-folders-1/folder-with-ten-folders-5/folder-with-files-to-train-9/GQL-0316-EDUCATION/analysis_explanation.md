# Analysis Explanation
**Folder:** GQL-0316-EDUCATION | **Context source:** This folder's context.txt only.
- System: LearnPath Assessment Platform (GraphQL), Education/EdTech LMS
- Host: `api.learnpath-assessment.example.com`
- Attacker tenant: `tenant-2956`, victim tenant: `tenant-5314`
- HAR mutation: `bulkResourceLookup(ids: ["R-2316", "R-1316", "R-3316"])`, response key: `getResource` — **INCONSISTENCY**: HAR uses `bulkResourceLookup` but response key is `getResource`. HAR operation is authoritative.
- Response: `ownerId: "other-user-29565314"`, `sensitiveField: "CONFIDENTIAL-29565314"`, `internalNotes: "Internal data exposed"`
- Redis cache keyed by `resourceId` only (no tenant dimension — secondary vulnerability)
- `x-request-id: req-29565314` is a response header (not a request header)
- Pattern 1.9: Batch/bulk lookup endpoints (BOLA) — `bulkResourceLookup` accepts arbitrary IDs without per-ID ownership checks; single request can enumerate any LMS resource across all tenants; §5.0 explicitly: "a single request can enumerate objects across all tenants"
- §4.0 RISK-GQL-316: `getResource` fetches by `resourceId` only; `bulkResourceLookup` lacks per-ID ownership filtering
**Consistency Guard:** All values from this folder's context.txt only.
