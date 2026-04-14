# Analysis Explanation
**Folder:** GQL-0310-SAAS | **Context source:** This folder's context.txt only.
- System: TaskFlow Collaboration API (GraphQL), SaaS/Project Management
- Host: `api.taskflow-collaborati.example.com`
- Attacker tenant: `tenant-ffdb`, victim tenant: `tenant-cf40`
- HAR mutation: `updateProject(id: "P-2310", input: {status: "approved", ownerId: "attacker-ffdbcf40"})`, response key: `getProject` — **INCONSISTENCY**: HAR uses `updateProject` mutation but response key is `getProject`. HAR operation is authoritative.
- Response: `ownerId: "other-user-ffdbcf40"`, `sensitiveField: "CONFIDENTIAL-ffdbcf40"`, `internalNotes: "Internal data exposed"`
- Redis cache keyed by `projectId` only (no tenant dimension — secondary vulnerability)
- `x-request-id: req-ffdbcf40` is a response header (not a request header)
- Pattern 1.2: Related/linked resource access (BOLA) — `updateProject` lacks tenancy check; cross-tenant project with linked `tasks` child resources is accessible; client-supplied `ownerId` enables unauthorized ownership reassignment of linked project records; `getProject` also fetches by `projectId` only (RISK-GQL-310)
**Consistency Guard:** All values from this folder's context.txt only.
