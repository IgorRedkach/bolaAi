# Analysis Explanation
**Folder:** GQL-0278-CONSTRUCTION | **Context source:** This folder's context.txt only.
- System: BuildCore BIM Collaboration, Construction/BIM
- Host: `api.buildcore-bim-collab.example.com`
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-c0c5a06a` is a response header (not sent in request)
- HAR request: `listResources(tenantId: "tenant-a06a")` — response key: `getResource` (INCONSISTENCY)
- tenantId: `tenant-a06a`, ownerId: `other-user-c0c5a06a`, sensitiveField: `CONFIDENTIAL-c0c5a06a`
- Pattern 4.2: Persistence poisoning — unauthorized read access to lifecycle records enables downstream manipulation of persisted BIM project state
**Consistency Guard:** All values from this folder's context.txt only.
