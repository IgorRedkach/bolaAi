# Analysis Explanation
**Folder:** GQL-0318-TRAVEL | **Context source:** This folder's context.txt only.
- System: SkyPort Global Distribution, Travel/GDS
- Host: `api.skyport-global-distr.example.com`
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-b7c0538c` is a response header (not sent in request)
- HAR request: `listResources(tenantId: "tenant-538c")` — response key: `getResource` (INCONSISTENCY)
- tenantId: `tenant-538c`, ownerId: `other-user-b7c0538c`, sensitiveField: `CONFIDENTIAL-b7c0538c`
- Pattern 1.12: Mass field exposure via client-controlled `tenantId` filter; no field allowlist on list resolver
**Consistency Guard:** All values from this folder's context.txt only.
