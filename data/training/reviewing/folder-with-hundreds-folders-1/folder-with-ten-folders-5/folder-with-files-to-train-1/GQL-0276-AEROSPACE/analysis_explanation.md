# Analysis Explanation
**Folder:** GQL-0276-AEROSPACE | **Context source:** This folder's context.txt only.
- System: WingTech Maintenance Portal, Aerospace/Aviation Maintenance
- Host: `api.wingtech-maintenance.example.com`
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-09a1a735` is a response header (not sent in request)
- HAR request: `updateResource(id: "R-2276", input: {status: "approved", ownerId: "attacker-09a1a735"})` — response key: `getResource` (INCONSISTENCY — mutation request, read-key response)
- tenantId: `tenant-a735`, ownerId: `other-user-09a1a735`, sensitiveField: `CONFIDENTIAL-09a1a735`
- Pattern 3.1: Client-assumed authority — design trusts client to supply only legitimate `ownerId`; no server-side authority check
**Consistency Guard:** All values from this folder's context.txt only.
