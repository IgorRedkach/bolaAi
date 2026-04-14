# Analysis Explanation
**Folder:** GQL-0287-AVIATION | **Context source:** This folder's context.txt only.
- System: AeroOps Flight Management, Aviation/Flight Operations
- Host: `api.aeroops-flight-manag.example.com`
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-a412b86d` is a response header (not sent in request)
- HAR request: `updateResource(id: "R-2287", input: {status: "approved", ownerId: "attacker-a412b86d"})` — response key: `getResource` (INCONSISTENCY — mutation request, read-key response)
- tenantId: `tenant-b86d`, ownerId: `other-user-a412b86d`, sensitiveField: `CONFIDENTIAL-a412b86d`
- Pattern 1.1: ID without ownership check — mutation `id` parameter not validated against authenticated user
**Consistency Guard:** All values from this folder's context.txt only.
