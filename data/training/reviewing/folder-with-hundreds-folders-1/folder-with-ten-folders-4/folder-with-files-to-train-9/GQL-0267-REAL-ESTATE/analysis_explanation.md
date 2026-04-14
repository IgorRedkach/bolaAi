# Analysis Explanation
**Folder:** GQL-0267-REAL-ESTATE | **Context source:** This folder's context.txt only.
- System: EstateFlow Property API, Real Estate/PropTech
- Host: `api.estateflow-property-.example.com` (trailing dash reproduced exactly from context.txt)
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-0963650d` is a response header (not sent in request)
- HAR request: `getResource(id: "R-2267")` — response key: `getResource` (CONSISTENT, no inconsistency)
- Victim tenantId: `tenant-650d`, ownerId: `other-user-0963650d`, sensitiveField: `CONFIDENTIAL-0963650d`
- Pattern 1.3: bulk/list endpoint; `listResources` returns all objects when client-supplied `tenantId` filter is not validated against JWT
- Redis cache keyed by `resourceId` only → no tenant isolation in cache layer
**Consistency Guard:** All values from this folder's context.txt only.
