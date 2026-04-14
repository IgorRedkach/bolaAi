# Analysis Explanation
**Folder:** GQL-0317-REAL-ESTATE | **Context source:** This folder's context.txt only.
- System: EstateFlow Property API, Real Estate/PropTech
- Host: `api.estateflow-property-.example.com` (trailing dash reproduced from context.txt)
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-f4a8e43e` is a response header (not sent in request)
- HAR request: `getResource(id: "R-2317")` — response key: `getResource` (CONSISTENT, no inconsistency)
- tenantId: `tenant-e43e`, ownerId: `other-user-f4a8e43e`, sensitiveField: `CONFIDENTIAL-f4a8e43e`
- Pattern 1.10: Identity propagation drift — resolver does not re-validate tenant identity; cross-service identity leakage
**Consistency Guard:** All values from this folder's context.txt only.
