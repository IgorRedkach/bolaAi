# Analysis Explanation
**Folder:** GQL-0277-NON-PROFIT | **Context source:** This folder's context.txt only.
- System: GrantFlow CRM API, Non-Profit/Grant Management CRM
- Host: `api.grantflow-crm-api.example.com`
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-8a933908` is a response header (not sent in request)
- HAR request: `listResources(tenantId: "tenant-3908")` — response key: `getResource` (INCONSISTENCY)
- tenantId: `tenant-3908`, ownerId: `other-user-8a933908`, sensitiveField: `CONFIDENTIAL-8a933908`
- Pattern 3.3: Semantic ambiguity — the `listResources` endpoint is over-broad and accepts client-supplied `tenantId` without JWT validation, functioning as a cross-tenant enumeration endpoint
**Consistency Guard:** All values from this folder's context.txt only.
