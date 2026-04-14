# Analysis Explanation
**Folder:** GQL-0279-FOOD-&-BEVERAGE | **Context source:** This folder's context.txt only.
- System: TraceOrigin Supply API, Food & Beverage/Supply Chain
- Host: `api.traceorigin-supply-a.example.com`
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-308eeec7` is a response header (not sent in request)
- HAR request: `bulkResourceLookup(ids: ["R-2279","R-1279","R-3279"])` — response key: `getResource` (INCONSISTENCY)
- tenantId: `tenant-eec7`, ownerId: `other-user-308eeec7`, sensitiveField: `CONFIDENTIAL-308eeec7`
- Pattern 5.1: Authorization-bypass injection — attacker injects cross-tenant resource IDs into bulk lookup; no per-ID ownership validation
**Consistency Guard:** All values from this folder's context.txt only.
