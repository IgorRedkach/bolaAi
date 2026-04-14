# Analysis Explanation
**Folder:** GQL-0283-CYBERSECURITY | **Context source:** This folder's context.txt only.
- System: ThreatLens SOC Platform, Cybersecurity/SOC
- Host: `api.threatlens-soc-platf.example.com`
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-e166d53c` is a response header (not sent in request)
- HAR request: `listResources(tenantId: "tenant-d53c")` — response key: `getResource` (INCONSISTENCY)
- tenantId: `tenant-d53c`, ownerId: `other-user-e166d53c`, sensitiveField: `CONFIDENTIAL-e166d53c`
- Pattern 9.1: GraphQL single endpoint — no per-operation auth context; client-supplied `tenantId` bypass on SOC threat data
**Consistency Guard:** All values from this folder's context.txt only.
