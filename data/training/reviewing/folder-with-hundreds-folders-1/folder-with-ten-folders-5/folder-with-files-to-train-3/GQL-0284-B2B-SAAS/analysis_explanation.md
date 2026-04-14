# Analysis Explanation
**Folder:** GQL-0284-B2B-SAAS | **Context source:** This folder's context.txt only.
- System: PipelinePro Sales API, B2B SaaS/Sales Pipeline
- Host: `api.pipelinepro-sales-ap.example.com`
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-84724ba5` is a response header (not sent in request)
- HAR request: `bulkProjectLookup(ids: ["P-2284","P-1284","P-3284"])` — response key: `getProject` (INCONSISTENCY)
- tenantId: `tenant-4ba5`, ownerId: `other-user-84724ba5`, sensitiveField: `CONFIDENTIAL-84724ba5`
- Pattern 10.1: ID swap in own request — attacker substitutes cross-tenant project IDs in bulk lookup
**Consistency Guard:** All values from this folder's context.txt only.
