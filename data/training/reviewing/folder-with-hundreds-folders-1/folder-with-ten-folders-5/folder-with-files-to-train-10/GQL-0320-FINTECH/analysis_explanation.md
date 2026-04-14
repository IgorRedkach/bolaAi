# Analysis Explanation
**Folder:** GQL-0320-FINTECH | **Context source:** This folder's context.txt only.
- System: PayBridge Transaction API, FinTech/Payment Processing
- Host: `api.paybridge-transactio.example.com`
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-a530999f` is a response header (not sent in request)
- HAR request: `getResource(id: "R-2320")` — response key: `getResource` (CONSISTENT, no inconsistency)
- tenantId: `tenant-999f`, ownerId: `other-user-a530999f`, sensitiveField: `CONFIDENTIAL-a530999f`
- Pattern 3.1: Client-assumed authority — resolver trusts client-supplied ID without ownership verification
**Consistency Guard:** All values from this folder's context.txt only.
