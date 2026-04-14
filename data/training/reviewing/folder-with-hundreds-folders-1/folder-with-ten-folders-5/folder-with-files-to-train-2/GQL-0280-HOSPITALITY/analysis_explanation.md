# Analysis Explanation
**Folder:** GQL-0280-HOSPITALITY | **Context source:** This folder's context.txt only.
- System: StayPro Property API, Hospitality/Property Management
- Host: `api.staypro-property-api.example.com`
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-0056bdc2` is a response header (not sent in request)
- HAR request: `updateResource(id: "R-2280", input: {status: "approved", ownerId: "attacker-0056bdc2"})` — response key: `getResource` (INCONSISTENCY — mutation request, read-key response)
- tenantId: `tenant-bdc2`, ownerId: `other-user-0056bdc2`, sensitiveField: `CONFIDENTIAL-0056bdc2`
- Pattern 5.2: Graph traversal injection — attacker traverses resolver graph via mutation input to read unauthorized records
**Consistency Guard:** All values from this folder's context.txt only.
