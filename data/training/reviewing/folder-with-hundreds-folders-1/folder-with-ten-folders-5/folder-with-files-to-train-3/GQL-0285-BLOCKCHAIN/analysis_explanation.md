# Analysis Explanation
**Folder:** GQL-0285-BLOCKCHAIN | **Context source:** This folder's context.txt only.
- System: ChainVault DeFi API, Blockchain/DeFi
- Host: `api.chainvault-defi-api.example.com`
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-91e14709` is a response header (not sent in request)
- HAR request: `bulkResourceLookup(ids: ["R-2285","R-1285","R-3285"])` — response key: `getResource` (INCONSISTENCY)
- tenantId: `tenant-4709`, ownerId: `other-user-91e14709`, sensitiveField: `CONFIDENTIAL-91e14709`
- Pattern 10.2: Parameter escalation — attacker substitutes DeFi resource IDs to extend own session scope
**Consistency Guard:** All values from this folder's context.txt only.
