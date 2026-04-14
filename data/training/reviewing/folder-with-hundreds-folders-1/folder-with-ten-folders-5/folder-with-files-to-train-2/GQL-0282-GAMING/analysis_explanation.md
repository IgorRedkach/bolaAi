# Analysis Explanation
**Folder:** GQL-0282-GAMING | **Context source:** This folder's context.txt only.
- System: RealmForge Game API, Gaming/Online Platform
- Host: `api.realmforge-game-api.example.com`
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-aea51faf` is a response header (not sent in request)
- HAR request: `bulkCharacterLookup(ids: ["C-2282","C-1282","C-3282"])` — response key: `getCharacter` (INCONSISTENCY — bulk request, single-record response key)
- tenantId: `tenant-1faf`, ownerId: `other-user-aea51faf`, sensitiveField: `CONFIDENTIAL-aea51faf`
- Pattern 7.1: PII logged operationally without masking; cross-tenant character data exposed in both response and logs
**Consistency Guard:** All values from this folder's context.txt only.
