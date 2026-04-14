# Analysis Explanation
**Folder:** GQL-0319-MEDIA | **Context source:** This folder's context.txt only.
- System: StreamCore VOD Platform, Media/VOD
- Host: `api.streamcore-vod-platf.example.com`
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-c9b96f4c` is a response header (not sent in request)
- HAR request: `updateResource(id: "R-2319", input: {status: "approved", ownerId: "attacker-c9b96f4c"})` — response key: `getResource` (INCONSISTENCY — mutation request, read-key response)
- tenantId: `tenant-6f4c`, ownerId: `other-user-c9b96f4c`, sensitiveField: `CONFIDENTIAL-c9b96f4c`
- Pattern 2.2: Metadata side-channel — mutation response returns sensitive VOD fields the caller is not authorized to read
**Consistency Guard:** All values from this folder's context.txt only.
