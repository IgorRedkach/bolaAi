# Analysis Explanation
**Folder:** GQL-0286-TELEMEDICINE | **Context source:** This folder's context.txt only.
- System: TeleCare Consultation API, Telemedicine/Remote Consultation
- Host: `api.telecare-consultatio.example.com`
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-1383283b` is a response header (not sent in request)
- HAR request: `updateResource(id: "R-2286", input: {status: "approved", ownerId: "attacker-1383283b"})` — response key: `getResource` (INCONSISTENCY — mutation request, read-key response)
- tenantId: `tenant-283b`, ownerId: `other-user-1383283b`, sensitiveField: `CONFIDENTIAL-1383283b`
- Pattern 10.5: Draft/unpublished record access — attacker reads consultation records that have not been published/finalized
**Consistency Guard:** All values from this folder's context.txt only.
