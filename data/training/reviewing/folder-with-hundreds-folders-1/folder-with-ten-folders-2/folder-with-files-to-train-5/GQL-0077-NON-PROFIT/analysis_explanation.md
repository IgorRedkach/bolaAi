# Analysis Explanation
**System analysed:** GrantFlow CRM API — GQL-0077 (Non-Profit / Fundraising CRM)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 2.2 (metadata/attribute side-channel — BAC). `internalNotes` and `auditLog` fields are returned cross-tenant, exposing operational metadata.
2. HAR: `getResource(id: "R-2077")` from `tenant-b473`. Response `tenant-a22b`: `CONFIDENTIAL-b473a22b`, `internalNotes: "Internal data exposed"`. `x-request-id: req-b473a22b`.
3. Pattern 2.2 distinguishes from simple BOLA: even after BOLA is fixed, metadata fields may still leak information — field-level authorization required.

## Consistency Guard
Tenant IDs: `tenant-b473`, `tenant-a22b`. Resource: `R-2077`. ownerId: `other-user-b473a22b`. Leaked: `CONFIDENTIAL-b473a22b`. Request: `req-b473a22b`. All from this folder only.
