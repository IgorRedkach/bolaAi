# Analysis Explanation
**System analysed:** VenueCore Ticketing API — GQL-0099 (Event Management / Ticketing)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 2.2 (metadata/attribute side-channel — BAC). `internalNotes`/`auditLog` exposed cross-tenant.
2. HAR: `bulkResourceLookup(["R-2099","R-1099","R-3099"])` from `tenant-5170`. Response `tenant-ef08`: `CONFIDENTIAL-5170ef08`, `internalNotes: "Internal data exposed"`. `x-request-id: req-5170ef08`.
3. Pattern 2.2: even after BOLA is fixed, metadata fields may leak — field-level authorization needed.

## Consistency Guard
Tenant IDs: `tenant-5170`, `tenant-ef08`. Resources: `R-2099`, `R-1099`, `R-3099`. ownerId: `other-user-5170ef08`. Leaked: `CONFIDENTIAL-5170ef08`. Request: `req-5170ef08`. All from this folder only.
