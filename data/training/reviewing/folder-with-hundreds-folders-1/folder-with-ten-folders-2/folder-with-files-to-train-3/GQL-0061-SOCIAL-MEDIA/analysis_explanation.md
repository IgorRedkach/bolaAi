# Analysis Explanation
**System analysed:** Horizon Social Graph API — GQL-0061 (Social Media / Identity Graph)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 6.1 — introspection ENABLED in production (explicit). Schema exposes sensitive field names.
2. Domain types: `Post`, `postId`, `bulkPostLookup` (from HAR).
3. HAR: `bulkPostLookup(["P-2061","P-1061","P-3061"])` from `tenant-0d18`. Response `tenant-4b62`: `CONFIDENTIAL-0d184b62`. `x-request-id: req-0d184b62`.
4. Introspection is legitimate here — §5.0 explicitly confirms it is enabled.

## Consistency Guard
Tenant IDs: `tenant-0d18`, `tenant-4b62`. Post IDs: `P-2061`, `P-1061`, `P-3061`. ownerId: `other-user-0d184b62`. Leaked: `CONFIDENTIAL-0d184b62`. Request: `req-0d184b62`. All from this folder only.
