# Analysis Explanation
**System analysed:** TraceOrigin Supply API — GQL-0079 (Food & Beverage / Supply Chain)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 3.3 (semantic ambiguity/over-broad endpoints — insecure design). `bulkResourceLookup` is semantically scoped to "own resources" but accepts any IDs.
2. HAR: `bulkResourceLookup(["R-2079","R-1079","R-3079"])` from `tenant-4693`. Response `tenant-620b`: `CONFIDENTIAL-4693620b`. `x-request-id: req-4693620b`.
3. Pattern 3.3 angle: design flaw in endpoint semantics — "bulk lookup" implies own data but implementation has no ownership boundary.

## Consistency Guard
Tenant IDs: `tenant-4693`, `tenant-620b`. Resources: `R-2079`, `R-1079`, `R-3079`. ownerId: `other-user-4693620b`. Leaked: `CONFIDENTIAL-4693620b`. Request: `req-4693620b`. All from this folder only.
