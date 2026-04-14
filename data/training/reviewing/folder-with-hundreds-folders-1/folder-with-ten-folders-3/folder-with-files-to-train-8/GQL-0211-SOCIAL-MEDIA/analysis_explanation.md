# Analysis Explanation
**System analysed:** Horizon Social Graph API — GQL-0211 (Social Media / Content Platform)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-211: `getPost`/`listPosts` resolver lacks `tenantId` check; accepts caller-supplied `tenantId`.
2. §5.0 Pattern 3.3: Insecure Design — semantic ambiguity; `listPosts` endpoint scope is undefined, over-broad.
3. HAR: `tenant-9c9c` queries `listPosts(tenantId: "tenant-fe91")` → `tenant-fe91` private posts: `CONFIDENTIAL-9c9cfe91`, `req-9c9cfe91`.
4. Social Media domain: private posts, drafts, moderated content — GDPR/CCPA privacy violation.

## Consistency Guard
Attacker: `tenant-9c9c`. Victim: `tenant-fe91`. Post: `P-2211`. Sensitive: `CONFIDENTIAL-9c9cfe91`. ownerId: `other-user-9c9cfe91`. Request: `req-9c9cfe91`. All from this folder only.
