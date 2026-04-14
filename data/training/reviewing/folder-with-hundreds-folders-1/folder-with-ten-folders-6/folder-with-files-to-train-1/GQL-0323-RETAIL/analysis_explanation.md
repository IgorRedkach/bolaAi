# Analysis Explanation
**Example:** GQL-0323-RETAIL — RewardCore Loyalty API
**Pattern:** 5.1 — Authorization-bypass injection (Injection)

---

## Why This Is a Vulnerability

Pattern 5.1 (Injection — Authorization-bypass injection) captures cases where an attacker injects attacker-controlled data into an authorization-sensitive path in such a way that the injection bypasses the intended access check. The `bulkResourceLookup` mutation is designed to accept a list of IDs for batch retrieval. However, because the resolver processes the list without per-ID ownership validation, an attacker can inject any cross-tenant IDs into the list. Each injected ID is processed as if it were a legitimate owned resource. This is an injection flaw because the injected IDs cause the authorization mechanism to be bypassed rather than enforced per-item.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for GQL-0323.

- **System Name:** RewardCore Loyalty API (§1.0)
- **Domain:** Retail / Loyalty Programme
- **Host:** `api.rewardcore-loyalty-a.example.com` (§6.0 HAR)
- **Attacker tenant:** `tenant-770d` (§6.0 HAR `x-tenant-id` header)
- **Victim tenant:** `tenant-855b` (§6.0 HAR; §6.0 response `tenantId`)
- **Injected IDs:** `R-2323`, `R-1323`, `R-3323` (§6.0 HAR `bulkResourceLookup` ids array)
- **Sensitive data exposed:** `sensitiveField: "CONFIDENTIAL-770d855b"`, `internalNotes: "Internal data exposed"` (§6.0 response)
- **ownerId of victim record:** `other-user-770d855b` (§6.0 response)
- **Vulnerable resolver:** `bulkResourceLookup` (§6.0 HAR; §4.0)
- **Root cause:** `bulkResourceLookup` accepts arbitrary ID arrays without per-ID ownership filtering (§4.0, §5.0)
- **Redis cache key gap:** Cache keyed by `resourceId` only (§2.0)

**Context.txt inconsistency documented:** HAR operation is `bulkResourceLookup`; response JSON key is `getResource`. This is an internal inconsistency in the context.txt. The HAR operation is authoritative.

## Domain Risk

Retail loyalty programme data includes customer points balances, redemption histories, personal offers, and PII. Cross-tenant bulk extraction exposes competitor retail programme structures and customer data. Pattern 5.1 injection allows systematic enumeration of loyalty records at scale — an attacker can enumerate all IDs in the `R-XXXX` namespace in a single bulk call, extracting all loyalty records from competing tenants.

## What the Model Should Learn

- Pattern 5.1 is not about SQL injection or traditional injection; it is about injecting IDs into a resolver path that bypasses per-item authorization.
- Bulk endpoints (`bulkResourceLookup`, `batchGet`, etc.) are high-risk surfaces because they amplify the per-item authorization flaw: one call returns multiple victim records.
- Authorization must be enforced per-item within the loop processing the IDs array, not just at the resolver entry point.
- The combination of `bulkResourceLookup` and predictable `R-XXXX` IDs makes this a particularly severe enumeration and mass-extraction risk.
- Redis cache without a tenant dimension enables cross-tenant cache poisoning in addition to the resolver-level flaw.
