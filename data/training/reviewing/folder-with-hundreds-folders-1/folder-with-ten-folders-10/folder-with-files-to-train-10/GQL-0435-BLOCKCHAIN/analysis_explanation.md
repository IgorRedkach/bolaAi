# Analysis Explanation — GQL-0435-BLOCKCHAIN

## What was wrong

### 1. Pattern 6.1 introspection placed last (Step 4) and treated as optional

The original response placed introspection in Step 4 with the qualifier "if Pattern 6.1 also present" — but Pattern 6.1 IS the primary declared pattern. Section 5.0 explicitly states introspection is enabled in production and exposes internal field names and relationship paths. Moved introspection to Step 1 to correctly model the reconnaissance phase that enables all subsequent BOLA exploitation (same structure as GQL-0017-REAL-ESTATE which also covers Pattern 6.1).

### 2. HAR primary (`bulkResourceLookup`) was in Step 3 — moved to Step 2

The HAR captures `bulkResourceLookup(ids: ["R-2435", "R-1435", "R-3435"])` from `tenant-53dd`. This is the primary demonstrated attack. The original response had `getResource` in Step 2 (primary) and `bulkResourceLookup` in Step 3. Swapped to align with HAR.

### 3. HAR request/response mismatch acknowledged

HAR request sends `bulkResourceLookup` but the response body contains `getResource`-shaped data. This is a synthetic artifact of the test harness. Noted in response.

### 4. Redis cache step missing

Section 2.0 explicitly documents: "Redis cache keyed by `resourceId` (NOTE: no user dimension in cache key)." This is a documented vulnerability enabling cache-poisoned cross-tenant reads. Was not in original response. Added as Step 4.

## Domain context

ChainVault is a Blockchain / DeFi platform. Resources represent DeFi protocol configurations, wallet/portfolio data, smart contract parameters, or transaction records. Cross-tenant read via introspection-guided `bulkResourceLookup` exposes proprietary DeFi strategies, wallet addresses, and internal protocol notes (`internalNotes`). Pattern 6.1 introspection is particularly dangerous in DeFi because it reveals the complete financial data model to any authenticated attacker before the BOLA is even exploited.

## HAR alignment

HAR primary: `bulkResourceLookup(ids: ["R-2435", "R-1435", "R-3435"])` with `x-tenant-id: tenant-53dd` → HTTP 200 → `tenantId: "tenant-6f9d"`, `sensitiveField`, `internalNotes`. This is Step 2.
