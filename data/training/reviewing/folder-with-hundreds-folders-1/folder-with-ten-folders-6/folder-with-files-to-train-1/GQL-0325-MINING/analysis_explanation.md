# Analysis Explanation
**Example:** GQL-0325-MINING — OreTrack Fleet Management
**Pattern:** 6.1 — Schema/relationship over-exposure (Misconfiguration)

---

## Why This Is a Vulnerability

Pattern 6.1 (Misconfiguration — Schema/relationship over-exposure) captures cases where the API's configuration exposes more than it should, either through introspection (revealing schema structure, internal type names, field relationships) or through over-broad resolver arguments (exposing privileged filter parameters that should be server-controlled). OreTrack exhibits both: (1) production introspection is enabled, meaning any authenticated user can enumerate the full schema — discovering that `listResources` accepts a `tenantId` argument — and (2) the `listResources` resolver does not validate that the supplied `tenantId` matches the JWT. The combination is compounding: introspection aids discovery of the exposed argument, and the unvalidated argument enables the cross-tenant access.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for GQL-0325.

- **System Name:** OreTrack Fleet Management (§1.0)
- **Domain:** Mining / Resource Extraction
- **Host:** `api.oretrack-fleet-manag.example.com` (§6.0 HAR)
- **Attacker tenant:** `tenant-7fdd` (§6.0 HAR `x-tenant-id` header)
- **Victim tenant:** `tenant-09bb` (§6.0 HAR `listResources` tenantId argument; §6.0 response `tenantId`)
- **Sensitive data exposed:** `sensitiveField: "CONFIDENTIAL-7fdd09bb"`, `internalNotes: "Internal data exposed"` (§6.0 response)
- **ownerId of victim record:** `other-user-7fdd09bb` (§6.0 response)
- **Vulnerable resolver:** `listResources` (§6.0 HAR)
- **Additional misconfiguration:** GraphQL introspection enabled in production (§5.0)
- **Root cause:** `listResources` accepts client-supplied `tenantId` with no JWT cross-check; introspection aids schema discovery (§4.0 RISK-GQL-325, §5.0)
- **Redis cache key gap:** Cache keyed by `resourceId` only (§2.0)

**Context.txt inconsistency documented:** HAR operation is `listResources`; response JSON key is `getResource`. This is an internal inconsistency in the context.txt. The HAR operation is authoritative for the exploit path.

## Domain Risk

Mining fleet management platforms contain operational telemetry for heavy machinery, extraction site locations, ore yield data, equipment maintenance schedules, and personnel assignments. Cross-tenant access to `sensitiveField` and `internalNotes` could expose proprietary extraction site intelligence, competitor resource yields, or fleet operational data — commercially sensitive and potentially relevant to national resource security in mining-critical regions.

## What the Model Should Learn

- Pattern 6.1 is specifically about configuration-level over-exposure: what is exposed via schema introspection and what arguments are publicly available in the schema.
- Introspection in production is not the primary vulnerability, but it is a significant enabler — it removes the need for reconnaissance and directly reveals exploitable arguments.
- A client-supplied `tenantId` filter argument on a list endpoint is a high-risk design: it makes tenancy boundary enforcement dependent on input validation rather than server-authoritative claims.
- Pattern 6.1 differs from Pattern 3.3 (semantic ambiguity) in that 6.1 is about configuration (what the schema exposes), while 3.3 is about the semantic design of the resolver logic itself.
- Redis cache without a tenant dimension enables cross-tenant cache poisoning in addition to the resolver-level flaw.
