# Analysis Explanation
**Example:** GQL-0350-PARKING — ParkIQ Management API
**Pattern:** 10.1 — ID swap in own request (Single-User)

---

## Why This Is a Vulnerability

Pattern 10.1 (Single-User — ID swap) captures the simplest form of authorization bypass: an attacker who has a legitimate, valid token for their own resources changes only the resource identifier in their own request. No session forgery, no privilege escalation, no second account — just swapping `nodeId: "my-node"` for `nodeId: "I-2350"`. The `getIntersection` resolver does not verify `intersection.tenantId` against `jwt.tenantId`, so the swap succeeds silently.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for GQL-0350.

- **System Name:** ParkIQ Management API (§1.0)
- **Domain:** Parking / Smart City
- **Host:** `api.parkiq-management-ap.example.com` (§6.0 HAR)
- **Attacker tenant:** `tenant-5e35` (§6.0 HAR `x-tenant-id`)
- **Victim tenant:** `tenant-7d19` (§6.0 HAR; §6.0 response `tenantId`)
- **Victim node ID:** `I-2350` (§6.0 HAR)
- **Object type:** `Intersection` / `nodeId` field (§3.0)
- **Sensitive data exposed:** `sensitiveField: "CONFIDENTIAL-5e357d19"`, `internalNotes: "Internal data exposed"` (§6.0 response)
- **ownerId of victim record:** `other-user-5e357d19` (§6.0 response)
- **Vulnerable resolver:** `getIntersection` (§6.0 HAR; §4.0 RISK-GQL-350)
- **Root cause:** `getIntersection` fetches by `nodeId` only, no `tenantId` JWT cross-check (§4.0, §5.0)
- **Redis cache key gap:** Cache keyed by `nodeId` only (§2.0)

**No operation name inconsistency:** HAR operation `getIntersection` matches response key `getIntersection`. Context is internally consistent on this point.

## Domain Risk

Smart city parking management systems control physical infrastructure — intersection signals, parking gate controls, and IoT device states. Cross-tenant access to `sensitiveField` and `internalNotes` of intersection objects could expose operational security data (patrol routes, traffic control timing) or allow an attacker to identify infrastructure vulnerabilities in a competing municipality's smart city deployment.

## What the Model Should Learn

- Pattern 10.1 (ID swap) is the minimum-effort BOLA attack: no sophistication required beyond knowing or guessing the target ID.
- The attacker's own session being valid is what makes this possible — it is not an unauthenticated attack.
- Resolver-level tenancy cross-check (`if (record.tenantId !== jwt.tenantId) throw Forbidden`) must be implemented regardless of whether the requester appears legitimate.
- Redis cache without tenant dimension creates a secondary attack path that persists even after resolver-level fixes if cache is not addressed.
