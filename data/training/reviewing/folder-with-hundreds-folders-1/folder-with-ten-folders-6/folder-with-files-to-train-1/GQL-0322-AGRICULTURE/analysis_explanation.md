# Analysis Explanation
**Example:** GQL-0322-AGRICULTURE — HarvestIQ IoT Platform
**Pattern:** 4.2 — Persistence poisoning via lifecycle actions (Integrity)

---

## Why This Is a Vulnerability

Pattern 4.2 (Integrity — Persistence poisoning) captures a more severe class of authorization flaw than simple data disclosure: an attacker can not only read a victim's record but durably corrupt it. The `updateResource` mutation is a lifecycle action — it is expected to change persistent state. Without a tenancy check in the mutation resolver, an attacker can supply any `resourceId` and overwrite fields such as `status` and `ownerId` on records belonging to other tenants. This specific case demonstrates: (1) cross-tenant record mutation, (2) forced status escalation (`approved`), and (3) `ownerId` reassignment — all durable changes to the victim's IoT platform record.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for GQL-0322.

- **System Name:** HarvestIQ IoT Platform (§1.0)
- **Domain:** Agriculture / Precision Farming
- **Host:** `api.harvestiq-iot-platfo.example.com` (§6.0 HAR)
- **Attacker tenant:** `tenant-12cc` (§6.0 HAR `x-tenant-id` header)
- **Victim tenant:** `tenant-81b0` (§6.0 HAR mutation target; §6.0 response `tenantId`)
- **Victim resource ID:** `R-2322` (§6.0 HAR mutation `id`)
- **Mutation input:** `{status: "approved", ownerId: "attacker-12cc81b0"}` (§6.0 HAR)
- **Sensitive data exposed in response:** `sensitiveField: "CONFIDENTIAL-12cc81b0"`, `internalNotes: "Internal data exposed"` (§6.0 response)
- **ownerId of victim record:** `other-user-12cc81b0` (§6.0 response)
- **Vulnerable resolver:** `updateResource` (§6.0 HAR)
- **Root cause:** Mutation resolver does not cross-check record's `tenantId` against JWT (§4.0 RISK-GQL-322, §5.0)
- **Redis cache key gap:** Cache keyed by `resourceId` only (§2.0)

**Context.txt inconsistency documented:** HAR operation is `updateResource`; response JSON key is `getResource`. This is an internal inconsistency in the context.txt. The HAR operation is authoritative for the exploit path.

## Domain Risk

Precision farming IoT data includes field telemetry, sensor readings, crop status, and equipment state. Forging an `approved` status on an IoT resource could trigger automated workflows (e.g., irrigation, harvest cycles) in the victim's environment. `ownerId` reassignment could permanently dispossess the legitimate owner of their device or record. Additionally, cross-tenant data disclosure of `sensitiveField` and `internalNotes` could expose proprietary agronomic data or crop yield intelligence.

## What the Model Should Learn

- Pattern 4.2 is specifically about durable state corruption, not just data disclosure. The mutation poisons the persistence layer.
- Lifecycle mutations (`updateResource`, `deleteResource`, status transitions) require the same tenancy authorization checks as read operations.
- Client-supplied `ownerId` in a mutation input is a red flag — ownership must be controlled by the server.
- A successful 200 response to a cross-tenant mutation confirms the persistence poisoning has taken effect.
- Redis cache without a tenant dimension enables cross-tenant cache poisoning in addition to the resolver-level flaw.
