# Analysis Explanation

This example (GQL-0436) was generated independently for the **TeleCare Consultation API** system (Telemedicine / Remote Care).

## Generation Method
1. Selected industry: **Telemedicine / Remote Care**
2. Designed realistic GraphQL architecture with schema, JWT auth, and multi-tenant data model.
3. Embedded **Pattern 7.1 (Operational PII/PHI leakage)** from bola_patterns.md into the resolver logic.
4. Generated HAR capture showing the cross-tenant request with mismatched tenantId evidence.
5. Wrote expected response grounded exclusively in the context.txt of this example.

## Why GraphQL?
GraphQL's single-endpoint model means all authorization must be enforced inside individual resolvers.
A missing WHERE clause in one resolver exposes the entire object graph.

## Consistency Guard
- Context refreshed for this example; no data from other examples was retained.
- All object IDs, tenant IDs, and field names are consistent within this folder only.

## Pattern Coverage
- Primary: Pattern 7.1 — Operational PII/PHI leakage (Logging Failures)
