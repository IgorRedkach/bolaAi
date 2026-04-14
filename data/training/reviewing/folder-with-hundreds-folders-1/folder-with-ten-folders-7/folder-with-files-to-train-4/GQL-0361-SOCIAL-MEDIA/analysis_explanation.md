# Analysis Explanation

This example (GQL-0361) was generated independently for the **Horizon Social Graph API** system (Social Media / Identity Graph).

## Generation Method
1. Selected industry: **Social Media / Identity Graph**
2. Designed realistic GraphQL architecture with schema, JWT auth, and multi-tenant data model.
3. Embedded **Pattern 1.10 (Cross-service identity propagation drift)** from bola_patterns.md into the resolver logic.
4. Generated HAR capture showing the cross-tenant request with mismatched tenantId evidence.
5. Wrote expected response grounded exclusively in the context.txt of this example.

## Why GraphQL?
GraphQL's single-endpoint model means all authorization must be enforced inside individual resolvers.
A missing WHERE clause in one resolver exposes the entire object graph.

## Consistency Guard
- Context refreshed for this example; no data from other examples was retained.
- All object IDs, tenant IDs, and field names are consistent within this folder only.

## Pattern Coverage
- Primary: Pattern 1.10 — Cross-service identity propagation drift (BOLA)
