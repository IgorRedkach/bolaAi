## Analysis reasoning

I reviewed the MetroPulse Traffic Orchestration v3.3.0 architecture specification, GraphQL schema, and HAR trace.

1. **Primary attack vector is `listIntersections` with client-supplied `tenantId`**: the HAR request shows `listIntersections(tenantId: "tenant-0c3e")` from a JWT carrying `tenant-b0b0`. Section 5.0 is explicit: "The resolver trusts the client-supplied `tenantId` instead of extracting it from the JWT." This is Pattern 1.5 (client-controlled tenant override), not merely a missing filter — the resolver actively uses the attacker-supplied tenant ID as the query scope. The existing expected_response.md incorrectly called the attack vector `getResource` — this is wrong. The HAR shows `listIntersections`.

2. **Schema field corrections required**: the original expected_response.md used generic `resourceId`, `getResource`, `bulkResourceLookup` — none of these field names exist in the GQL-0004 schema. The correct names are `nodeId`, `getIntersection`, `bulkIntersectionLookup`. All reproduction steps were referencing non-existent API fields.

3. **Physical safety impact is the distinguishing factor**: unlike financial or healthcare BOLA, intersection data includes `commands: [Command!]`. A successful read of cross-tenant intersection topology enables an informed `updateIntersection` follow-on attack — issuing unauthorized traffic signal commands. This creates direct public safety risk (collisions, emergency vehicle access disruption).

4. **Three independent attack paths**: `listIntersections` (HAR confirmed, Pattern 1.5), `getIntersection` (RISK-GQL-004 documented, Pattern 1.1), and `bulkIntersectionLookup` (section 4.0 documented, Pattern 1.9). Each must be remediated independently as they are distinct resolver paths.

5. **Redis cache without tenant dimension**: `nodeId`-only cache key means that even after resolver fixes, stale cross-tenant intersection data may remain cached.
