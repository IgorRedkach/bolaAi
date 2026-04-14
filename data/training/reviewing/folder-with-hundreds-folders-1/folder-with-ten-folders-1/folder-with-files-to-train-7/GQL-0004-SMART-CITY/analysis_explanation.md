## Analysis reasoning

I reviewed the MetroPulse Traffic Orchestration v3.3.0 architecture, GraphQL schema, and HAR trace.

1. **Wrong field names in original**: the original used `resourceId`, `getResource`, `bulkResourceLookup`, `R-1004` — none of which exist in this schema. The correct names are `nodeId`, `getIntersection`, `bulkIntersectionLookup`, `N-1004`. This is the same error as in train-6/GQL-0004.

2. **Primary attack vector is `listIntersections` tenant override**: the HAR shows `listIntersections(tenantId: "tenant-0c3e")`, not a single-ID GET. Section 5.0 documents the specific vulnerability: client-supplied `tenantId` trusted over JWT.

3. **Safety impact distinguishes this from financial BOLA**: the `commands: [Command!]` field on `Intersection` means enumerated intersection topology enables physical-world follow-on attacks — unauthorized traffic signal commands. This is critical infrastructure.

4. **Identical to train-6/GQL-0004**: same system, same tenants, same HAR. The quality issues found and fixed in train-6 apply identically here.
