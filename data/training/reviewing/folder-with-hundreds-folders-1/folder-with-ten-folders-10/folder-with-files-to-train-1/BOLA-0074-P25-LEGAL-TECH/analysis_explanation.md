## Analysis reasoning

1. **Wrong endpoint and ID format**: the original expected_response.md used `/api/v1/resources/RES-*` — the context specifies `/api/v3/nodes/NOD-*` and the HAR uses `NOD-2074`. All corrected.

2. **Pattern 2.5 (Critical Infrastructure Interface Exposure) requires framing the `nodes` endpoint as critical infrastructure**: in a legal eDiscovery platform, "nodes" are not generic resources — they represent eDiscovery processing units, litigation repository nodes, or evidence containers. These are critical legal infrastructure components. The original response treated this as a generic BOLA without explaining the "critical infrastructure" aspect.

3. **Write escalation (PATCH/DELETE) is mandatory for Pattern 2.5**: section 4.0 explicitly lists GET/PATCH/DELETE. Modifying or deleting another law firm's eDiscovery node has uniquely severe consequences — potential evidence tampering, obstruction of justice, and contempt of court. These consequences should be in the reproduction steps.

4. **RISK-25-074 references the same root cause pattern**: handler written before tenant isolation policy, remediation blocked pending DB migration #DB-174. This is concrete, traceable evidence for the documented risk.

5. **"No specific variant documented" was wrong**: Pattern 2.5 specifically requires demonstrating write access to critical interface — the PATCH step shows this.
