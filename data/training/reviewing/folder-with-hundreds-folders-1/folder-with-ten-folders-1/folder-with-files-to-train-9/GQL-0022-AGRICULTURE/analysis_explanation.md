## Analysis reasoning

1. **HAR shows `updateResource` write as primary**: HAR is `updateResource(id: "R-2022", input: {status: "approved", ownerId: "attacker-788421de"})`. The original expected_response.md ignored this and started with `getResource` single-ID.

2. **Pattern 10.5 (Draft/Non-Published Resource Access) has two phases**: (a) discovery — enumerate draft resources via `listResources(status: "draft", tenantId: "...")` to find unpublished resources; (b) exploitation — read or modify those resources. The HAR demonstrates the exploitation phase directly (write + status promotion). The discovery phase is added via `listResources(status: "draft")` to show the complete Pattern 10.5 attack chain.

3. **Status promotion (`draft` → `approved`) is uniquely dangerous in agriculture/IoT**: the `status` field in a precision farming platform with MQTT IoT connections is not just metadata — transitioning a resource from `draft` to `approved` may trigger IoT actions (activating sensor configurations, scheduling irrigation commands, approving pesticide applications). Unauthorized status promotion by a competitor could interfere with another operator's crop management.

4. **Draft resources contain the most sensitive proprietary data**: unreleased crop prediction models, pre-season field plans, and pending chemical schedules are the most strategically valuable data a farming operator has. Pattern 10.5 specifically targets this pre-publication content.

5. **Bulk lookup confirmed, not conditional**: section 4.0 documents `bulkResourceLookup` lacking per-ID filter.

6. **Introspection removed**: not documented in sections 4.0 or 5.0.

7. **HAR response/request mismatch**: request is `updateResource` mutation but response is `getResource`. Same synthetic artifact. Confirmed signal: `tenantId: tenant-21de` with HTTP 200.
