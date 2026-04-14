## Analysis reasoning

1. **HAR shows `listResources` tenant override as the primary attack**: HAR request is `listResources(tenantId: "tenant-a5a7")` from JWT `tenant-1c38`. The original expected_response.md started with a `getResource` single-ID substitution step that did not match the HAR evidence. The HAR is the strongest evidence signal — the primary reproduction must lead with that attack.

2. **Pattern 1.8 (Sequential IDs) is a distinct complementary finding**: the `R-NNNN` naming convention (R-1007, R-2007) means IDs are predictable and incrementable. An attacker who cannot exploit `listResources` can still enumerate all resources by iterating IDs. This is the core of Pattern 1.8 and should be demonstrated with a sequential ID substitution step (Step 3).

3. **Introspection step removed**: introspection is not documented as a risk in section 4.0 or 5.0. Adding it as a reproduction step introduces unverified speculation not grounded in the context.

4. **Bulk lookup is confirmed, not conditional**: section 4.0 explicitly states `bulkResourceLookup` lacks per-ID ownership filtering — this is a documented architectural note, not a hypothesis.

5. **IIoT/manufacturing impact framing is important**: `Resource` objects in a "Robotics Fleet" with `items: [Item!]` represent industrial assets. Cross-tenant access reveals manufacturing process parameters, robot configurations, or OPC-UA node mappings. This framing makes the vulnerability training signal more specific to the domain.

6. **HAR response body type mismatch is synthetic artifact**: request is `listResources` query but response body is formatted as `getResource`. Same synthetic artifact pattern observed throughout this training set. The confirmed signal is the `tenantId: tenant-a5a7` in the response body with HTTP 200 status.
