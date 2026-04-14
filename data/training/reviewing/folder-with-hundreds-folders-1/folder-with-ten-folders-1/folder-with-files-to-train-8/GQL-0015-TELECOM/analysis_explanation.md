## Analysis reasoning

1. **HAR shows `updateResource` write mutation as primary attack**: HAR request is `updateResource(id: "R-2015", input: {status: "approved", ownerId: "attacker-86e1b85a"})` from `tenant-86e1`. The original expected_response.md completely ignored this and started with a `getResource` read step. The HAR-evidenced write mutation must be primary.

2. **Pattern 5.1 (Authorization-bypass injection) mechanism explained**: the resolver validates the JWT (authentication passes) but uses the client-supplied `resourceId` to fetch the object without checking `WHERE tenant_id = jwt.tenantId`. By injecting a cross-tenant `resourceId`, the authorization context for that object is bypassed. This is the injection aspect — the authorization decision is poisoned by the injected ID value.

3. **5G Core context amplifies impact**: SpectreNet Policy Control is a 5G PCF (Policy Control Function). `Resource` objects represent network policy rules that control QoS, traffic prioritization, and subscriber service levels. An attacker from MNO-A can approve MNO-B's pending policy deployments, potentially degrading competing operators' network performance or taking ownership of their 5G slice configurations.

4. **`ownerId` transfer is a distinct secondary harm**: the mutation includes `ownerId: "attacker-86e1b85a"` in the input. If accepted, this gives the attacker nominal control over another operator's 5G policy resource, which could affect incident response and change management processes.

5. **Bulk lookup confirmed, not conditional**: section 4.0 explicitly documents `bulkResourceLookup` lacking per-ID ownership filtering.

6. **Introspection removed**: not documented in sections 4.0 or 5.0.

7. **Redis cache added**: section 2.0 documents `resourceId`-only cache key.

8. **HAR response/request mismatch**: request is `updateResource` mutation but response is structured as `getResource`. Same synthetic artifact pattern. The confirmed signal is `tenantId: tenant-b85a` in the response with HTTP 200.
