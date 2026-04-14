## Analysis reasoning

1. **HAR shows `listResources` tenant override as primary**: HAR request is `listResources(tenantId: "tenant-151b")` from `tenant-2fef`. The original expected_response.md started with `getResource` single-ID which doesn't match.

2. **Pattern 10.1 (Single-User ID Swap) defines the attack simplicity**: section 5.0 is explicit — "a single authenticated user substitutes their own valid `resourceId` with a victim's `resourceId`. With one token, data belonging to another user is accessible." The training signal is that no special attack infrastructure is needed — one valid token and one string substitution. The original expected_response.md didn't distinguish this from the generic BOLA description — it should emphasize the "single user, single token, one change" nature.

3. **Two demonstration paths needed**: (a) `listResources` tenant override (HAR evidence — gets ALL records for the target tenant) and (b) `getResource` single-ID swap (Pattern 10.1 canonical — gets one specific record with ID substitution). Both are equally important training signals.

4. **PCI DSS context elevates severity**: PayBridge is explicitly "PCI DSS + REST + Webhook callbacks." Transaction records and payment method tokens in a PCI-scoped platform are Cardholder Data (CHD). Cross-tenant CHD access is a reportable PCI DSS breach, requiring incident notification to card brands and acquiring banks.

5. **Bulk lookup confirmed, not conditional**: section 4.0 documents `bulkResourceLookup` lacking per-ID filter.

6. **Introspection removed**: not documented in sections 4.0 or 5.0.

7. **Redis cache added**: section 2.0 documents `resourceId`-only cache key.
