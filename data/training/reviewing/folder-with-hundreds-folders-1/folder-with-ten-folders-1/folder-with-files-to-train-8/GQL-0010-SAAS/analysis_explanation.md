## Analysis reasoning

1. **HAR matches `getProject` single-ID substitution**: unlike most examples where the HAR was mismatched with the primary reproduction step, here the HAR shows `getProject(id: "P-2010")` from `tenant-2c0d` returning `tenant-673b` data — which aligns with the original Step 2. This is kept as the primary step.

2. **Mass assignment attack was entirely missing from the original expected_response.md**: Pattern 1.12 is explicitly "Mass assignment via object fields." Section 5.0 states: `updateProject` accepts `ownerId` and `tenantId` as writable fields in the input. The original response never demonstrated the mass assignment attack — it only showed a read BOLA. This is the most significant correction: Step 3 must demonstrate an `updateProject` mutation with client-supplied `ownerId` and `tenantId` to show the full Pattern 1.12 exploitation. This is more dangerous than simple read access — it enables permanent ownership transfer.

3. **Distinction between BOLA (read) and Mass Assignment (write+ownership)**: the HAR demonstrates a cross-tenant read (BOLA). Pattern 1.12 adds the ownership transfer dimension. The training signal is: first confirm the read works, then escalate to ownership transfer via the mass assignment flaw.

4. **Bulk lookup confirmed, not conditional**: section 4.0 explicitly documents `bulkProjectLookup` lacking per-ID ownership filtering.

5. **Introspection removed**: not documented in sections 4.0 or 5.0.

6. **Redis cache added**: section 2.0 documents `projectId`-only cache key. A project with `sensitiveField` (business strategy, roadmap, client data) cached without a tenant dimension could serve cross-tenant.
