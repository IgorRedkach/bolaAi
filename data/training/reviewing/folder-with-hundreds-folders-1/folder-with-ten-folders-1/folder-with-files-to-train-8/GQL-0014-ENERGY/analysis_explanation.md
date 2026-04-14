## Analysis reasoning

1. **HAR matches `getMeter` single-ID read**: HAR is `getMeter(id: "M-2014")` from `tenant-3061` returning `tenant-d34b` — kept as primary step.

2. **Pattern 4.2 (Persistence Poisoning via Lifecycle Actions) was entirely missing**: the original expected_response.md only demonstrated a read BOLA. Pattern 4.2 specifically concerns integrity attacks through write lifecycle operations. In a smart grid billing platform, `updateMeter` and `deleteMeter` share the same missing `tenant_id` check as `getMeter` — if the read BOLA works, the write and delete mutations also work cross-tenant. The training signal for Pattern 4.2 must demonstrate these write-path attacks.

3. **Smart grid / energy domain makes persistence poisoning especially dangerous**: meter readings are SCADA-bridged billing records used for energy settlement between utilities and regulators. Falsifying readings (e.g., changing `status` to `"tampered"` or overwriting `internalNotes`) constitutes billing fraud and may trigger regulatory audit failure. Deleting meter records destroys evidence required for energy settlement and grid compliance.

4. **Bulk lookup confirmed, not conditional**: section 4.0 explicitly documents `bulkMeterLookup` lacking per-ID ownership filtering.

5. **Introspection removed**: not documented in sections 4.0 or 5.0.

6. **Redis cache added**: section 2.0 documents `meterId`-only cache key. Cached meter readings without a tenant dimension could result in one utility seeing another's consumption data when a cache hit returns stale cross-tenant data.
