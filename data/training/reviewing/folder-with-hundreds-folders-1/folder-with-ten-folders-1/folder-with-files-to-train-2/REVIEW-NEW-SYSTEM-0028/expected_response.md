## Findings

1. **Mass assignment via unrestricted Django serializer on `PATCH /api/v1/assets/{id}/metadata`**: `AssetMetadataSerializer` uses `fields = '__all__'` and does not include `content_owner_id` in `read_only_fields`, meaning any key present in the PATCH request body is mapped directly to the corresponding `content_assets` column by the ORM. A `CONTENT_EDITOR` (`user_editor_A`) can inject `"content_owner_id": "user_editor_A"` into an otherwise legitimate metadata update and permanently transfer ownership of asset `VID-BLOCKBUSTER` away from its legitimate owner `STUDIO_HOLLYWOOD`.

2. **Write on a security-critical field without ownership check (Pattern 1.6)**: the `partial_update` controller checks only that the caller's role is `CONTENT_EDITOR` or `EXECUTIVE_PRODUCER`, never that the `content_owner_id` field is restricted from the `CONTENT_EDITOR` role. The HAR response body explicitly reflects `"content_owner_id": "user_editor_A"`, confirming the database write succeeded without any ownership-level gate.

3. **Persistence poisoning (Pattern 4.2)**: once committed, the poisoned `content_owner_id` causes the Monetization Engine to remit revenue to `user_editor_A` on every future billing cycle, and the DRM Service derives access controls from the now-corrupted record — silent, compounding financial and IP-theft impact until detected by manual audit.

## Evidence

- **HAR PATCH request** (`startedDateTime: 2026-04-09T17:45:12.045Z`, elapsed 98 ms): `PATCH https://api.streamverse.com/api/v1/assets/VID-BLOCKBUSTER/metadata`; JWT encodes `user_id: user_editor_A`, `role: CONTENT_EDITOR`; body `{"description": "Final cut version. Approved for premium tier.", "content_owner_id": "user_editor_A", "last_audited_by": "user_editor_A"}`.
- **HAR response**: HTTP 200 OK, `x-db-latency-ms: 35`; response body echoes `"content_owner_id": "user_editor_A"` — the ORM committed the injected value. The original owner `STUDIO_HOLLYWOOD` is gone from the record.
- **Serializer root cause** (section 6.2, `AssetMetadataSerializer`): `fields = '__all__'` and `read_only_fields = ['total_views', 'last_updated']` — `content_owner_id` is absent from `read_only_fields`, making it writable by any role that can reach the endpoint (RISK-MEDIA-009, Epic CMM-301 deferred).
- **Controller role check** (section 6.0): `if request.user.role not in ['CONTENT_EDITOR', 'EXECUTIVE_PRODUCER']: return 403` — a `CONTENT_EDITOR` passes unconditionally. No per-field permission check follows.
- **Schema confirms field sensitivity** (section 5.0): `content_owner_id VARCHAR(100) NOT NULL` is annotated `-- Key for Monetization and DRM`, establishing the business-critical nature of this field.

## Reproduction

Step 1 — send a legitimate PATCH with only editor-permitted fields to confirm the endpoint accepts requests from `CONTENT_EDITOR`:

```bash
curl -i -X PATCH "https://api.streamverse.com/api/v1/assets/VID-BLOCKBUSTER/metadata" \
  -H "Authorization: Bearer <JWT_user_editor_A_CONTENT_EDITOR>" \
  -H "Content-Type: application/json" \
  -d '{"description": "Final cut version. Approved for premium tier."}'
```

Expected: HTTP 200, response body reflects updated `description`; `content_owner_id` remains `STUDIO_HOLLYWOOD`.

Step 2 — inject `content_owner_id` in the same PATCH body:

```bash
curl -i -X PATCH "https://api.streamverse.com/api/v1/assets/VID-BLOCKBUSTER/metadata" \
  -H "Authorization: Bearer <JWT_user_editor_A_CONTENT_EDITOR>" \
  -H "Content-Type: application/json" \
  -d '{"description": "Final cut version. Approved for premium tier.", "content_owner_id": "user_editor_A", "last_audited_by": "user_editor_A"}'
```

Expected secure outcome: HTTP 400/403 — `content_owner_id` is read-only for `CONTENT_EDITOR` role; field is stripped or rejected.  
Observed vulnerable outcome: HTTP 200, response body contains `"content_owner_id": "user_editor_A"` — ownership has been silently transferred; subsequent Monetization Engine run remits revenue to `user_editor_A`.

## Remediation

- **Fix the serializer immediately (RISK-MEDIA-009)**: in `AssetMetadataSerializer`, replace `fields = '__all__'` with an explicit allowlist of editor-writable fields (`fields = ['description', 'tags', 'release_date']`) and add `content_owner_id` to `read_only_fields`. This closes mass assignment at the serialization layer regardless of caller role.
- **Add a per-field role check in `partial_update`**: after the role check, explicitly strip any restricted fields from `request.data` if the caller is `CONTENT_EDITOR`: `restricted = {'content_owner_id', 'last_audited_by'}; if request.user.role == 'CONTENT_EDITOR' and restricted & set(request.data.keys()): return Response({"error": "Field not writable by this role."}, status=403)`.
- **Route `content_owner_id` changes to a separate, role-gated endpoint**: per the RBAC table (section 3.1), ownership transfers are an `EXECUTIVE_PRODUCER` function via a dedicated API endpoint — enforce this at the routing layer, not just by convention.
- **Audit existing records**: query `content_assets` for any `content_owner_id` values that match `cmm_users.user_id` with `role = 'CONTENT_EDITOR'` to detect prior ownership injections.
