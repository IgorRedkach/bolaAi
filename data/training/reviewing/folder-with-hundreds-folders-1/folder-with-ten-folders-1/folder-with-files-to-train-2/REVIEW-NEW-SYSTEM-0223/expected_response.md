## Findings

1. **Mass assignment via unrestricted Prisma `data: req.body` on `PATCH /api/v3/configs/{id}`**: the `updateConfiguration` controller passes the entire HTTP request body directly to `prisma.netConfig.update({ data: req.body })` (RISK-NET-121 — DTO replaced with generic interface). A `TIER_1_FIELD_OPS` engineer can inject the administrative fields `owner_id` and `is_locked` alongside legitimate fields (`description`, `version_number`) and the ORM will silently overwrite those security-critical columns in the `net_configs` table.

2. **Post-update RBAC check creates a self-confirming bypass**: the ownership and lock-status check occurs after the update is committed — `if (updateResult.is_locked || updateResult.owner_id !== callingUser)`. By injecting `"owner_id": "eng_low_1004"` and `"is_locked": false`, the attacker ensures that the post-update state satisfies the check (`owner_id` now matches the caller, `is_locked` is now false), so the controller returns 200 instead of 403. The check is evaluated against the corrupted state it just wrote.

## Evidence

- **HAR PATCH request** (`startedDateTime: 2026-04-09T19:35:22.011Z`, elapsed 75 ms): `PATCH https://api.netops.telco/api/v3/configs/cfg_991A`; JWT encodes `sub: eng_low_1004`, `role: TIER_1_FIELD_OPS`; body `{"description": "Temporary override for Tier 1 team debugging.", "owner_id": "eng_low_1004", "is_locked": false, "version_number": 43}`.
- **HAR response**: HTTP 200 OK; `x-db-writes: 2` (confirms two columns were written in addition to the expected fields); body `{"status": "UPDATE_SUCCESS", "message": "Configuration metadata updated successfully."}`.
- **Flawed controller** (section 6.0): `data: req.body` — all keys in the request body are forwarded to Prisma's update, including `owner_id` and `is_locked` which are annotated as restricted in the schema (section 5.0). The RBAC check `if (updateResult.is_locked || updateResult.owner_id !== callingUser)` evaluates the post-update result, not the pre-update state.
- **Schema confirms field restrictions** (section 5.0): `owner_id` is annotated `-- RBAC/Ownership Enforced` and `is_locked` as `-- Security Interlock Flag` — both are explicitly flagged as protected fields requiring TIER_3_CORE_ENG privilege per section 3.2.
- **Two-step consequence**: with `cfg_991A` now owned by `eng_low_1004` and `is_locked: false`, the attacker's subsequent PATCH with actual `config_text` changes will pass the RBAC check — granting write access to the core router configuration that was previously locked by management.

## Reproduction

Step 1 — confirm that accessing `cfg_991A` as `eng_low_1004` without the injection is denied (baseline ownership check):

```bash
curl -i -X PATCH "https://api.netops.telco/api/v3/configs/cfg_991A" \
  -H "Authorization: Bearer <JWT_eng_low_1004_TIER_1_FIELD_OPS>" \
  -H "Content-Type: application/json" \
  -d '{"description": "Routine update attempt"}'
```

Expected secure outcome: HTTP 403 — config is locked and owned by `eng_core_33X`, not `eng_low_1004`.  
(Note: due to the post-update RBAC check flaw, this will return 403 only if `is_locked` remains true from the DB.)

Step 2 — inject `owner_id` and `is_locked` to overwrite the security fields:

```bash
curl -i -X PATCH "https://api.netops.telco/api/v3/configs/cfg_991A" \
  -H "Authorization: Bearer <JWT_eng_low_1004_TIER_1_FIELD_OPS>" \
  -H "Content-Type: application/json" \
  -d '{"description": "Temporary override for Tier 1 team debugging.", "owner_id": "eng_low_1004", "is_locked": false, "version_number": 43}'
```

Expected secure outcome: HTTP 400/403 — `owner_id` and `is_locked` are read-only for `TIER_1_FIELD_OPS`; injected fields are rejected.  
Observed vulnerable outcome: HTTP 200 `{"status": "UPDATE_SUCCESS"}` with `x-db-writes: 2` — ownership transferred to `eng_low_1004`, lock cleared; subsequent config text changes are now authorized.

## Remediation

- **Fix mass assignment immediately (RISK-NET-121)**: replace `data: req.body` with an explicit field allowlist — `data: { description: req.body.description, version_number: req.body.version_number }`. Never pass the raw request body to an ORM update.
- **Move the RBAC check to pre-update state**: read `existingConfig.owner_id` and `existingConfig.is_locked` before calling `prisma.netConfig.update()`. If `is_locked || existingConfig.owner_id !== callingUser`, return 403 immediately without executing the update.
- **Route `owner_id` and `is_locked` changes to a separate, role-gated endpoint**: per section 3.2, these fields require `TIER_3_CORE_ENG`. Create a dedicated `PATCH /api/v3/configs/{id}/admin-fields` endpoint protected by a strict role check, and strip these keys from the general metadata update path.
- **Add a database-level constraint**: use a PostgreSQL row-level security (RLS) policy on `net_configs` that restricts `UPDATE` of `owner_id` and `is_locked` to a specific database role used only by the privileged code path.
