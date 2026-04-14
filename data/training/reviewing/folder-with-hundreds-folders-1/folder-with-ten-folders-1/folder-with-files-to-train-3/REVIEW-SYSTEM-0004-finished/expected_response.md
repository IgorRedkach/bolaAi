## Findings

1. **BOLA via batch/bulk endpoint — tenant isolation missing on `POST /api/v1/telematics/batch-locate`**: the `getBatchLocations` controller extracts `tenant_id` from the JWT but passes the caller-supplied `vehicle_ids` array to `findBulkLocationsbatch()`, which executes `SELECT t FROM VehicleTelemetry t WHERE t.vehicleId IN :vehicleIds` — no `AND t.tenantId = :tenantId` filter. Any vehicle ID included in the request body is returned regardless of tenant ownership. The secure query `findSecureByVehicleId` with tenant binding exists in the same repository but is not used for the batch path.

2. **Competitor fleet real-time GPS location exposed**: a dispatcher authenticated as `org_logistics_alpha` included competitor vehicle `TRK-99882` (belonging to Omega Freight, a different tenant) in the `vehicle_ids` array. The response returned `TRK-99882`'s real-time GPS coordinates (`lat: 41.8781, lon: -87.6298`), speed (105 km/h), and heading (90°) — live route intelligence for a competitor's truck.

## Evidence

- **HAR POST request** (`startedDateTime: 2026-04-08T19:08:14.331Z`, elapsed 185 ms): `POST https://api.freightnode.com/api/v1/telematics/batch-locate`; JWT encodes `sub: dispatcher_01`, `tenant_id: org_logistics_alpha`, `role: dispatcher`; body `{"vehicle_ids": ["TRK-1001", "TRK-1002", "TRK-99882"]}`.
- **HAR response**: HTTP 200 OK, `x-db-query-time-ms: 42`; response includes all three vehicles — `TRK-1001` (lat 34.0522, lon -118.2437, 85 km/h), `TRK-1002` (lat 34.0610, lon -118.2510, 0 km/h), and `TRK-99882` (lat 41.8781, lon -87.6298, 105 km/h, last_updated 19:08:13Z).
- **Tenant mismatch**: `TRK-1001` and `TRK-1002` belong to `org_logistics_alpha` (the caller's tenant). `TRK-99882` has a vehicle ID pattern and cross-country location suggesting a different tenant fleet — returned in the same batch response without any ownership check.
- **Flawed controller** (section 6.2): `String userTenantId = (String) principal.getTokenAttributes().get("tenant_id")` — extracted but never used in the query call. `telemetryRepository.findBulkLocationsbatch(request.getVehicleIds())` uses the `IN` query without tenant binding.
- **Correct pattern exists** (section 6.1): `findSecureByVehicleId(@Param("vehicleId") String vehicleId, @Param("tenantId") String tenantId)` applies `AND t.tenantId = :tenantId` — but this method is not called from the batch controller.
- **Schema confirms tenant columns** (section 5.0): both `vehicles` and `vehicle_telemetry` tables have `tenant_id VARCHAR(100) NOT NULL` with dedicated indexes — the data model supports tenant isolation; the enforcement gap is in the application layer.

## Reproduction

Step 1 — send a baseline request with only own-tenant vehicle IDs:

```bash
curl -i -X POST "https://api.freightnode.com/api/v1/telematics/batch-locate" \
  -H "Authorization: Bearer <JWT_dispatcher_01_org_logistics_alpha>" \
  -H "Content-Type: application/json" \
  -d '{"vehicle_ids": ["TRK-1001", "TRK-1002"]}'
```

Expected: HTTP 200, results for `TRK-1001` and `TRK-1002` only.

Step 2 — append a competitor vehicle ID to the batch:

```bash
curl -i -X POST "https://api.freightnode.com/api/v1/telematics/batch-locate" \
  -H "Authorization: Bearer <JWT_dispatcher_01_org_logistics_alpha>" \
  -H "Content-Type: application/json" \
  -d '{"vehicle_ids": ["TRK-1001", "TRK-1002", "TRK-99882"]}'
```

Expected secure outcome: HTTP 200 with results for only `TRK-1001` and `TRK-1002`; `TRK-99882` is omitted or returns a 403/filtering notice — its `tenant_id` does not match the caller's `org_logistics_alpha`.  
Observed vulnerable outcome: HTTP 200, all three vehicles returned including `TRK-99882` with real-time GPS at lat 41.8781, lon -87.6298, speed 105 km/h.

## Remediation

- **Apply tenant filter in `findBulkLocationsbatch`**: change the JPA query to `SELECT t FROM VehicleTelemetry t WHERE t.vehicleId IN :vehicleIds AND t.tenantId = :tenantId` and add `@Param("tenantId") String tenantId` to the method signature. Update the controller to pass `userTenantId` as the second argument.
- **Pre-filter the ID array in the controller**: before calling the repository, validate that every ID in `request.getVehicleIds()` belongs to the calling tenant by querying `vehicles WHERE id IN (...) AND tenant_id = userTenantId`. Reject or strip any IDs that do not match and return an error for the unrecognised IDs.
- **Return a filtered result rather than an error** for unrecognised IDs to avoid enumeration leakage: silently omit IDs not belonging to the tenant rather than returning a 404 that confirms the ID exists.
- **Add integration tests for cross-tenant batch requests**: assert that any batch request containing a foreign tenant's vehicle ID returns only the caller's own vehicles and that the response size does not grow with injected foreign IDs.
