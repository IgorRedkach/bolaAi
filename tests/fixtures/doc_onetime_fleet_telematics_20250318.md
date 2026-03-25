# Fleet Telematics Partner API — v1 (internal)

Bearer token required. **Object-level authorization is not documented** for vehicle, driver, or trip IDs.

## REST

- `GET /fleet/v1/vehicles/{vehicleId}/telemetry` — Last 24h GPS + engine data for a vehicle.
- `GET /fleet/v1/drivers/{driverId}/routes` — Assigned routes and stops for a driver.
- `POST /fleet/v1/bulk/location-history` — Body `{ "vehicleIds": ["..."] }`. Returns merged tracks. **Fleet manager role.** No statement that caller may only request vehicles in their fleet.
- `GET /fleet/v1/incidents/{incidentId}` — Safety incident record linked to vehicle/driver.

## GraphQL

- `trip(id: ID!) { id vehicleId driverId waypoints { lat lon ts } }` — Full trip; nested waypoints; **no** documented trip-level auth.

## Deprecated

- `GET /fleet/v0/snapshot/{snapshotId}` — Legacy daily export pointer. Token required; **snapshot ownership** not described.
