# IoT device management API (internal v2)

API keys per organization. **No statement that a caller may only access devices in their org.**

REST only — **no GraphQL.**

## Endpoints

- `GET /iot/v2/devices/{deviceId}/telemetry` — Last 24h telemetry for a device.
- `POST /iot/v2/devices/bulk/commands` — Body `{ "deviceIds": ["d-1","d-2"], "command": "reboot" }`. Sends command to multiple devices; **does not state** the caller must own or manage those devices.
- `GET /iot/v2/orgs/{orgId}/devices` — List devices in org. No mention of org-scoping per caller.
