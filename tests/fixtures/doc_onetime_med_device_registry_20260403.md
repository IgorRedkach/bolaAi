# Medical Device Registry API — Developer Reference v2.1

## Overview

The Medical Device Registry (MDR) API provides programmatic access to the Federal Medical Device Database.
Manufacturers, distributors, and regulatory staff use this API to register devices, submit certification
results, track recall notices, and access audit trails.

**Base URL:** `https://mdr.gov/api/v1`

**Authentication:** All endpoints require a Bearer token obtained via `POST /auth/token`. Tokens are
scoped to a user identity and optionally a manufacturer organization. Tokens do not include embedded
role claims; role checks rely on server-side lookup by user ID at request time.

---

## Endpoints

### GET /api/v1/devices/{deviceId}

Retrieve the full device registration record by its unique device identifier.

**Request:**
```
GET /api/v1/devices/{deviceId}
Authorization: Bearer <token>
```

**Path parameters:**
- `deviceId` (string, required): The unique device identifier (e.g., `DEV-20240-XR9`)

**Response (200 OK):**
```json
{
  "deviceId": "DEV-20240-XR9",
  "name": "ClearScan X9 Imaging System",
  "manufacturerId": "MFR-442",
  "category": "diagnostic-imaging",
  "certificationStatus": "approved",
  "submittedBy": "user-882",
  "createdAt": "2024-03-15T10:30:00Z"
}
```

**Notes:** Requires valid token. Returns device data including the `manufacturerId` of the owning
organization. The documentation does not state that the response is filtered to the requesting
user's manufacturer.

---

### GET /api/v1/manufacturers/{manufacturerId}/devices

List all registered devices belonging to a manufacturer organization.

**Request:**
```
GET /api/v1/manufacturers/{manufacturerId}/devices
Authorization: Bearer <token>
```

**Path parameters:**
- `manufacturerId` (string, required): The manufacturer organization identifier

**Query parameters:**
- `status` (string, optional): Filter by certification status (`approved`, `pending`, `recalled`)
- `page` (integer, optional): Page number (default 1)

**Response (200 OK):**
```json
{
  "manufacturerId": "MFR-442",
  "devices": [
    { "deviceId": "DEV-20240-XR9", "name": "ClearScan X9", "status": "approved" },
    { "deviceId": "DEV-20241-XR10", "name": "ClearScan X10", "status": "pending" }
  ],
  "total": 2
}
```

**Notes:** Requires valid token. Returns all devices for the given `manufacturerId` path parameter.
No documentation states that the response is restricted to the authenticated user's own manufacturer.

---

### PUT /api/v1/devices/{deviceId}/recalls

Submit or update a recall notice for a registered device. Recall submission changes device status
to `recalled` and triggers downstream notifications.

**Request:**
```
PUT /api/v1/devices/{deviceId}/recalls
Authorization: Bearer <token>
Content-Type: application/json
```

**Request body:**
```json
{
  "reason": "Calibration drift detected in power regulation module",
  "severity": "class-II",
  "recalledBy": "user-882",
  "affectedBatch": "BATCH-2024-09"
}
```

**Path parameters:**
- `deviceId` (string, required): The device to recall

**Response (200 OK):**
```json
{
  "recallId": "RCL-20240-4421",
  "deviceId": "DEV-20240-XR9",
  "status": "recall-initiated",
  "recalledBy": "user-882"
}
```

**Notes:** Requires valid token. The `recalledBy` field is accepted from the client request body
and stored as-is. The documentation does not describe server-side verification that the submitting
user holds a `recall-manager` role or that the user belongs to the device's owning manufacturer.

---

### POST /api/v1/devices/{deviceId}/certifications

Submit a new certification result (test report, conformance declaration) for a device.

**Request:**
```
POST /api/v1/devices/{deviceId}/certifications
Authorization: Bearer <token>
Content-Type: application/json
```

**Request body:**
```json
{
  "certificationBody": "ISO-13485-Lab-7",
  "result": "pass",
  "reportDate": "2024-11-01",
  "submittingManufacturerId": "MFR-442",
  "documentRef": "CERT-DOC-2024-991"
}
```

**Path parameters:**
- `deviceId` (string, required): The device receiving the certification

**Response (201 Created):**
```json
{
  "certificationId": "CERT-20241-7721",
  "deviceId": "DEV-20240-XR9",
  "status": "pending-review"
}
```

**Notes:** The `submittingManufacturerId` field in the request body is accepted from the client.
Documentation does not state that the server verifies this field matches the device's registered
`manufacturerId` or the authenticated user's organization.

---

### GET /api/v1/audit-logs/{logId}

Retrieve a specific audit log entry. Audit logs record all state changes to device records,
recall notices, and certification submissions.

**Request:**
```
GET /api/v1/audit-logs/{logId}
Authorization: Bearer <token>
```

**Path parameters:**
- `logId` (string, required): The audit log entry identifier

**Response (200 OK):**
```json
{
  "logId": "LOG-20240-99312",
  "eventType": "recall-initiated",
  "actorUserId": "user-882",
  "targetDeviceId": "DEV-20240-XR9",
  "timestamp": "2024-11-01T14:20:00Z",
  "previousStatus": "approved",
  "newStatus": "recalled"
}
```

**Notes:** Requires valid token. The documentation does not restrict this endpoint to
administrative users or to users whose actions appear in the log. Any authenticated user with a
valid token can retrieve any log entry by providing a known or guessed `logId`.

---

### DELETE /api/v1/devices/{deviceId}/certifications/{certificationId}

Remove a certification record from a device.

**Request:**
```
DELETE /api/v1/devices/{deviceId}/certifications/{certificationId}
Authorization: Bearer <token>
```

**Response (204 No Content)**

**Notes:** Requires valid token. No documentation states that only the original submitter or
an admin may delete the certification.

---

## Error Responses

| Status | Meaning |
|--------|---------|
| 401 | Missing or invalid token |
| 404 | Resource not found |
| 500 | Internal server error (details may be included in `message` field) |

**Note:** 500 responses may include internal database error messages and stack traces, potentially
exposing internal identifiers and schema details.

---

## Notes

This is a REST-only API. No GraphQL or SOQL endpoints are defined.
