# Analysis Explanation
**Folder:** GQL-0300-PARKING | **Context source:** This folder's context.txt only.
- System: ParkIQ Management API, Parking/Smart City
- Host: `api.parkiq-management-ap.example.com`
- Attacker tenant: `tenant-c506`, victim tenant: `tenant-d195`
- Object type: `Intersection`, ID field: `nodeId`, operation: `getIntersection(id: "I-2300")` — CONSISTENT with response key `getIntersection`
- Response: `ownerId: other-user-c506d195`, `sensitiveField: CONFIDENTIAL-c506d195`
- `x-request-id: req-c506d195` is a server-assigned response header, not a request header
- Redis keyed by `nodeId` only — no tenant dimension (§2.0 cache note)
- Pattern 4.2: Persistence poisoning — attacker reads cross-tenant intersection control data; combined with write access (`updateIntersection`) could poison traffic/parking commands for victim tenant
**Consistency Guard:** All values from this folder's context.txt only.
