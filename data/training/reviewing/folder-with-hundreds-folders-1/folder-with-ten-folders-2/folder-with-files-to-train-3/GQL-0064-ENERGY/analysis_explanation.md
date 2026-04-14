# Analysis Explanation
**System analysed:** PowerGrid Customer Billing API — GQL-0064 (Energy / Utilities / Smart Grid)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 10.1 (ID swap in own request — single-user). User substitutes own meterId with victim's.
2. §4.0 RISK-GQL-064: `getMeter` fetches by `meterId` only — no tenantId match.
3. Domain types: `Meter`, `meterId`, `getMeter`, `bulkMeterLookup` (from schema §3.0 and HAR).
4. HAR: `bulkMeterLookup(["M-2064","M-1064","M-3064"])` from `tenant-8862`. Response `tenant-4e51`: `CONFIDENTIAL-88624e51`. `x-request-id: req-88624e51`.
5. Pattern 10.1 angle: single attacker with one valid token swaps their known meterId for victim's IDs — no privilege change required.

## Consistency Guard
Tenant IDs: `tenant-8862`, `tenant-4e51`. Meters: `M-2064`, `M-1064`, `M-3064`. ownerId: `other-user-88624e51`. Leaked: `CONFIDENTIAL-88624e51`. Request: `req-88624e51`. All from this folder only.
