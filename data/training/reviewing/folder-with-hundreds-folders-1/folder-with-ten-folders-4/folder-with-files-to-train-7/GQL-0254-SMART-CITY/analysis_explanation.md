# Analysis Explanation

**Folder:** GQL-0254-SMART-CITY
**Context source:** This folder's context.txt only. No other example was consulted.

---

## Step-by-step Analysis

### 1. Architecture Review (§2.0)
MetroPulse Traffic Orchestration (v4.4.0) is a smart city / traffic management platform. GraphQL endpoint: `POST https://api.metropulse-traffic-o.example.com/graphql` (Apollo Server). Redis caching keyed by `nodeId` with no tenant dimension — secondary cross-tenant cache risk.

### 2. Schema Inspection (§3.0)
`getIntersection(id: ID!): Intersection` — the argument is a plain caller-supplied node ID. The `Intersection` type includes `nodeId`, `tenantId`, `ownerId`, and `data { sensitiveField, internalNotes }`. No tenant filter is encoded in the query signature. `bulkIntersectionLookup(ids: [ID!]!)` also accepts arbitrary IDs with no per-ID ownership filtering.

### 3. Risk Assessment (§4.0)
RISK-GQL-254: "The `getIntersection` resolver fetches by `nodeId` only. The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`."

### 4. Vulnerability Pattern (§5.0)
Pattern 3.1 — Client-assumed authority (Insecure Design): The system was designed assuming the client would only supply node IDs it owns. No server-side mechanism challenges this assumption. The §5.0 description mentions "client supplies price, role, or status fields" — the specific manifestation in this HAR is simpler (client supplies a cross-tenant `nodeId`), but both are Pattern 3.1: authority is assumed from the client's request rather than verified by the server.

### 5. HAR Trace Analysis (§6.0)
- **Endpoint:** `POST https://api.metropulse-traffic-o.example.com/graphql`
- **Request headers:** `:authority: api.metropulse-traffic-o.example.com`, `authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...`, `x-tenant-id: tenant-f085`, `content-type: application/json`
- **Request body:** `getIntersection(id: "I-2254")` — attacker queries an intersection owned by `tenant-f712`
- **`x-request-id: req-f085f712`** is a **response header** (§6.0 response.headers), NOT a request header. Not included in the curl command.
- **Response:** `tenantId: tenant-f712`, `ownerId: other-user-f085f712`, `sensitiveField: CONFIDENTIAL-f085f712`, `internalNotes: Internal data exposed`

### 6. Smart City / Traffic Management Domain Impact
Traffic intersection records in MetroPulse contain signal phase configurations, incident event logs, sensor readings, and `internalNotes` that may include maintenance override codes or infrastructure-sensitive annotations. Unauthorized read access could expose data enabling physical traffic signal manipulation planning. This represents both a data breach and a potential public safety risk.

### 7. Reproduction Construction
Curl uses: host `api.metropulse-traffic-o.example.com`, JWT from §6.0, `x-tenant-id: tenant-f085`, query with `id: "I-2254"`. `x-request-id` omitted (response header only). No placeholder or cross-example data used.

---

**Consistency Guard:** All details (system `MetroPulse Traffic Orchestration`, version `4.4.0`, host `api.metropulse-traffic-o.example.com`, tenants `tenant-f085`/`tenant-f712`, JWT, `nodeId: I-2254`, `ownerId: other-user-f085f712`, `CONFIDENTIAL-f085f712`, RISK-GQL-254, Pattern 3.1) sourced exclusively from this folder's context.txt.
