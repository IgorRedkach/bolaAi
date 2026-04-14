## System

- System: ConsumerProfile GraphQL API v4.0.0
- Domain: E-COMMERCE / CUSTOMER RELATIONSHIP MANAGEMENT (CRM) / IDENTITY
- Risk ID: RISK-GRPH-001

## Findings

### 1. GraphQL Mass Assignment — Privilege Escalation via Injected `role: ADMIN` in Mutation Input (Pattern 9.1 + Pattern 1.12)

The `updateUserProfile` mutation resolver (`userResolver.js`, section 6.1) spreads the entire client-supplied `input` object directly into the Mongoose `$set` update:

```javascript
const updatedUser = await User.findByIdAndUpdate(
    userId,
    { $set: { ...input } },  // THE CRITICAL FLAW: Untrusted spread operator
    { new: true, runValidators: true }
);
```

The GraphQL schema exposes only benign fields in `UpdateUserInput` (`displayName`, `shippingAddress`). However, the resolver imposes no allowlist — any field passed in `input` is forwarded to MongoDB. The Mongoose schema is configured with `{ strict: false }` (RISK-GRPH-001), which causes the ORM to accept and write any field, including fields not defined in the schema. The `role` field is defined in the UserSchema (`enum: ['CUSTOMER', 'SUPPORT', 'ADMIN']`) and is writable via `$set` without any role-level guard.

**HAR evidence**: POST `https://api.consumer-profile.com/graphql` with JWT `sub: "usr_99182A"`, `role: "CUSTOMER"`. Mutation body includes `role: ADMIN` injected into the input object alongside `displayName`. Response: HTTP 200 OK, `{"data": {"updateUserProfile": {"id": "usr_99182A", "displayName": "Attacker-Admin", "role": "ADMIN"}}}`. The response explicitly reflects `"role": "ADMIN"` — confirming the MongoDB document was updated. `usr_99182A` now has `ADMIN` privileges across the entire e-commerce platform.

## Evidence

- **HAR trace**: JWT `role: "CUSTOMER"` → mutation with `role: ADMIN` in input → response confirms `"role": "ADMIN"`. Single request, instant privilege escalation.
- **Resolver code** (section 6.1): `{ $set: { ...input } }` — no field filtering, no allowlist.
- **Mongoose schema** (section 5.0): `{ strict: false }` annotation explicitly marked as the flaw (RISK-GRPH-001); `role` field defined with enum `['CUSTOMER', 'SUPPORT', 'ADMIN']` — writable via `$set`.
- **GraphQL schema** (section 7.1): `UpdateUserInput` only declares `displayName` and `shippingAddress` — `role` is absent from the schema type, but the resolver does not enforce the schema definition as an allowlist.
- **Architecture** (section 3.2): resolver is responsible for ensuring the user "only attempts to update fields appropriate for their current role" — this is not enforced in the implementation.

## Reproduction

```http
POST /graphql HTTP/2.0
Host: api.consumer-profile.com
Authorization: Bearer <JWT_sub=usr_99182A, role=CUSTOMER>
Content-Type: application/json

{
  "query": "mutation PrivilegeEscalation { updateUserProfile(input: { displayName: \"Attacker-Admin\", role: ADMIN }) { id displayName role } }"
}
```

Expected secure outcome: GraphQL error — `role` is not a permitted field in `UpdateUserInput`, or resolver rejects any input key not in the explicit allowlist.  
Observed vulnerable outcome: HTTP 200 OK, `{"data": {"updateUserProfile": {"id": "usr_99182A", "role": "ADMIN"}}}` — CUSTOMER-role user escalated to ADMIN in a single mutation.

## Remediation

- **Use an explicit field allowlist in the resolver** (RISK-GRPH-001): replace `{ $set: { ...input } }` with an explicit pick: `{ $set: { displayName: input.displayName, shippingAddress: input.shippingAddress } }`. Never spread untrusted user input directly into database update operations.
- **Remove `{ strict: false }` from the Mongoose schema**: set `{ strict: true }` (the default) so the ORM rejects unrecognized fields at the model layer as a defence-in-depth measure.
- **Add a runtime field blocklist/allowlist at the resolver before the ORM call**: validate `Object.keys(input)` against the permitted set and throw a GraphQL `UserInputError` if any unauthorized field is present.
- **Do not return sensitive fields in mutation responses**: the `role` and `isVerified` fields must be excluded from the `updateUserProfile` response type — this prevents attackers from confirming privilege escalation via the mutation response.
