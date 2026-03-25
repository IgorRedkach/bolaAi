# HealthFirst Claims Processing — API Documentation (v2)

Authentication: JWT bearer tokens issued per user. Users belong to one plan sponsor (employer).

## REST Endpoints

- `GET /claims/v2/submissions/{submissionId}` — Returns full claim details: member name, diagnosis codes (ICD-10), provider NPI, billed amount, adjudication status, and internal adjuster notes. Requires valid token. **No statement** that the caller must be the submitting member or the assigned adjuster.

- `GET /claims/v2/members/{memberId}/history` — Returns all claims for a member: dates, amounts, statuses, diagnosis summaries. **Does not verify** the caller is that member or their authorized representative.

- `POST /claims/v2/batch/adjudicate` — Body `{ "claimIds": ["clm-001", "clm-002"], "decision": "approved" }`. Adjudicates multiple claims. **Does not verify** the caller is the assigned adjuster for every claim in the batch.

## GraphQL Endpoint

`POST /claims/v2/graphql`

```graphql
type Claim {
  id: ID!
  memberId: ID!
  diagnosisCodes: [String!]!
  billedAmount: Float!
  status: String!
}

type Mutation {
  approveClaim(claimId: ID!): Claim
  denyClaim(claimId: ID!, reason: String!): Claim
}

type Query {
  claim(id: ID!): Claim
  memberClaims(memberId: ID!): [Claim!]!
}
```

No resolver-level ownership checks are documented. The schema does not state that `approveClaim` verifies the caller is an assigned adjuster, or that `claim(id)` checks the caller is the member.

## Roles

- **Member** — submits claims, views own history.
- **Adjuster** — reviews and adjudicates assigned claims.
- **Plan Admin** — full access to plan's claims.

Role enforcement beyond "valid JWT required" is not described.
