## System

- System: Horizon Social Graph API v7.1.0
- Domain: SOCIAL MEDIA / IDENTITY GRAPH
- Risk ID: RISK-GRPH-702

## Findings

### 1. GraphQL Resolver Traversal — `User.groups` Edge Ignores `Group.is_private` (Pattern 5.2)

The Node.js `resolveUserGroups` resolver (section 6.2) queries the Neo4j graph for all groups the friend belongs to without filtering on `is_private`:

```javascript
// VULNERABILITY 5.2: Fails to check Group privacy status before returning the edge.
const groups = await db.query(
    `MATCH (u:User {id: $friendId})-[:MEMBER_OF]->(g:Group) RETURN g LIMIT $limit`,
    { friendId, limit: args.limit }
);
// FLAW: No filtering based on g.is_private is performed here.
return groups.map(group => new Group(group));
```

The attacker is authorized to view User B's public profile via `user(id: "usr-victim-001")` (they are `FRIENDS_WITH`). The `groups` field on the `User` type is traversable without a privacy check (section 3.2, RISK-GRPH-702). Once the attacker has a `Group` node, they query `messages` on it — the `ChatMessages` resolver checks if the requesting user is a member, but because the group node was obtained through a bypass (not through a verified membership path), this check is defeated.

**HAR evidence**: POST `https://api.horizon-social.com/graphql`. JWT: `sub: usr-attacker-A1`. Query traverses `user(id: "usr-victim-001") → groups(limit: 1) → messages(limit: 10)`. Response: HTTP 200 OK. Response header `x-resolver-nodes: User, Group, Message: 12` — 12 nodes resolved including Group and Message nodes. Response body includes `"isPrivate": true` for group `grp-trade-secrets-771` and three message contents: corporate acquisition plan (`project code: ORION`), instruction to avoid email, and `"internal memo is tagged RESTRICTED"`.

## Evidence

- **HAR trace**: attacker JWT → `usr-victim-001` → `groups` traversal → private group `grp-trade-secrets-771` (`isPrivate: true`) → 3 restricted board meeting messages returned. HTTP 200 OK.
- **Node.js resolver** (section 6.2): Cypher query `MATCH (u:User)-[:MEMBER_OF]->(g:Group) RETURN g` with no `WHERE g.is_private = false` filter — all groups returned regardless of privacy.
- **GraphQL schema** (section 6.1): `User.groups` resolver note: "FLAW: This resolver allows traversal to a Group object regardless of Group.is_private."
- **Architecture** (sections 2.2 + 3.2 + RISK-GRPH-702): Hasura configured with "select all fields" default for `User`, trusting downstream resolvers; `groups` relationship traversal does not apply privacy filter; `ChatMessages` resolver only checks membership (defeated by traversal).

## Reproduction

```http
POST /graphql HTTP/2.0
Host: api.horizon-social.com
Authorization: Bearer <USER_A_JWT>
Content-Type: application/json

{"query": "query StealPrivateMessages { user(id: \"usr-victim-001\") { id name groups(limit: 1) { id name isPrivate messages(limit: 10) { content timestamp } } } }"}
```

`usr-victim-001` must be a friend of the attacker (FRIENDS_WITH relationship exists) and must be a member of a private group.

Expected secure outcome: `groups` returns only public groups (`is_private = false`), or HTTP 200 with `groups: []` for traversal blocked by privacy filter.  
Observed vulnerable outcome: HTTP 200 OK, private group `grp-trade-secrets-771` (`isPrivate: true`) and its confidential messages returned.

## Remediation

- **Add `is_private = false` filter to the `resolveUserGroups` Cypher query** (RISK-GRPH-702): change to `MATCH (u:User {id: $friendId})-[:MEMBER_OF]->(g:Group) WHERE g.is_private = false RETURN g LIMIT $limit` — only public groups are traversable from a friend's profile.
- **Re-verify membership in the `messages` resolver using the *requesting user's* identity**: check `MATCH (u:User {id: $requestingUserId})-[:MEMBER_OF]->(g:Group {id: $groupId})` before returning messages — deny if no membership relationship exists.
- **Configure Hasura row-level permissions to enforce `is_private` at the graph traversal layer**: use Hasura's permission system to add a row-level condition on the `groups` relationship: `{ "is_private": { "_eq": false } }` — this prevents the resolver from returning private groups regardless of how the traversal was initiated.
- **Avoid "select all fields" defaults on nodes with relationship edges to private data**: audit the Hasura configuration and restrict `User.groups` to require explicit membership check in the permission rule.
