## Analysis reasoning

I reviewed the Horizon Social Graph API v7.1.0 architecture specification, Hasura/Node.js resolver code, Neo4j schema, and HAR trace.

1. **Traversal bypass root cause**: the Cypher query in `resolveUserGroups` is `MATCH (u:User {id: $friendId})-[:MEMBER_OF]->(g:Group) RETURN g` — no `WHERE g.is_private = false`. This means all groups the friend belongs to are returned, including private ones. The attacker is authorized to view User B's profile (FRIENDS_WITH relationship), so the top-level `user` resolver passes. Once the `groups` field returns a private group node, the attacker has the group ID.

2. **`ChatMessages` membership check defeated**: section 4.0 states "The `ChatMessages` field resolver was implemented lazily, and it only checks if the requesting user is a member of the group." The attacker (User A) is NOT a member of `grp-trade-secrets-771`. But the HAR shows messages were returned. Section 4.1 explains: "the authorization context (which should have been the friend's authorization, not the attacker's) was improperly propagated or checked." The resolver assumes the group node was legitimately accessible, so the membership check fails to apply the attacker's actual identity correctly — or the check is bypassed because the request is routed through the friend's authorized context.

3. **HAR node count as evidence**: `x-resolver-nodes: User, Group, Message: 12` confirms three resolver types executed: the `User` resolver (1), the `Group` resolver (1 group returned), and the `Message` resolver (12 messages resolved — `limit: 10` requested). The response contains 3 message contents. The `isPrivate: true` field in the group response explicitly confirms the attacker traversed a private group.

4. **Confidential content sensitivity**: the messages contain an M&A acquisition target (`project code: ORION`), an instruction to avoid paper trails ("do not share this via email"), and a RESTRICTED-tagged memo. In a corporate social platform context, this is material non-public information (MNPI) — exposure could violate securities regulations in addition to the platform's privacy policy.

5. **Hasura "select all" default**: section 3.2 documents the root configuration failure — "Hasura engine was configured with a default 'select all fields' permission for the `User` object." This is the upstream configuration gap that allowed the traversal. Hasura's row-level permissions can enforce privacy constraints at the graph query level — they were not configured for the `groups` relationship.
