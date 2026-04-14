## Analysis reasoning

1. **HAR shows `updateResource` write as primary**: HAR is `updateResource(id: "R-2024", input: {status: "approved"...})`. The original expected_response.md used `getResource` single-ID as primary.

2. **Pattern 1.2 (Related/Linked Resources) is specifically addressed by `getResourceWithChildren`**: the schema has `getResourceWithChildren(id: ID!): Resource` and `items: [Item!]` relationships. Pattern 1.2 means an attacker exploits the graph relationships — not just the root document but all linked sub-documents and items. This is the canonical Pattern 1.2 attack: access an authorized or cross-tenant root resource, then traverse all its related items. The original expected_response.md never demonstrated this traversal.

3. **Legal eDiscovery context makes document tampering uniquely dangerous**: `status: "approved"` in an eDiscovery system could mean approving a document for production to opposing counsel, removing a privilege designation, or marking evidence for submission. Unauthorized document status changes in litigation can be grounds for sanctions, evidence tampering claims, or waiver of attorney-client privilege.

4. **`auditLog: [AuditEntry!]` exposure is particularly concerning in legal context**: reading another firm's document audit log reveals which attorneys reviewed which documents and when — revealing their case strategy and work product.

5. **Bulk lookup confirmed, not conditional**: section 4.0 documents `bulkResourceLookup` lacking per-ID filter.

6. **Redis cache with legal documents**: legal documents cached without tenant dimension could serve privileged content from one law firm's matters to another. This is a strict-liability attorney-client privilege violation if it occurs in production.
