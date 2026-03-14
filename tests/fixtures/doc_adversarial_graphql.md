# DataHub GraphQL API

## Overview
DataHub provides a unified GraphQL API for documents, users, and projects.

## Endpoint
- **POST /graphql** — All operations use this single endpoint.

## Schema (excerpt)
- **Query:** `user(id: ID!): User` — Returns user profile by ID.
- **Query:** `document(id: ID!): Document` — Returns document metadata and content.
- **Query:** `me: User` — Returns the current authenticated user. User has nested field `documents: [Document]`.
- **Mutation:** `deleteDocument(id: ID!): Boolean` — Deletes a document by ID.
- **Mutation:** `updateDocument(id: ID!, input: DocumentInput!): Document` — Updates document fields.

## Authentication
- Bearer token required. No further details on per-object authorization.

## Notes
- Documentation does not state whether `user(id)` or `document(id)` resolvers verify that the caller is allowed to access that object.
- Nested `me { documents }` may or may not filter by owner; not specified.
