# DocVault File API — Developer Reference

## Overview

DocVault provides document and folder management for enterprise customers. API base path: `https://api.docvault.example/files/api`.

## Auth

- OAuth2 Bearer token in `Authorization` header. Scope: `files.read`, `files.write`.
- No documentation of how the backend restricts access to a specific document or folder by identity (e.g. owner, shared-with).

## Endpoints

### Documents

- **GET /files/api/documents/{docId}** — Returns metadata and download URL for the document. Requires `files.read`.
- **DELETE /files/api/documents/{docId}** — Soft-delete the document. Requires `files.write`. Doc does not state that the caller must be the document owner or have explicit share permission.

### Folders

- **GET /files/api/folders/{folderId}** — Returns folder metadata and list of child document IDs. Requires `files.read`.
- **GET /files/api/folders/{folderId}/documents** — List documents in the folder. Optional `?sort=name`. No description of access control: can any authenticated user with `files.read` access any folder by ID?

## Data Model

- **Document** — docId, folderId, ownerId, name, size.
- **Folder** — folderId, parentFolderId, name, ownerId.

## Risk

If the API does not validate that the Bearer token’s subject (or tenant) is allowed to access the requested docId or folderId, any user could access or delete another user’s files by guessing IDs.
