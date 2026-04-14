## Findings

1. **GraphQL state bypass via `components_in_progress` field — access to DRAFT components and ITAR-restricted blueprints**: the `Project` type exposes two component resolvers. `published_components` correctly filters by `state == 'PUBLISHED'`. `components_in_progress` (section 5.1 annotation: "VULN A — intended for internal PMs, but exposed globally") filters by `assigned_vendors` but **fails to filter by Component `state`**. A subcontractor authenticated with `vendor_id: VND-4011` and role `subcontractor_engineer` can use `components_in_progress` in a GraphQL query to traverse into `Component` nodes in `DRAFT` state, bypassing the publication state machine (section 3.2).

2. **Presigned S3 URL generated for DRAFT blueprint — ITAR-restricted file exposed**: the `Document-Subgraph` implicitly trusts upstream traversal (section 6.2) and generates an AWS GovCloud S3 presigned URL (valid 15 minutes / 900 seconds) for any `Blueprint` object reached by a query — including `DRAFT` components. The HAR response returns a live presigned URL for `aft_strut_v0.9_unapproved.dwg`, which is an unapproved ITAR-controlled engineering drawing, directly accessible to the subcontractor without Government Contracting Officer approval.

## Evidence

- **HAR POST request** (`startedDateTime: 2026-04-08T14:22:15.891Z`, elapsed 412 ms, `x-apollo-tracing-duration: 390ms`): `POST https://api.aegisforge.govcloud.mil/graphql`; JWT encodes `sub: cac-99182b-441`, `vendor_id: VND-4011`, `clearance_level: SECRET`, `caveats: ["NOFORN"]`, `roles: ["subcontractor_engineer"]`; body contains query `ExtractDraftCAD` with `project(id: "PRJ-FX") { components_in_progress { id nomenclature state blueprints { filename s3_download_url } } }`.
- **HAR response**: HTTP 200 OK; data returns component `C-8819-DRAFT` with `state: "DRAFT"`, `nomenclature: "Aft Landing Strut Assembly"`, and blueprint `aft_strut_v0.9_unapproved.dwg` alongside the presigned URL `https://aegisforge-blueprints-gov-west.s3.us-gov-west-1.amazonaws.com/PRJ-FX/C-8819-DRAFT/aft_strut_v0.9_unapproved.dwg?...&X-Amz-Expires=900&X-Amz-Signature=b4c2...` — valid for 900 seconds.
- **GraphQL schema confirms the bypass** (section 5.1): `components_in_progress` is annotated "FAILS to filter by Component `state`." The secure resolver is `published_components`. The vulnerable resolver exposes `DRAFT` state data to any assigned vendor.
- **Document-Subgraph implicit trust** (section 6.2): "The `Document-Subgraph` implicitly trusts the upstream subgraphs. It assumes that if a user has successfully navigated the graph to request a `Blueprint`, the parent `Component` resolver has already verified the publication state." Since the parent resolver does not verify state, the Document-Subgraph generates the presigned URL unconditionally.
- **ITAR violation**: the blueprint filename `aft_strut_v0.9_unapproved.dwg` is within the `DRAFT` state component — not approved by a Government Contracting Officer — and contains ITAR-controlled engineering data for the "F-X Vanguard" aerospace platform.

## Reproduction

Step 1 — confirm authorized access via the correct `published_components` resolver:

```bash
curl -i -X POST "https://api.aegisforge.govcloud.mil/graphql" \
  -H "Authorization: Bearer <JWT_VND-4011_subcontractor_engineer>" \
  -H "Content-Type: application/json" \
  -H "x-amz-govcloud-region: us-gov-west-1" \
  -d '{"query":"query AuthorizedAccess { project(id: \"PRJ-FX\") { id codename published_components { id nomenclature state blueprints { filename s3_download_url } } } }","variables":{}}'
```

Expected: only components with `state: "PUBLISHED"` are returned.

Step 2 — use `components_in_progress` to access DRAFT components and their blueprints:

```bash
curl -i -X POST "https://api.aegisforge.govcloud.mil/graphql" \
  -H "Authorization: Bearer <JWT_VND-4011_subcontractor_engineer>" \
  -H "Content-Type: application/json" \
  -H "x-amz-govcloud-region: us-gov-west-1" \
  -d '{"query":"query ExtractDraftCAD { project(id: \"PRJ-FX\") { id codename components_in_progress { id nomenclature state blueprints { filename s3_download_url } } } }","variables":{}}'
```

Expected secure outcome: HTTP 200 with empty `components_in_progress` array, or HTTP 403 — `subcontractor_engineer` role is not permitted to access this resolver.  
Observed vulnerable outcome: HTTP 200, `C-8819-DRAFT` returned with `state: "DRAFT"` and a live presigned URL for `aft_strut_v0.9_unapproved.dwg` valid for 900 seconds.

## Remediation

- **Restrict `components_in_progress` to internal PM roles**: add a resolver-level authorization guard — verify the caller's JWT `roles` contains `project_manager` or `internal_pm` before returning any data. Return an empty array or authorization error for `subcontractor_engineer` callers.
- **Add state filter to `components_in_progress`**: even for authorized internal callers, the resolver must filter by `state IN ['DRAFT', 'PENDING_REVIEW']` and enforce that vendor-assigned users cannot see components below `PUBLISHED`.
- **Implement defense-in-depth in the Document-Subgraph**: before generating an S3 presigned URL, the `Document-Subgraph` must independently verify that the parent `Component.state == 'PUBLISHED'` for the requesting `vendor_id` — never rely solely on the upstream resolver's authorization decision.
- **Disable or field-level protect `components_in_progress`** from the Apollo Router's externally exposed supergraph schema — apply `@authorized` directives or router-level query depth/field restrictions to prevent subcontractors from discovering internal resolver names.
