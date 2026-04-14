## Findings

1. **BFLA (Broken Function Level Authorization) — admin force-clear path lacks route-level authorization middleware**: `mapping.txt` section 7.3 mandates "All `/api/v1/admin/*` HTTP routes must include explicit authorization middleware before gRPC invocation mapping occurs. Missing middleware is a deployment blocker." This constraint exists precisely because the edge BFF (`architecture.txt`, section 4.0) is responsible only for "coarse route controls" — it does not enforce the admin role policy. If the middleware is absent, a retail-role JWT can reach the gRPC mapping layer and invoke `ComplianceAdminService.ForceClearTransfer` without role enforcement at the HTTP tier.

2. **Missing server-side role enforcement in `ComplianceAdminService` gRPC service**: `grpc.txt` section 5.3 states `ForceClearTransfer` requires `aml_compliance_officer`. `architecture.txt` section 4.0 explicitly warns: "Trust in transport identity (mTLS peer) must not replace user-level authorization for admin operations." `architecture.txt` section 4.1 states: "Retail roles are never allowed to invoke admin force-clear functions." Together these confirm the gRPC service itself must enforce role checks on every method, independent of the BFF route result. If the service trusts the mTLS peer identity (the BFF) without re-evaluating the forwarded user role, a request that slips past the missing middleware will be executed.

3. **Kafka event consumer authorization provenance gap**: `kafka.txt` section 6.3 requires that `TransferForceCleared` events include `verified_authorization_decision_id` and `verified_actor_role` fields, both signed by the authorization service. Events missing these fields must be rejected with a `SECURITY_EVENT_INVALID_ADMIN_ACTION` marker. If an unauthorized `ForceClearTransfer` executes due to findings 1 or 2, the resulting event will lack valid authorization provenance fields — the consumer must reject it. Without this check, downstream ledger and reporting systems will accept unauthorized force-clears as legitimate.

## Evidence

- **`mapping.txt` section 7.3**: explicitly states missing admin auth middleware is a deployment blocker and CI should fail builds — the constraint documents the known risk of omission.
- **`architecture.txt` sections 4.0–4.1**: states coarse BFF controls only; retail roles prohibited from force-clear; mTLS trust must not substitute user-level checks.
- **`grpc.txt` section 5.3**: `ForceClearTransfer` requires `aml_compliance_officer`; failure must return `PERMISSION_DENIED` regardless of BFF route result.
- **`kafka.txt` section 6.3**: `TransferForceCleared` events must carry signed authorization fields; absent fields mandate event rejection and security incident emission.

No HAR trace is available in this folder. The vulnerability surface is entirely specification-grounded, representing a design-level BFLA risk confirmed by four independent architecture constraint documents.

## Reproduction Playbook

**Finding 1 — admin route authorization middleware test:**

Send a `ForceClearTransfer`-equivalent request using a retail-role JWT:

```http
POST /api/v1/admin/transfers/{transfer_id}/force-clear HTTP/1.1
Host: <bff_host>
Authorization: Bearer <JWT_role=retail_customer>
Content-Type: application/json

{"override_reason": "authorization boundary test"}
```

Expected secure outcome: HTTP 403 — authorization middleware denies retail role before gRPC invocation.  
Expected vulnerable outcome: HTTP 200 or gRPC OK — middleware absent, request forwarded to `ComplianceAdminService`.

**Finding 2 — gRPC server-side role enforcement test:**

In a test environment, bypass BFF middleware and call `ComplianceAdminService.ForceClearTransfer` directly over mTLS with a forwarded retail-role identity context.

Expected secure outcome: gRPC `PERMISSION_DENIED` — service enforces `aml_compliance_officer` requirement independently.  
Expected vulnerable outcome: gRPC OK — service trusts mTLS peer without re-checking forwarded user role.

**Finding 3 — event consumer provenance check test:**

Publish a `TransferForceCleared` Kafka event without `verified_authorization_decision_id` or `verified_actor_role`.

Expected secure outcome: consumer rejects event, emits `SECURITY_EVENT_INVALID_ADMIN_ACTION`.  
Expected vulnerable outcome: consumer processes event, downstream ledger accepts unauthorized force-clear as valid.

## Remediation

- **Add mandatory authorization middleware to all `/api/v1/admin/*` routes**: middleware must validate JWT role against an allowlist (`aml_compliance_officer` for force-clear operations) before forwarding to gRPC layer. CI pipeline must fail if middleware is absent.
- **Enforce server-side role checks in `ComplianceAdminService` on every method**: extract forwarded identity context from gRPC metadata, reject with `PERMISSION_DENIED` if `role` is not in the required set — do not rely solely on mTLS peer identity.
- **Validate authorization provenance in event consumers**: reject `TransferForceCleared` events that lack `verified_authorization_decision_id` or carry an unsigned/invalid `verified_actor_role` — emit `SECURITY_EVENT_INVALID_ADMIN_ACTION` and dead-letter the event.
