## Analysis reasoning

I reviewed the ClientData GraphQL Interface API v5.0.0 architecture specification, Java Spring resolver code, schema, and HAR trace.

1. **Missing role check — resolver reads role but does not use it**: the Java resolver (section 6.1) calls `env.getContext().get("role")` to get `authenticatedRole`, but the code comment marks the guard as missing: "The code FAILS to check: `if (!"ADMIN".equals(authenticatedRole)) { return null; }`". The variable is set but never evaluated. This is a classic forgotten check pattern — the developer wrote the context lookup, which implies intent to add a guard, but never completed the implementation.

2. **RISK-GRPH-906 documents the exact cause**: "The `@requiresAuth(role: ADMIN)` directive was forgotten during the final schema merge." The directive was the intended protection mechanism — without it, the resolver has no declarative authorization and the implementation-level check was never added. The field is open.

3. **HAR — vertical escalation confirmed by response content**: the JWT is marked as a `USER` role (`USER_JWT_88192A`). The `internalAuditData` response contains `lastLoginIP`, `failedLoginAttemptsLast24h: 5`, and `piiChangeHistory` with a hashed previous address value. None of these fields are appropriate for a standard user to see about their own account — they are internal security monitoring data. This is vertical privilege escalation: the caller received data associated with a privilege level higher than their role.

4. **Interface type amplifies the risk**: the `Client` interface is implemented by multiple concrete types (`BasicUser`, `EnterpriseUser`, `AdminUser`). Because `internalAuditData` is defined on the interface, the field resolver is available for all concrete types. An attacker querying any object that implements `Client` can attempt to fetch `internalAuditData`. The `me` query returns the attacker's own `BasicUser` object — and because BOLA passes (it's their own object), only the field-level role guard matters.

5. **This is not a horizontal BOLA**: the attacker is querying their own account (`me`), not another user's. The violation is vertical — accessing administrative fields on their own object that should require an elevated role. The fix is at the field resolver level, not the object-level authorization.
