## Analysis reasoning

I reviewed the SupplyChain Partner GraphQL Portal v4.1.0 architecture specification, Ruby GraphQL type definition, schema, and HAR trace.

1. **Two-step attack chain**: finding 1 (introspection) is the discovery mechanism; finding 2 (field over-fetching) is the exploitation. The HAR shows the exploitation step — the partner already knows the field name `internalAuditNotes` and queries it directly. The introspection step is documented in section 4.1 step 1 ("An attacker sends an introspection query") and is not shown separately in the HAR (as noted in the HAR description: "Pattern 6.1, not shown in this specific trace"). Without introspection, the field name would not be discoverable.

2. **Missing field-level guard in the Ruby type**: the `Types::OrderType` definition (section 6.1) defines `field :internal_audit_notes` with a comment: "There is NO method called 'authorized?' or 'can_read_notes?' applied here." The `def internal_audit_notes` method returns `object.internal_audit_notes` — a direct ActiveRecord attribute access. In GraphQL-Ruby, field-level authorization requires either an `authorized?` class method on the type, a `Pundit` or `CanCan` policy call, or a custom guard. None are present.

3. **Parent BOLA check is insufficient**: section 3.2 states the resolver performs a BOLA check to ensure the order belongs to the partner. This check is correct and necessary, but insufficient. The parent authorization ensures the partner can see the order record — it does not authorize which fields on that record are accessible. Field-level authorization is a separate concern. An authorized read of `ORD-99182A` should not imply authorized read of `internal_audit_notes`.

4. **HAR fraud note leakage**: the response body contains `"Order flagged for potential fraud. High risk of chargeback (92%). Ship only to verified billing address. DO NOT offer rush shipping."` This is internal fraud intelligence. Exposing this to the partner whose order was flagged would: (a) reveal the internal fraud scoring methodology, (b) allow the partner to adjust behaviour to avoid future flags, (c) reveal that the partner is under fraud investigation.

5. **RISK-GRPH-905 documents both failures**: introspection left enabled from a debugging sprint, and `internalAuditNotes` excluded from REST docs but accidentally left visible in the GraphQL schema. The combination created the chain.
