## Analysis reasoning

I reviewed the ConsumerProfile GraphQL API v4.0.0 architecture specification, Node.js/Apollo resolver code, Mongoose schema, GraphQL schema, and HAR trace.

1. **Mass assignment root cause — spread operator + strict:false**: the two flaws interact. The `{ ...input }` spread in `$set` means any client-provided key in the input JSON object is passed to MongoDB. The `{ strict: false }` Mongoose option means the ORM writes any field without schema validation, including fields not declared in the schema. Together they form a direct write path from user input to any database field.

2. **GraphQL schema does not protect the resolver**: the `UpdateUserInput` GraphQL type only defines `displayName` and `shippingAddress`. A WAF or schema validator could reject `role: ADMIN` at the GraphQL parsing layer if input type enforcement was strict. However, in the implementation described, the resolver receives the input after schema validation, and there is no check that the `input` object keys match the GraphQL input type definition. The `role` field is injected as a raw JSON key in the mutation — and because Apollo passes the full `input` argument to the resolver, the injected key reaches `{ ...input }`.

3. **HAR confirms the full chain**: JWT `role: "CUSTOMER"` is the starting identity. The mutation body includes `role: ADMIN` as a peer-level key to `displayName`. The response body contains `"role": "ADMIN"` — this is the value the Mongoose ORM wrote back and returned via `findByIdAndUpdate` with `{ new: true }`. The resolver comment confirms: "Returns the updated user object, potentially revealing the success of the role change." The reflection is a direct read of the updated MongoDB document.

4. **Impact — vertical privilege escalation**: this is not a horizontal BOLA (accessing another user's data) but a vertical privilege escalation (elevating own role). The attacker goes from `CUSTOMER` to `ADMIN` in a single mutation. Section 4.1 states: "their next issued JWT will reflect the elevated `ADMIN` role, granting them full vertical privilege escalation across the entire e-commerce platform." Admin access to an e-commerce platform includes customer PII, payment data, and order management.

5. **`runValidators: true` does not help**: the Mongoose query option `runValidators: true` runs schema validators on `$set` operations, but the `role` field IS defined in the schema with a valid enum value (`ADMIN`) — so validation passes. This is a false sense of security — validators check type correctness, not authorization.
