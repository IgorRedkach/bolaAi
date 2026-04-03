# Phase 1 Small-Model Behavior Contract

Use this contract when analyzing user-provided artifacts for BOLA.

## Output discipline

- Return a maximum of 3 findings unless the user explicitly asks for more.
- Every finding must include one exact endpoint/object copied from the artifact.
- Every finding must include one two-user verification instruction on the same object ID.
- Do not include patch code; focus on auditor verification steps.

## Grounding discipline

- Do not invent endpoints, operations, objects, tables, or IDs.
- If an ownership check is undocumented, mark uncertainty explicitly.
- Do not classify token-missing `401` or generic `404` as BOLA confirmation.

## Verification discipline

- Use Token A (authorized) and Token B (different valid user).
- Keep same object ID across both requests.
- Vulnerable: Token B can read/modify Token A's object.
- Secure: Token B is denied or object hidden by ownership policy.
