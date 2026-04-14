---
name: docs-authoring-quality
description: Enforces high-consequence engineering standards for developer-facing documentation. Ensures all examples, guides, and explanations are grounded in logical invariants and evidence-first reporting.
---
# Documentation Authoring Quality (v2026.4)

## Strategic Scope
Apply this skill to all files in `docs/`, `src/training/`, and any developer instructions. This project adheres to a "No Shortcuts" quality policy.

## Output Contract
- **Commands-First**: Lead with the actionable CLI command or API call.
- **Contextual Integrity**: Use real paths (`src/bola_ai/...`), realistic IDs, and verbatim identifiers from project logs/traces.
- **Atomic Topics**: One logical concept per page. Cross-reference using relative markdown links.
- **Visual Evidence**: Always include the "Expected Outcome" (e.g., specific JSON response keys or 403/200 status codes).
- **Zero-Latency Snippets**: Code must be runnable via copy-paste without manual variable substitution (use placeholders like `{{TOKEN}}` only if context-specific data is absent).

## Logic-First Writing Rules

1. **Deterministic Style**
   - No marketing, personality, or emoji. Use technical prose.
   - Headers must be functional (e.g., "Verification Protocol" instead of "How to check things").
2. **Structural Integrity**
   - No generic "Next Steps" or "Conclusion" footers.
   - Lead with the **Logical Invariant** (the rule being documented).
3. **Frontmatter Constraints**
   - `title`: Must match the repository sidebar label exactly.
   - `type`: Must specify one of: [tutorial, how-to, reference, explanation, security-spec].

## Security Documentation Gate
When documenting security features or vulnerability classes:
- **Evidence-First**: Cite specific lines of code or artifact types.
- **Request Completeness**: For REST documentation, provide the full `curl` command including Method, Headers, and Body.
- **The Assertion Invariant**: Explicitly define what constitutes a "Secure Result" vs. a "Vulnerable Result."

## Doc Type Definitions
- **Tutorial**: Learning by building (requires a sequence of successes).
- **How-to**: Task-oriented (requires a specific goal).
- **Reference**: Technical lookup (exhaustive lists/APIs).
- **Explanation**: Design rationale (the "Why").
- **Security-Spec**: Logical ontology of failure patterns.

## Finalization Checklist

```text
- [ ] Document type is isolated (no mixing)
- [ ] Headings cite the specific technical component or invariant
- [ ] Command/Code block appears within the first two paragraphs
- [ ] Examples use real project paths and verbatim log data
- [ ] Assertions for "Pass/Fail" states are clearly defined
- [ ] Terminology aligns with the 'Universal Vulnerability Ontology'
- [ ] No placeholder URLs used if real URLs exist in project context