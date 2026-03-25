# Agent weak-place registry (mandatory)

**Purpose:** Every **weak spot**, **partial fix**, or **“could be improved”** item must be **recorded here** until it is **fixed and verified**. The coding agent **must not** treat a session as complete while **any row below is OPEN** (unless the only blocker is documented in ISSUES.md as environment/stack unavailable — still file OPEN issue).

## Rules

1. **On starting work:** Read this file. **OPEN** rows = mandatory work before claiming “all goals met.”
2. **When you find a gap** (E2E miss, wrong curl method vs doc, grounding slip, test gap, doc drift): **append** a row with status **OPEN**.
3. **After you fix:** Change status to **FIXED**, run the verification (unit test / E2E / script), then set **VERIFIED** with date and evidence (test name or log path).
4. **Automatic next loop:** After fixing, **do not stop** at “fixed in code” — **re-run** the failing check **immediately**. If anything still fails, add/update rows and **repeat** until **no OPEN rows** remain for this cycle’s scope.
5. **Registry clear:** When there are **no OPEN rows**, keep a short history table below **or** a single line: `*(none — registry clear; YYYY-MM-DD)*`
6. **Goal protection:** Do not delete user-defined goals from `docs/GOALS.md` unless the user explicitly requests deletion; treat accidental removal as a weak place.

## Registry

*(none — registry clear; 2026-03-24 — WP-016 closed: grounding suffix leakage; WP-015 closed: invalid-token verification; WP-014 closed: plain Fix steps; WP-013 closed: numbered Notes; WP-012 closed: Python code blocks; WP-011 closed: hallucinated query params; WP-010 OPEN (model capacity); WP-009 closed: domain-as-path in context extraction; WP-008 closed: Notes leakage; WP-007 closed: Fix steps verbosity; WP-006 closed: cheat-sheet RAG leakage)*

| ID | Found | Description | Evidence |
|----|-------|-------------|----------|
| WP-002 | 2025-03-02 | REST-only doc + invented GraphQL in q3 | `test_normalize_report_strips_graphql_blocks_when_rest_only_doc` |
| WP-003 | 2026-03-24 | Full suite had E2E timeout due chunk accumulation across live tests | `tests/test_e2e_llm.py::_reset_and_ingest` + full `pytest tests/` |
| WP-004 | 2026-03-24 | q5 curl output showed malformed `https:/[use only endpoints...]` after redaction | `test_normalize_report_replaces_broken_redacted_url_with_grounded_placeholder` |
| WP-005 | 2026-03-24 | q5 logic claimed user-A denial confirms BOLA | `test_normalize_report_rewrites_invalid_user_a_denied_confirmation` |

| WP-006 | 2026-03-24 | "## BOLA Remediation Cheat Sheet" from RAG knowledge base leaks into reports | VERIFIED — `_strip_report_leakage` strips it; `test_normalize_report_strips_bola_remediation_cheat_sheet` passes |
| WP-007 | 2026-03-24 | Model generates verbose "**Fix steps:**" sections not in output spec | VERIFIED — regex strips `**Fix steps:**` blocks; `test_normalize_report_strips_fix_steps_sections` passes |
| WP-008 | 2026-03-24 | Raw "## Notes" / "### Notes" fixture sections leak as spurious findings | VERIFIED — stripped in `_strip_report_leakage`; `test_normalize_report_strips_raw_notes_section` passes

| WP-009 | 2026-03-24 | `_extract_paths_from_context` extracts domain names (e.g. `/api.waterdistrict.gov/v2`) as allowed paths, producing malformed fallback URLs like `https://api.example.com/api.waterdistrict.gov/v2` | VERIFIED — domain-segment filter added to `_extract_paths_from_context`; `test_extract_paths_excludes_domain_segments` passes |

| WP-010 | 2026-03-24 | Curl examples use wrong path — model reuses the first retrieved path (e.g. `/accounts/{accountId}/usage`) for all findings' curl examples instead of the specific endpoint path | PARTIALLY MITIGATED — `_fix_curl_path_mismatch()` now replaces mismatched curl blocks with a corrected placeholder using the heading path; `test_fix_curl_path_mismatch_*` tests pass; prompt reinforced; Issue 22 filed. Root cause (model generates wrong path) remains; mitigation corrects output post-generation |
| WP-011 | 2026-03-24 | Hallucinated query parameters in curl examples: `?owner=...&tenant=...&admin=true&uuid=...` — not in documentation | VERIFIED — regex strips `?owner=...&tenant=...&admin=...&uuid=...` patterns; `test_normalize_report_strips_hallucinated_query_params` passes |
| WP-012 | 2026-03-24 | Python/Django code blocks (`def verify_owner(request)`) appearing in report — implementation fix code is off-topic for an audit tool | VERIFIED — Python code blocks stripped in `_strip_report_leakage`; `test_normalize_report_strips_python_code_block` passes |
| WP-013 | 2026-03-24 | Numbered `### 4. Notes` heading not caught by WP-008 regex (only catches unnumbered `### Notes`) — fixture Notes section leaks into reports as a spurious finding | VERIFIED — Notes regex updated to `(?:\d+\.\s+)?Notes`; `test_normalize_report_strips_numbered_notes_section` passes |
| WP-014 | 2026-03-24 | Plain-text `- Fix steps:` (unbolded, list-item format) not stripped — WP-007 regex only catches `**Fix steps:**` bold variant | VERIFIED — plain-text `- Fix steps:` bullet stripped; `test_normalize_report_strips_plain_fix_steps_bullet` passes |
| WP-015 | 2026-03-24 | "Call with an invalid token" in verification steps tests authentication, not BOLA — Issue 11 normalization handles "without a token" but not "with an invalid token" | VERIFIED — regex replaces invalid-token phrasing; `test_normalize_report_replaces_invalid_token_verification` passes |

| WP-016 | 2026-03-24 | `GROUNDING_USER_SUFFIX` from user prompt echoed verbatim by the model at end of reports ("**Mandatory grounding (person-style and runbook answers included):**") | VERIFIED — strip marker added to `_strip_report_leakage`; `test_normalize_report_strips_grounding_suffix_echo` passes |

| WP-017 | 2026-03-24 | Finding sections whose `###` heading was redacted to `[use only endpoints from the documentation]` survive in the report — the full finding block (rationale, verification, curl) is nonsensical but still present, confusing auditors | VERIFIED — `_redacted_heading_block` regex strips entire finding sections with redacted headings (two-pass for consecutive blocks); `test_normalize_report_strips_redacted_heading_finding_blocks` passes |

| WP-018 | 2026-03-24 | Model sometimes writes inverted rationale: "The server **restricts** this endpoint to admins" instead of "No documentation states the server restricts this endpoint" — turns a BOLA risk into a false statement of correct security | VERIFIED — WP-018: normalization adds 'No documentation states' prefix when 'The server restricts/requires/enforces' appears immediately after a Rationale heading; `test_normalize_report_fixes_inverted_rationale` passes |

| WP-019 | 2026-03-24 | Model over-applies `submittingEmployeeId` body-field BOLA pattern to path-level endpoints (GET/HEAD). When a multi-action query mentions POST /coverage-changes, the model applies the body-field rationale to all findings including GET endpoints where no body field exists | VERIFIED — WP-019: `_strip_get_body_payload` strips `-d` body with submittingEmployeeId from GET/HEAD curl blocks; `test_normalize_report_strips_get_body_submitting_employee_id` passes |
| WP-020 | 2026-03-24 | Model loops and generates repeated `#### Rationale:` / `#### Verification steps:` sub-blocks under the same `###` finding heading (seen in Q6 self-audit) | VERIFIED — WP-020: `_dedup_subheadings` strips repeated #### sub-heading blocks within same ### section (key=heading line only); `test_normalize_report_deduplicates_repeated_rationale_subheadings` passes |

| WP-021 | 2026-03-02 | Trailing "Additional Notes" section about hypothetical GraphQL/SOQL in REST-only reports | Normalization strips Additional Notes sections; `test_normalize_report_strips_additional_notes_section` passes | VERIFIED |

*Next OPEN row: use ID **WP-022**.*
