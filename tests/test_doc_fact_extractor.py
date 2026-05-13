"""Tests for bola_ai.rag.doc_fact_extractor and doc_facts.

Covers:
- DocTypeDetector: correct section detection for each document type
- DocFactExtractor: per-type fact extraction correctness
- StructuredDocFacts.to_prompt_block(): risk signal surfacing
- Edge cases: empty text, unknown format, partial documents
"""
from __future__ import annotations

import pytest

from bola_ai.rag.doc_fact_extractor import DocFactExtractor, DocTypeDetector
from bola_ai.rag.doc_facts import DocSection, StructuredDocFacts


# ─── Fixtures ────────────────────────────────────────────────────────────────

_ARCH_SPEC_TEXT = """\
# ENGINEERING ARCHITECTURE SPECIFICATION
**System Name:** ExamplePay API
**Document Version:** 2.0.0 (FINAL)
**Classification:** SENSITIVE
**Domain:** Fintech / Payment Processing

## 1.0 Overview
The ExamplePay API uses OAuth 2.0 JWT tokens for authentication.
Users authenticate with a Bearer token carrying the sub claim.

## 2.0 Auth
Vehicle ownership is tracked in the `payment_ownership` table.
Known issues: BUG-PAY-001: ownership check skipped for refund endpoint.
"""

_SQL_SCHEMA_TEXT = """\
CREATE TABLE accounts (
    account_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(100) NOT NULL,
    balance DECIMAL(18,2) NOT NULL DEFAULT 0
);

CREATE TABLE transactions (
    tx_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    amount DECIMAL(18,2),
    status VARCHAR(20)
);
"""

_REST_CONTRACT_TEXT = """\
**Endpoint:** `POST /api/v2/accounts/{accountId}/transfer`
**Description:** Transfer funds between accounts.

**Required Headers:**
    Authorization: Bearer <JWT>

**Request Body:**
{
  "target_account_id": "string",
  "amount": "number"
}

**Error Responses:**
* `403 Forbidden`: User does not own the account.
"""

_SOURCE_CODE_TEXT = """\
Here is the flawed Go handler:

```go
func TransferFunds(c *gin.Context) {
    accountId := c.Param("accountId")
    userID, _ := c.Get("user_id")

    // BUG-PAY-001: ownership check disabled to reduce latency
    /* FIX:
    if !db.CheckOwnership(userID, accountId) {
        c.JSON(403, gin.H{"error": "forbidden"})
        return
    }
    */

    // proceed with transfer
    processTransfer(accountId, userID.(string))
    c.JSON(200, gin.H{"status": "ok"})
}
```
"""

_GRAPHQL_TEXT = """\
type Query {
    getUserProfile(userId: ID!): UserProfile
    getOrder(orderId: ID!): Order
}

type Mutation {
    updateProfile(userId: ID!, fields: [String!]!): UserProfile
}
"""

_EMBEDDED_HAR_TEXT = """\
The attacker sends this request:

```json
{
  "log": {
    "version": "1.2",
    "entries": [
      {
        "startedDateTime": "2026-01-01T00:00:00Z",
        "time": 100,
        "request": {
          "method": "POST",
          "url": "https://api.example.com/transfer"
        },
        "response": {
          "status": 200
        }
      }
    ]
  }
}
```
"""

_COMPOSITE_TEXT = (
    _ARCH_SPEC_TEXT + "\n\n" +
    _SQL_SCHEMA_TEXT + "\n\n" +
    _SOURCE_CODE_TEXT + "\n\n" +
    _REST_CONTRACT_TEXT + "\n\n" +
    _EMBEDDED_HAR_TEXT
)


# ─── DocTypeDetector tests ────────────────────────────────────────────────────

class TestDocTypeDetector:

    def test_detects_arch_spec(self):
        sections = DocTypeDetector.detect(_ARCH_SPEC_TEXT)
        assert DocSection.ARCH_SPEC in sections

    def test_detects_sql_schema(self):
        sections = DocTypeDetector.detect(_SQL_SCHEMA_TEXT)
        assert DocSection.SQL_SCHEMA in sections

    def test_detects_source_code(self):
        sections = DocTypeDetector.detect(_SOURCE_CODE_TEXT)
        assert DocSection.SOURCE_CODE in sections

    def test_detects_rest_contract(self):
        sections = DocTypeDetector.detect(_REST_CONTRACT_TEXT)
        assert DocSection.REST_CONTRACT in sections

    def test_detects_graphql(self):
        sections = DocTypeDetector.detect(_GRAPHQL_TEXT)
        assert DocSection.GRAPHQL_SCHEMA in sections

    def test_detects_embedded_har(self):
        sections = DocTypeDetector.detect(_EMBEDDED_HAR_TEXT)
        assert DocSection.EMBEDDED_HAR in sections

    def test_composite_detects_multiple(self):
        sections = DocTypeDetector.detect(_COMPOSITE_TEXT)
        assert DocSection.ARCH_SPEC in sections
        assert DocSection.SQL_SCHEMA in sections
        assert DocSection.SOURCE_CODE in sections
        assert DocSection.EMBEDDED_HAR in sections

    def test_empty_text_returns_user_guide(self):
        sections = DocTypeDetector.detect("  \n  ")
        assert DocSection.USER_GUIDE in sections

    def test_plain_prose_returns_user_guide(self):
        sections = DocTypeDetector.detect("This is a simple user guide with no code or schema.")
        assert DocSection.USER_GUIDE in sections

    def test_log_lines_detected(self):
        log_text = "2026-01-01T10:00:00 INFO Request received [ACCESS] user=alice"
        sections = DocTypeDetector.detect(log_text)
        assert DocSection.LOG_TRACE in sections


# ─── DocFactExtractor tests ───────────────────────────────────────────────────

class TestDocFactExtractor:

    def setup_method(self):
        self.extractor = DocFactExtractor()

    # ── System metadata ────────────────────────────────────────────────────

    def test_extracts_system_name(self):
        facts = self.extractor.extract(_ARCH_SPEC_TEXT)
        assert facts.system is not None
        assert "ExamplePay" in facts.system.name

    def test_extracts_domain(self):
        facts = self.extractor.extract(_ARCH_SPEC_TEXT)
        assert "Fintech" in facts.system.domain or "Payment" in facts.system.domain

    def test_extracts_classification(self):
        facts = self.extractor.extract(_ARCH_SPEC_TEXT)
        assert facts.system.classification == "SENSITIVE"

    def test_extracts_version(self):
        facts = self.extractor.extract(_ARCH_SPEC_TEXT)
        assert facts.system.version is not None
        assert "2.0.0" in facts.system.version

    # ── Auth model ─────────────────────────────────────────────────────────

    def test_extracts_auth_scheme(self):
        facts = self.extractor.extract(_ARCH_SPEC_TEXT)
        assert facts.auth_model is not None
        assert "OAuth" in facts.auth_model.scheme or "JWT" in facts.auth_model.scheme or "Bearer" in facts.auth_model.scheme

    def test_extracts_identity_claim(self):
        facts = self.extractor.extract(_ARCH_SPEC_TEXT)
        assert facts.auth_model is not None
        assert facts.auth_model.identity_claim in ("sub", "user_id", None)

    def test_extracts_explicit_bugs(self):
        facts = self.extractor.extract(_ARCH_SPEC_TEXT)
        assert facts.auth_model is not None
        bugs = " ".join(facts.auth_model.explicit_bugs)
        assert "BUG-PAY-001" in bugs or "ownership" in bugs.lower()

    # ── SQL schemas ────────────────────────────────────────────────────────

    def test_extracts_sql_table_names(self):
        facts = self.extractor.extract(_SQL_SCHEMA_TEXT)
        table_names = [s.name for s in facts.schemas]
        assert "accounts" in table_names

    def test_accounts_has_ownership_column(self):
        facts = self.extractor.extract(_SQL_SCHEMA_TEXT)
        acc = next((s for s in facts.schemas if s.name == "accounts"), None)
        assert acc is not None
        assert any("user_id" in c for c in acc.ownership_columns)

    def test_transactions_table_missing_ownership(self):
        facts = self.extractor.extract(_SQL_SCHEMA_TEXT)
        tx = next((s for s in facts.schemas if s.name == "transactions"), None)
        assert tx is not None
        assert tx.missing_ownership_fk is True

    def test_accounts_pk_is_uuid(self):
        facts = self.extractor.extract(_SQL_SCHEMA_TEXT)
        acc = next((s for s in facts.schemas if s.name == "accounts"), None)
        assert acc is not None
        assert acc.pk_type == "uuid"

    # ── REST endpoints ─────────────────────────────────────────────────────

    def test_extracts_endpoint_method_and_path(self):
        facts = self.extractor.extract(_REST_CONTRACT_TEXT)
        methods = [e.method for e in facts.endpoints]
        paths = [e.path for e in facts.endpoints]
        assert "POST" in methods
        assert any("/api/v2/accounts/" in p for p in paths)

    def test_endpoint_has_path_param(self):
        facts = self.extractor.extract(_REST_CONTRACT_TEXT)
        ep = next((e for e in facts.endpoints if "POST" in e.method), None)
        assert ep is not None
        assert ep.path_params  # {accountId}

    def test_endpoint_gate3_signal(self):
        # accountId in path with no ownership check described → GATE3
        facts = self.extractor.extract(_REST_CONTRACT_TEXT)
        assert facts.has_id_params_without_ownership

    # ── Code flows ─────────────────────────────────────────────────────────

    def test_extracts_go_handler(self):
        facts = self.extractor.extract(_SOURCE_CODE_TEXT)
        assert any(c.language == "go" for c in facts.code_flows)

    def test_handler_name_extracted(self):
        facts = self.extractor.extract(_SOURCE_CODE_TEXT)
        go_flow = next((c for c in facts.code_flows if c.language == "go"), None)
        assert go_flow is not None
        assert go_flow.handler_name == "TransferFunds"

    def test_ownership_bypassed_detected(self):
        facts = self.extractor.extract(_SOURCE_CODE_TEXT)
        go_flow = next((c for c in facts.code_flows if c.language == "go"), None)
        assert go_flow is not None
        assert go_flow.ownership_check_bypassed is True

    def test_bug_id_extracted(self):
        facts = self.extractor.extract(_SOURCE_CODE_TEXT)
        go_flow = next((c for c in facts.code_flows if c.language == "go"), None)
        assert go_flow is not None
        assert "BUG-PAY-001" in go_flow.bug_ids

    def test_risk_signal_bypassed(self):
        facts = self.extractor.extract(_SOURCE_CODE_TEXT)
        assert facts.has_bypassed_auth_checks

    def test_risk_signal_explicit_bugs(self):
        facts = self.extractor.extract(_SOURCE_CODE_TEXT)
        assert facts.has_explicit_bug_notes

    # ── Embedded HAR ───────────────────────────────────────────────────────

    def test_embedded_har_extracted(self):
        facts = self.extractor.extract(_EMBEDDED_HAR_TEXT)
        assert facts.embedded_har_json is not None
        assert '"entries"' in facts.embedded_har_json

    # ── Composite document ─────────────────────────────────────────────────

    def test_composite_not_empty(self):
        facts = self.extractor.extract(_COMPOSITE_TEXT)
        assert not facts.is_empty()

    def test_composite_has_schemas_and_endpoints_and_code(self):
        facts = self.extractor.extract(_COMPOSITE_TEXT)
        assert facts.schemas
        assert facts.endpoints
        assert facts.code_flows

    def test_composite_risk_signals(self):
        facts = self.extractor.extract(_COMPOSITE_TEXT)
        assert facts.has_bypassed_auth_checks
        assert facts.has_explicit_bug_notes
        assert facts.has_id_params_without_ownership

    # ── Edge cases ─────────────────────────────────────────────────────────

    def test_empty_string(self):
        facts = self.extractor.extract("")
        assert facts.is_empty()

    def test_none_like_empty(self):
        facts = self.extractor.extract("   \n  ")
        assert facts.is_empty()

    def test_plain_prose_no_crash(self):
        facts = self.extractor.extract("This is a simple user manual about using the system.")
        assert facts is not None  # no exception

    def test_extract_from_chunks(self):
        chunks = [
            {"content": _ARCH_SPEC_TEXT, "source": "spec.txt"},
            {"content": _SQL_SCHEMA_TEXT, "source": "schema.sql"},
        ]
        facts = self.extractor.extract_from_chunks(chunks)
        assert facts.system is not None
        assert facts.schemas


# ─── StructuredDocFacts.to_prompt_block tests ────────────────────────────────

class TestToPromptBlock:

    def test_gate3_signal_in_block(self):
        extractor = DocFactExtractor()
        facts = extractor.extract(_COMPOSITE_TEXT)
        block = facts.to_prompt_block()
        assert "GATE3" in block

    def test_bypassed_signal_in_block(self):
        extractor = DocFactExtractor()
        facts = extractor.extract(_SOURCE_CODE_TEXT)
        block = facts.to_prompt_block()
        assert "BYPASS" in block.upper() or "BYPASSED" in block.upper()

    def test_block_contains_system_name(self):
        extractor = DocFactExtractor()
        facts = extractor.extract(_ARCH_SPEC_TEXT)
        block = facts.to_prompt_block()
        assert "ExamplePay" in block

    def test_block_contains_schema_names(self):
        extractor = DocFactExtractor()
        facts = extractor.extract(_SQL_SCHEMA_TEXT)
        block = facts.to_prompt_block()
        assert "accounts" in block

    def test_empty_facts_block_is_empty_string(self):
        facts = StructuredDocFacts()
        assert facts.to_prompt_block() == ""

    def test_risk_signals_section_present(self):
        extractor = DocFactExtractor()
        facts = extractor.extract(_COMPOSITE_TEXT)
        block = facts.to_prompt_block()
        assert "RISK SIGNALS" in block
