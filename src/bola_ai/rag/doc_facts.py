"""Data classes representing structured, security-relevant facts
extracted from heterogeneous documentation artifacts.

Unlike the HAR-specific FactIndex (which operates on live network traces),
DocFacts operates on static documentation: architecture specs, SQL schemas,
source code, API contracts, GraphQL schemas, and embedded HAR snippets.

These facts are extracted deterministically *before* the LLM call and
injected into the analysis prompt as a compact, high-signal fact block.
This mirrors the HarExtractor → FactIndex → LLM pattern used in PRISM-HAR,
extended to cover every document type that reaches the generic oracle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ─── Document section types ──────────────────────────────────────────────────

class DocSection(str, Enum):
    """Detectable section types within a mixed documentation artifact."""
    ARCH_SPEC       = "arch_spec"       # Narrative engineering / architecture doc
    SQL_SCHEMA      = "sql_schema"      # DDL: CREATE TABLE, ALTER TABLE, etc.
    SOURCE_CODE     = "source_code"     # Code in any language
    REST_CONTRACT   = "rest_contract"   # Endpoint reference (method + path + params)
    GRAPHQL_SCHEMA  = "graphql_schema"  # SDL type / query / mutation definitions
    OPENAPI_YAML    = "openapi_yaml"    # OpenAPI / Swagger YAML or JSON
    EMBEDDED_HAR    = "embedded_har"    # HAR JSON embedded inside a document
    EVENT_SCHEMA    = "event_schema"    # Kafka / MQTT / SQS message schemas
    USER_GUIDE      = "user_guide"      # Prose user guide / README
    LOG_TRACE       = "log_trace"       # Log lines / access logs (non-HAR)
    UNKNOWN         = "unknown"


# ─── Per-type fact classes ────────────────────────────────────────────────────

@dataclass
class EndpointFact:
    """A single REST or GraphQL operation with its security-relevant attributes."""
    method: str                          # GET / POST / PUT / PATCH / DELETE / QUERY / MUTATION
    path: str                            # /api/v1/users/{userId}
    path_params: list[str]               # ["userId"] — caller-controlled ID params
    query_params: list[str]              # ["fields", "filter"] — field selectors
    body_fields: list[str]               # fields accepted in request body
    auth_required: bool                  # True if auth header / decorator declared
    ownership_check_present: bool        # True if code/doc explicitly mentions ownership check
    ownership_check_bypassed: bool       # True if check is commented out / noted as bug
    restricted_fields: list[str]         # fields documented as restricted / role-gated
    accepts_field_selector: bool         # True if ?fields= or selection set param present
    bug_notes: list[str]                 # BUG-XXX / TODO / FIXME inline comments
    raw_snippet: str = ""               # short excerpt for grounding


@dataclass
class SchemaFact:
    """Security-relevant facts about a single database table or GraphQL type."""
    name: str                            # table / type name
    columns: list[str]                   # all column / field names
    ownership_columns: list[str]         # userId, accountId, tenantId, ownerId, etc.
    has_rls: bool                        # Row-Level Security policy mentioned
    has_auth_binding: bool               # binding to auth identity is present
    missing_ownership_fk: bool           # ID-keyed table with no ownership FK
    sensitive_columns: list[str]         # password, token, ssn, credit_card, etc.
    pk_type: Optional[str]               # "uuid", "int_serial", "varchar", "unknown"


@dataclass
class CodeFlowFact:
    """Security-relevant observations from a source code snippet."""
    language: str                        # go, python, java, typescript, etc.
    handler_name: str                    # function / class handling the endpoint
    endpoint_path: str                   # path this handler serves (if detectable)
    auth_check_present: bool
    ownership_check_present: bool
    ownership_check_bypassed: bool       # check is commented-out or wrapped in TODO
    user_id_source: Optional[str]        # where user identity comes from (JWT claim, session, etc.)
    resource_id_source: Optional[str]    # how resource ID is obtained (URL param, body, etc.)
    bug_ids: list[str]                   # e.g. ["BUG-AUTO-901"]
    bypass_evidence: str                 # verbatim code snippet showing the bypass


@dataclass
class AuthModelFact:
    """Authentication and authorization model described in the artifact."""
    scheme: str                          # oauth2, jwt, session, api_key, mtls, saml, etc.
    identity_claim: Optional[str]        # JWT claim carrying user identity (sub, userId, etc.)
    ownership_table: Optional[str]       # DB table binding identity to resources
    ownership_column: Optional[str]      # column in that table holding the user FK
    roles: list[str]                     # named roles (ADMIN, USER, FLEET_MANAGER, etc.)
    explicit_bugs: list[str]             # explicitly noted authorization bugs


@dataclass
class SystemMetaFact:
    """Top-level metadata about the documented system."""
    name: str
    domain: str
    classification: str                  # SENSITIVE, PUBLIC, HIPAA_SCOPE, etc.
    version: Optional[str]
    document_sections: list[str]         # DocSection values detected


# ─── Root fact container ──────────────────────────────────────────────────────

@dataclass
class StructuredDocFacts:
    """All security-relevant facts extracted from one document (or chunk set).

    This is the output of DocFactExtractor and the input to the analysis
    prompt builder.  Empty lists/None mean "not found in document" rather
    than "not applicable".
    """
    system: Optional[SystemMetaFact] = None
    auth_model: Optional[AuthModelFact] = None
    endpoints: list[EndpointFact] = field(default_factory=list)
    schemas: list[SchemaFact] = field(default_factory=list)
    code_flows: list[CodeFlowFact] = field(default_factory=list)
    embedded_har_json: Optional[str] = None   # raw HAR JSON found embedded in doc

    # Aggregate risk signals (set during extraction)
    has_field_selector_endpoints: bool = False   # Gate 1 indicator
    has_write_endpoints_with_restricted_fields: bool = False  # Gate 2 indicator
    has_id_params_without_ownership: bool = False  # Gate 3 indicator
    has_bypassed_auth_checks: bool = False
    has_explicit_bug_notes: bool = False
    doc_sections_found: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return (
            self.system is None
            and not self.endpoints
            and not self.schemas
            and not self.code_flows
            and self.embedded_har_json is None
        )

    def to_prompt_block(self) -> str:
        """Render compact, LLM-readable fact summary for injection into prompt.

        Design goals:
        - Short enough to fit in a 512-token context window slice
        - High signal: only security-relevant facts, no boilerplate
        - Verbatim excerpts preserved for downstream evidence grounding
        """
        lines: list[str] = []

        if self.system:
            s = self.system
            lines.append(f"## SYSTEM: {s.name} | {s.domain} | {s.classification}")
            if s.version:
                lines.append(f"Version: {s.version}")
            lines.append(f"Sections detected: {', '.join(s.document_sections)}")
            lines.append("")

        if self.auth_model:
            a = self.auth_model
            lines.append(f"## AUTH MODEL: {a.scheme}")
            if a.identity_claim:
                lines.append(f"Identity claim: {a.identity_claim}")
            if a.ownership_table:
                lines.append(f"Ownership binding: {a.ownership_table}.{a.ownership_column}")
            if a.roles:
                lines.append(f"Roles: {', '.join(a.roles)}")
            if a.explicit_bugs:
                lines.append(f"⚠ Explicit auth bugs: {'; '.join(a.explicit_bugs)}")
            lines.append("")

        if self.schemas:
            lines.append("## SCHEMAS")
            for s in self.schemas:
                flag = ""
                if s.missing_ownership_fk:
                    flag = " [⚠ NO OWNERSHIP FK]"
                if not s.has_auth_binding:
                    flag += " [⚠ NO AUTH BINDING]"
                ownership_str = (
                    f" | ownership: {', '.join(s.ownership_columns)}"
                    if s.ownership_columns else " | NO OWNERSHIP COLUMN"
                )
                sensitive_str = (
                    f" | sensitive: {', '.join(s.sensitive_columns)}"
                    if s.sensitive_columns else ""
                )
                lines.append(
                    f"  {s.name}{flag}{ownership_str}{sensitive_str} | pk={s.pk_type}"
                )
            lines.append("")

        if self.endpoints:
            lines.append("## ENDPOINTS")
            for e in self.endpoints:
                flags: list[str] = []
                if e.accepts_field_selector:
                    flags.append("GATE1:field-selector")
                if e.body_fields and e.restricted_fields:
                    flags.append("GATE2:restricted-fields")
                if e.path_params and not e.ownership_check_present:
                    flags.append("GATE3:no-ownership-check")
                if e.ownership_check_bypassed:
                    flags.append("⚠BYPASSED")
                if e.bug_notes:
                    flags.append(f"BUG:{e.bug_notes[0][:40]}")
                flag_str = f" [{', '.join(flags)}]" if flags else ""
                auth_str = "auth✓" if e.auth_required else "⚠NO-AUTH"
                params_str = ""
                if e.query_params:
                    params_str += f" ?{'+'.join(e.query_params)}"
                if e.path_params:
                    params_str += f" id:{'+'.join(e.path_params)}"
                lines.append(
                    f"  {e.method} {e.path}{params_str} [{auth_str}]{flag_str}"
                )
            lines.append("")

        if self.code_flows:
            lines.append("## CODE FLOWS")
            for c in self.code_flows:
                status = []
                if not c.auth_check_present:
                    status.append("⚠NO-AUTH-CHECK")
                if c.ownership_check_bypassed:
                    status.append("⚠OWNERSHIP-BYPASSED")
                elif not c.ownership_check_present:
                    status.append("⚠NO-OWNERSHIP-CHECK")
                if c.bug_ids:
                    status.append(f"BUG:{','.join(c.bug_ids)}")
                status_str = f" [{', '.join(status)}]" if status else " [OK]"
                lines.append(
                    f"  {c.language}::{c.handler_name} → {c.endpoint_path}{status_str}"
                )
                if c.bypass_evidence:
                    lines.append(f"    BYPASS: {c.bypass_evidence[:120]}")
            lines.append("")

        # Risk summary
        risk: list[str] = []
        if self.has_field_selector_endpoints:
            risk.append("GATE1:field-selector-present")
        if self.has_write_endpoints_with_restricted_fields:
            risk.append("GATE2:restricted-fields-in-write")
        if self.has_id_params_without_ownership:
            risk.append("GATE3:id-param-no-ownership")
        if self.has_bypassed_auth_checks:
            risk.append("BYPASSED-AUTH-CODE")
        if self.has_explicit_bug_notes:
            risk.append("EXPLICIT-BUG-NOTES")
        if risk:
            lines.append(f"## RISK SIGNALS: {' | '.join(risk)}")

        return "\n".join(lines).strip()
