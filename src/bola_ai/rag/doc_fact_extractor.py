"""Deterministic pre-step: extract security-relevant facts from heterogeneous
documentation before the LLM sees it.

This module implements the DocTypeDetector (classify what is in the text) and
DocFactExtractor (produce StructuredDocFacts for each detected section type).

Design philosophy mirrors the HAR-side HarExtractor → FactIndex pipeline:
  1. Deterministic – no LLM involved; pure regex / parse
  2. Type-aware – each section type has its own extractor strategy
  3. Compact output – facts are condensed, not the raw text

Supported section types and their extraction strategies:

  ARCH_SPEC     → system name / domain / auth model / explicit bug notes
  SQL_SCHEMA    → tables, ownership columns, FK bindings, sensitive fields
  SOURCE_CODE   → handlers, auth checks (present/bypassed), BUG comments
  REST_CONTRACT → endpoints, path/query params, restricted fields, auth
  GRAPHQL_SCHEMA→ types with ID fields, queries/mutations, auth directives
  EMBEDDED_HAR  → detected and passed to HarExtractor for PRISM-HAR path
  OPENAPI_YAML  → paths, security schemes, operation parameters
  USER_GUIDE    → plain prose; minimal fact extraction (risk hints only)
  LOG_TRACE     → structured log lines; minimal extraction
"""

from __future__ import annotations

import json
import re
from typing import Optional

from bola_ai.logging_config import get_logger
from bola_ai.rag.doc_facts import (
    AuthModelFact,
    CodeFlowFact,
    DocSection,
    EndpointFact,
    SchemaFact,
    StructuredDocFacts,
    SystemMetaFact,
)

logger = get_logger("doc_fact_extractor")

# ─── Regex bank ──────────────────────────────────────────────────────────────

# Architecture spec markers
_ARCH_SPEC_MARKERS = re.compile(
    r"(ENGINEERING ARCHITECTURE SPECIFICATION|System Name:|Document Version:|"
    r"Executive Summary|architecture overview)",
    re.I,
)
# SQL markers
_SQL_CREATE_RE = re.compile(r"\bCREATE\s+TABLE\s+", re.I)
_SQL_ALTER_RE  = re.compile(r"\bALTER\s+TABLE\s+", re.I)

# Source code fences
_CODE_FENCE_RE = re.compile(
    r"```(go|python|java|typescript|javascript|rust|csharp|c\+\+|kotlin|swift|php|ruby)",
    re.I,
)
# API contract markers
_HTTP_VERB_PATH_RE = re.compile(
    r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/[^\s\"'<>\n]+)",
    re.I,
)
# GraphQL markers
_GRAPHQL_RE = re.compile(
    r"(type\s+Query\s*\{|type\s+Mutation\s*\{|mutation\s+\w+\s*\(|query\s+\{|"
    r"GraphQL|graphql_schema|__schema)",
    re.I,
)
# OpenAPI markers
_OPENAPI_RE = re.compile(
    r"(openapi:\s*[\"']?3\.|swagger:\s*[\"']?2\.|paths:\s*\n\s+/)",
    re.I,
)
# HAR markers
_HAR_RE = re.compile(
    r'"startedDateTime"\s*:\s*"[^"]+"\s*,\s*"time"',
    re.I,
)
# Event schema markers
_EVENT_RE = re.compile(
    r"(kafka|rabbitmq|mqtt|sqs|sns|event\s+bus|message\s+schema|pubsub)",
    re.I,
)
# Log trace markers
_LOG_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}.*?(INFO|WARN|ERROR|DEBUG|FATAL)|"
    r"\[ACCESS\]|\[ERROR\]|\[WARN\])",
    re.I,
)

# Ownership columns
_OWNERSHIP_COL_RE = re.compile(
    r"\b(user_id|userId|account_id|accountId|tenant_id|tenantId|owner_id|ownerId|"
    r"customer_id|customerId|org_id|orgId|workspace_id|workspaceId|"
    r"patient_id|patientId|employee_id|employeeId|firm_id|firmId|"
    r"principal_id|principalId|sub_id|subId)\b",
    re.I,
)
# Sensitive columns
_SENSITIVE_COL_RE = re.compile(
    r"\b(password|passwd|secret|token|api_key|apiKey|ssn|credit_card|"
    r"card_number|private_key|refresh_token|session_token)\b",
    re.I,
)
# Field selector query params
_FIELD_SELECTOR_RE = re.compile(
    r"[\?&]?(fields|columns|\$select|attributes|properties)\s*=",
    re.I,
)
# Query param extraction
_QUERY_PARAM_RE = re.compile(r"[\?&]([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=", re.I)
# Path param extraction
_PATH_PARAM_RE = re.compile(r"/\{([^}]+)\}|/:([a-zA-Z_][a-zA-Z0-9_]*)")
# Bug/bypass comment markers
_BUG_RE = re.compile(
    r"(BUG-[A-Z0-9\-]+|TODO[:\s][^\n]+|FIXME[:\s][^\n]+|"
    r"skip.*ownership|skip.*auth|missing.*check|commented.out|"
    r"SKIPPED|developers skipped|reduce.*latency.*skip)",
    re.I,
)
# Bypassed ownership check patterns
_BYPASSED_OWNERSHIP_RE = re.compile(
    r"(CheckOwnership|checkOwnership|check_ownership|verifyOwner|verify_owner|"
    r"isOwner|is_owner|hasAccess|has_access|canAccess|can_access)"
    r"[^}]{0,200}"
    r"(/\*|//.*skip|//.*TODO|//.*BUG|#.*skip|#.*TODO)",
    re.I | re.S,
)
# Auth check markers in code
_AUTH_CHECK_RE = re.compile(
    r"(authenticate|authorize|verify.*token|decode.*jwt|validate.*bearer|"
    r"require_auth|@Auth|@Authenticated|@secured|middleware.*auth|"
    r"c\.Get\([\"']user_id[\"']\)|request\.user|ctx\.user|getUser\()",
    re.I,
)
# Roles
_ROLES_RE = re.compile(
    r"[\"'`](ADMIN|OWNER|VIEWER|EDITOR|MEMBER|USER|FLEET_MANAGER|LESSEE|"
    r"MANAGER|READONLY|SUPERADMIN|OPERATOR|ANALYST)[\"'`]",
    re.I,
)
# Auth scheme
_AUTH_SCHEME_RE = re.compile(
    r"\b(OAuth\s*2\.0|JWT|Bearer|mTLS|mutual\s+TLS|SAML|API.?key|"
    r"Basic\s+auth|session|cookie|HMAC|X\.509|certificate)\b",
    re.I,
)
# Identity claim
_IDENTITY_CLAIM_RE = re.compile(
    r'"(sub|user_id|userId|account_id|accountId|principal_id|principalId)"',
    re.I,
)
# CREATE TABLE name extraction
_TABLE_NAME_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"\[]?(\w+)[`\"\]]?",
    re.I,
)
# Column definition line
_COLUMN_DEF_RE = re.compile(
    r"^\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+(VARCHAR|TEXT|INT|BIGINT|UUID|BOOLEAN|"
    r"DATE|TIMESTAMP|SERIAL|FLOAT|DOUBLE|DECIMAL|JSON|JSONB)",
    re.I | re.M,
)
# PK type detection
_UUID_PK_RE = re.compile(r"UUID\s+PRIMARY\s+KEY|gen_random_uuid\(\)", re.I)
_INT_PK_RE  = re.compile(r"SERIAL\s+PRIMARY\s+KEY|INT.*PRIMARY\s+KEY", re.I)

# Code fence language extraction
_FENCE_LANG_RE = re.compile(r"```(\w+)")
_FUNC_NAME_RE = re.compile(
    r"\b(?:func|def|function|async\s+function)\s+(\w+)\s*\(",
    re.I,
)

# Restricted / role-gated field hints
_RESTRICTED_FIELD_RE = re.compile(
    r"(restricted|role.?gated|privileged|admin.?only|not.*accessible|"
    r"cannot.*modify|should.*not.*set|read.?only\s+field)",
    re.I,
)

# System name from arch spec
_SYSTEM_NAME_RE = re.compile(
    r"\*\*System\s+Name:\*\*\s*(.+)|System\s+Name:\s*(.+)|"
    r"#\s+(.+?)\s*\n.*(?:API|Platform|Service)",
    re.I,
)
_DOMAIN_RE = re.compile(r"\*\*Domain:\*\*\s*(.+)|\bDomain:\s*(.+)", re.I)
_CLASSIFICATION_RE = re.compile(
    r"\*\*Classification:\*\*\s*(.+)|Classification:\s*(.+)",
    re.I,
)
_VERSION_RE = re.compile(
    r"\*\*Document\s+Version:\*\*\s*(.+)|Version:\s*([\d\.]+)",
    re.I,
)


# ─── DocTypeDetector ─────────────────────────────────────────────────────────

class DocTypeDetector:
    """Classify which section types are present in a document or chunk set.

    Operates on plain text (does not tokenize). Designed to be fast – just
    regex scans, no expensive computation.
    """

    @staticmethod
    def detect(text: str) -> list[DocSection]:
        """Return an ordered list of DocSection types found in *text*.

        The list is ordered by detection confidence, not document order.
        """
        detected: list[DocSection] = []
        t = text  # keep original case for code/HAR detection

        # Highest-signal checks first (mutually exclusive sections)
        if _HAR_RE.search(t):
            detected.append(DocSection.EMBEDDED_HAR)
        if _SQL_CREATE_RE.search(t) or _SQL_ALTER_RE.search(t):
            detected.append(DocSection.SQL_SCHEMA)
        if _CODE_FENCE_RE.search(t):
            detected.append(DocSection.SOURCE_CODE)
        if _GRAPHQL_RE.search(t):
            detected.append(DocSection.GRAPHQL_SCHEMA)
        if _OPENAPI_RE.search(t):
            detected.append(DocSection.OPENAPI_YAML)
        if _HTTP_VERB_PATH_RE.search(t) and DocSection.OPENAPI_YAML not in detected:
            detected.append(DocSection.REST_CONTRACT)
        if _ARCH_SPEC_MARKERS.search(t):
            detected.append(DocSection.ARCH_SPEC)
        if _EVENT_RE.search(t):
            detected.append(DocSection.EVENT_SCHEMA)
        if _LOG_RE.search(t):
            detected.append(DocSection.LOG_TRACE)
        if not detected:
            detected.append(DocSection.USER_GUIDE)

        return detected


# ─── Per-type extractors ──────────────────────────────────────────────────────

def _extract_system_meta(text: str, sections: list[DocSection]) -> Optional[SystemMetaFact]:
    name = ""
    # Priority: prefer explicit "System Name:" field over document title heading
    explicit_name_re = re.compile(
        r"\*\*System\s+Name:\*\*\s*([^\n]+)|\bSystem\s+Name:\s*([^\n]+)",
        re.I,
    )
    m = explicit_name_re.search(text)
    if m:
        name = next(g for g in m.groups() if g).strip(" *")
    if not name:
        m = _SYSTEM_NAME_RE.search(text)
        if m:
            name = next(g for g in m.groups() if g).strip(" *")
    if not name:
        return None

    domain = ""
    m = _DOMAIN_RE.search(text)
    if m:
        domain = next(g for g in m.groups() if g).strip(" *")

    classification = "UNSPECIFIED"
    m = _CLASSIFICATION_RE.search(text)
    if m:
        classification = next(g for g in m.groups() if g).strip(" *")

    version = None
    m = _VERSION_RE.search(text)
    if m:
        version = next(g for g in m.groups() if g).strip(" *")

    return SystemMetaFact(
        name=name,
        domain=domain,
        classification=classification,
        version=version,
        document_sections=[s.value for s in sections],
    )


def _extract_auth_model(text: str) -> Optional[AuthModelFact]:
    scheme_match = _AUTH_SCHEME_RE.search(text)
    if not scheme_match:
        return None

    scheme = scheme_match.group(0).strip()

    claim_match = _IDENTITY_CLAIM_RE.search(text)
    claim = claim_match.group(1) if claim_match else None

    # Look for an ownership binding table (e.g. vehicle_ownership, user_resources)
    own_tbl_re = re.compile(
        r"\b(\w*ownership\w*|\w*binding\w*|\w*membership\w*)\b",
        re.I,
    )
    own_tbl_match = own_tbl_re.search(text)
    ownership_table = own_tbl_match.group(1) if own_tbl_match else None
    ownership_col = None
    if ownership_table:
        col_m = _OWNERSHIP_COL_RE.search(text)
        ownership_col = col_m.group(0) if col_m else None

    roles = list(dict.fromkeys(m.group(1).upper() for m in _ROLES_RE.finditer(text)))

    bugs = []
    for m in _BUG_RE.finditer(text):
        b = m.group(0).strip()[:80]
        if b not in bugs:
            bugs.append(b)

    if not (scheme or claim or ownership_table or bugs):
        return None

    return AuthModelFact(
        scheme=scheme,
        identity_claim=claim,
        ownership_table=ownership_table,
        ownership_column=ownership_col,
        roles=roles[:8],
        explicit_bugs=bugs[:5],
    )


def _extract_sql_schemas(text: str) -> list[SchemaFact]:
    """Parse CREATE TABLE blocks and extract security-relevant column facts."""
    schemas: list[SchemaFact] = []

    # Split on CREATE TABLE boundaries
    table_blocks = _SQL_CREATE_RE.split(text)[1:]  # skip text before first CREATE
    for raw_block in table_blocks:
        # Extract table name
        name_m = _TABLE_NAME_RE.search("CREATE TABLE " + raw_block[:120])
        if not name_m:
            continue
        table_name = name_m.group(1)

        # Grab the columns section (up to closing parenthesis or double blank line)
        paren_depth = 0
        lines: list[str] = []
        for line in raw_block.splitlines():
            paren_depth += line.count("(") - line.count(")")
            lines.append(line)
            if paren_depth <= 0 and lines:
                break
        block_text = "\n".join(lines)

        columns = [m.group(1) for m in _COLUMN_DEF_RE.finditer(block_text)]
        ownership_cols = [c for c in columns if _OWNERSHIP_COL_RE.match(c)]
        sensitive_cols = [c for c in columns if _SENSITIVE_COL_RE.match(c)]

        # Detect PK type
        if _UUID_PK_RE.search(block_text):
            pk_type = "uuid"
        elif _INT_PK_RE.search(block_text):
            pk_type = "int_serial"
        else:
            pk_type = "unknown"

        has_rls = bool(re.search(r"\bROW\s+LEVEL\s+SECURITY\b", block_text, re.I))
        has_auth_binding = bool(ownership_cols)
        missing_ownership_fk = bool(columns) and not ownership_cols

        schemas.append(SchemaFact(
            name=table_name,
            columns=columns[:20],
            ownership_columns=ownership_cols,
            has_rls=has_rls,
            has_auth_binding=has_auth_binding,
            missing_ownership_fk=missing_ownership_fk,
            sensitive_columns=sensitive_cols,
            pk_type=pk_type,
        ))

    return schemas


def _extract_endpoints(text: str) -> list[EndpointFact]:
    """Extract REST endpoints from API contract prose or code comments."""
    endpoints: list[EndpointFact] = []
    seen: set[str] = set()

    for m in _HTTP_VERB_PATH_RE.finditer(text):
        method = m.group(1).upper()
        path = m.group(2).rstrip(".,;")

        key = f"{method} {path}"
        if key in seen:
            continue
        seen.add(key)

        # Grab surrounding context (200 chars each side)
        start = max(0, m.start() - 200)
        end = min(len(text), m.end() + 400)
        context = text[start:end]

        path_params = list(dict.fromkeys(
            p for g in _PATH_PARAM_RE.findall(path) for p in g if p
        ))
        query_params = list(dict.fromkeys(
            m2.group(1) for m2 in _QUERY_PARAM_RE.finditer(context)
        ))
        accepts_field_selector = bool(_FIELD_SELECTOR_RE.search(path + context))

        auth_required = bool(_AUTH_CHECK_RE.search(context)) or bool(
            re.search(r"Authorization|Bearer|JWT|auth", context, re.I)
        )
        ownership_check_present = bool(re.search(
            r"(checkOwnership|check_ownership|ownership.*check|"
            r"verifyOwner|isOwner|has_access|canAccess|"
            r"belongs_to|belongsTo)",
            context, re.I,
        ))
        ownership_check_bypassed = bool(_BYPASSED_OWNERSHIP_RE.search(context))

        bug_notes = [m3.group(0)[:60] for m3 in _BUG_RE.finditer(context)]

        restricted_fields: list[str] = []
        if _RESTRICTED_FIELD_RE.search(context):
            # Try to pull field names from surrounding text
            restricted_fields = re.findall(
                r'"([a-zA-Z_][a-zA-Z0-9_]*)"(?=[^"]*(?:restricted|role|admin))',
                context, re.I,
            )[:5]

        # Body fields from JSON schema snippets nearby
        body_fields = re.findall(
            r'"([a-zA-Z_][a-zA-Z0-9_]+)"\s*:\s*"(?:string|integer|boolean|number)',
            context,
        )[:10]

        endpoints.append(EndpointFact(
            method=method,
            path=path,
            path_params=path_params,
            query_params=query_params,
            body_fields=body_fields,
            auth_required=auth_required,
            ownership_check_present=ownership_check_present,
            ownership_check_bypassed=ownership_check_bypassed,
            restricted_fields=restricted_fields,
            accepts_field_selector=accepts_field_selector,
            bug_notes=bug_notes[:3],
            raw_snippet=context[:200],
        ))

    return endpoints


def _extract_code_flows(text: str) -> list[CodeFlowFact]:
    """Extract security-relevant facts from fenced code blocks."""
    flows: list[CodeFlowFact] = []

    # Find all fenced code blocks
    fence_blocks = re.split(r"```\w*\n?", text)
    lang_matches = list(_FENCE_LANG_RE.finditer(text))

    for i, block in enumerate(fence_blocks[1::2], 0):  # odd-indexed = inside fence
        # Determine language
        language = lang_matches[i].group(1).lower() if i < len(lang_matches) else "unknown"
        if len(block.strip()) < 30:
            continue

        # Handler / function name
        func_m = _FUNC_NAME_RE.search(block)
        handler_name = func_m.group(1) if func_m else "(anonymous)"

        # Endpoint path this handler serves
        path_m = _HTTP_VERB_PATH_RE.search(block)
        endpoint_path = path_m.group(2) if path_m else "(unknown)"

        # Auth check
        auth_present = bool(_AUTH_CHECK_RE.search(block))

        # Ownership check
        own_present = bool(re.search(
            r"(checkOwnership|check_ownership|verifyOwner|isOwner|has_access|"
            r"belongsTo|CheckOwnership)",
            block, re.I,
        ))
        own_bypassed = bool(_BYPASSED_OWNERSHIP_RE.search(block))

        # If there's a comment showing a check is commented out
        if not own_bypassed and re.search(
            r"(/\*.*?check.*?\*/|//.*?skip.*?check|#.*?skip.*?check|"
            r"/\*.*?FIX.*?\*/)",
            block, re.I | re.S,
        ):
            own_bypassed = True

        # Bug IDs
        bug_ids = list(dict.fromkeys(
            m.group(0) for m in re.finditer(r"BUG-[A-Z0-9\-]+", block)
        ))

        # Bypass evidence — the commented-out block
        bypass_evidence = ""
        bypass_m = re.search(
            r"(//.*?skip[^\n]*|/\*[^*]*\*/|#.*?skip[^\n]*)",
            block, re.I | re.S,
        )
        if bypass_m:
            bypass_evidence = bypass_m.group(0)[:200].strip()

        # User identity source
        uid_m = re.search(
            r"c\.Get\([\"']user_id[\"']\)|request\.user|ctx\.user|"
            r"claims\[.user.\]|token\.sub|getUser\(",
            block, re.I,
        )
        uid_source = uid_m.group(0) if uid_m else None

        # Resource ID source
        rid_m = re.search(
            r"c\.Param\([\"'][^\"']+[\"']\)|request\.params\.|"
            r"args\['[^']+'\]|path_param|getPathParam",
            block, re.I,
        )
        rid_source = rid_m.group(0) if rid_m else None

        flows.append(CodeFlowFact(
            language=language,
            handler_name=handler_name,
            endpoint_path=endpoint_path,
            auth_check_present=auth_present,
            ownership_check_present=own_present,
            ownership_check_bypassed=own_bypassed,
            user_id_source=uid_source,
            resource_id_source=rid_source,
            bug_ids=bug_ids,
            bypass_evidence=bypass_evidence,
        ))

    return flows


def _extract_embedded_har(text: str) -> Optional[str]:
    """Find and return the first HAR JSON blob embedded in the document."""
    # Find the outermost JSON object that looks like a HAR
    har_start_re = re.compile(r'(\{[^{]*"log"\s*:\s*\{)')
    m = har_start_re.search(text)
    if not m:
        return None

    # Walk forward to find balanced braces
    start = m.start()
    depth = 0
    for i, ch in enumerate(text[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start : i + 1]
                # Validate it's actually HAR
                try:
                    data = json.loads(candidate)
                    if "log" in data and "entries" in data.get("log", {}):
                        return candidate
                except (json.JSONDecodeError, ValueError):
                    return candidate  # return raw text for partial HAR
                break

    return None


# ─── Main extractor ───────────────────────────────────────────────────────────

class DocFactExtractor:
    """Main entry-point.  Call extract(text) to get StructuredDocFacts.

    Typical usage (in runner.py before the LLM call):

        extractor = DocFactExtractor()
        facts = extractor.extract(evidence_str)
        if not facts.is_empty():
            context = facts.to_prompt_block() + "\\n\\n" + context
    """

    def extract(self, text: str) -> StructuredDocFacts:
        """Detect document sections and extract facts from each."""
        if not text or not text.strip():
            return StructuredDocFacts()

        sections = DocTypeDetector.detect(text)
        facts = StructuredDocFacts(doc_sections_found=[s.value for s in sections])

        logger.debug(
            "DocFactExtractor detected sections: %s",
            [s.value for s in sections],
        )

        # System metadata (from ARCH_SPEC)
        if DocSection.ARCH_SPEC in sections:
            facts.system = _extract_system_meta(text, sections)

        # Auth model (cross-cutting — present in most doc types)
        facts.auth_model = _extract_auth_model(text)

        # SQL schemas
        if DocSection.SQL_SCHEMA in sections:
            facts.schemas = _extract_sql_schemas(text)

        # REST endpoints (from contract prose AND code)
        if DocSection.REST_CONTRACT in sections or DocSection.SOURCE_CODE in sections:
            facts.endpoints = _extract_endpoints(text)

        # Code flows
        if DocSection.SOURCE_CODE in sections:
            facts.code_flows = _extract_code_flows(text)

        # Embedded HAR (defer to HarExtractor in pipeline)
        if DocSection.EMBEDDED_HAR in sections:
            facts.embedded_har_json = _extract_embedded_har(text)

        # ── Aggregate risk signals ──────────────────────────────────────────
        facts.has_field_selector_endpoints = any(
            e.accepts_field_selector for e in facts.endpoints
        )
        facts.has_write_endpoints_with_restricted_fields = any(
            e.method in ("POST", "PUT", "PATCH") and e.restricted_fields
            for e in facts.endpoints
        )
        facts.has_id_params_without_ownership = any(
            e.path_params and not e.ownership_check_present
            for e in facts.endpoints
        )
        facts.has_bypassed_auth_checks = any(
            c.ownership_check_bypassed for c in facts.code_flows
        ) or any(
            e.ownership_check_bypassed for e in facts.endpoints
        )
        facts.has_explicit_bug_notes = (
            (facts.auth_model is not None and bool(facts.auth_model.explicit_bugs))
            or any(bool(e.bug_notes) for e in facts.endpoints)
            or any(bool(c.bug_ids) for c in facts.code_flows)
        )

        return facts

    def extract_from_chunks(self, chunks: list[dict]) -> StructuredDocFacts:
        """Extract facts from a list of RAG chunk dicts (each has 'content' key)."""
        combined = "\n\n".join(c.get("content", "") for c in chunks)
        return self.extract(combined)
