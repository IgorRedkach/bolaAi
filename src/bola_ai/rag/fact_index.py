"""In-memory index of observable facts from a StructuredArtifact.

The FactIndex is used by the FindingValidator to ground every claim in the
LLM's output against facts that can be mechanically verified from the parsed
HAR. This ensures zero hallucination: if it wasn't in the HAR, the validator
will reject the finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from bola_ai.rag.har_extractor import HarEntry, StructuredArtifact
from bola_ai.logging_config import get_logger

logger = get_logger("fact_index")


@dataclass
class EntryFacts:
    """Immutable facts observable for one HAR entry."""
    entry_id: int
    method: str
    url: str
    path: str
    host: str
    auth_header_present: bool
    auth_header_prefix: Optional[str]
    response_status: int
    path_id_segments: list[str]
    response_body_text: str
    full_text: str

    def contains(self, substring: str) -> bool:
        return substring in self.full_text

    def has_status(self, status: int) -> bool:
        return self.response_status == status


@dataclass
class FactIndex:
    """All verifiable facts derived from a StructuredArtifact.

    Built once before the LLM call; consulted by FindingValidator after.
    """
    entries: dict[int, EntryFacts] = field(default_factory=dict)
    all_host_set: frozenset[str] = field(default_factory=frozenset)
    all_path_ids: frozenset[str] = field(default_factory=frozenset)
    sequential_int_ids: bool = False
    distinct_id_values: list[str] = field(default_factory=list)
    cross_customer_confirmed: bool = False
    batch_endpoint_present: bool = False

    def has_entry(self, entry_id: int) -> bool:
        return entry_id in self.entries

    def entry_contains(self, entry_id: int, substring: str) -> bool:
        e = self.entries.get(entry_id)
        if e is None:
            return False
        return e.contains(substring)

    def entry_status(self, entry_id: int) -> Optional[int]:
        e = self.entries.get(entry_id)
        return e.response_status if e else None

    def entry_has_auth(self, entry_id: int) -> bool:
        e = self.entries.get(entry_id)
        return bool(e and e.auth_header_present)

    @classmethod
    def build(cls, artifact: StructuredArtifact) -> "FactIndex":
        idx = cls()
        idx.all_host_set = frozenset(artifact.hosts)
        idx.sequential_int_ids = artifact.has_sequential_int_ids
        idx.batch_endpoint_present = artifact.has_batch_endpoints

        all_path_ids: list[str] = []
        for entry in artifact.entries:
            ef = _build_entry_facts(entry)
            idx.entries[entry.id] = ef
            all_path_ids.extend(entry.path_id_segments)

        idx.all_path_ids = frozenset(all_path_ids)
        idx.cross_customer_confirmed = _detect_cross_customer(artifact.entries)
        idx.distinct_id_values = list(dict.fromkeys(all_path_ids))
        return idx


def _build_entry_facts(e: HarEntry) -> EntryFacts:
    auth_val = next(
        (v for k, v in e.request_headers.items() if k.lower() == "authorization"),
        None,
    )
    auth_present = auth_val is not None
    auth_prefix: Optional[str] = None
    if auth_val:
        parts = auth_val.split(" ", 1)
        if len(parts) == 2:
            auth_prefix = parts[0]

    # Build the full text used for evidence quote grounding. This must match
    # exactly the condensed text that was sent to the model.
    full_text = e.to_condensed_text()

    return EntryFacts(
        entry_id=e.id,
        method=e.method,
        url=e.url,
        path=e.path,
        host=e.host,
        auth_header_present=auth_present,
        auth_header_prefix=auth_prefix,
        response_status=e.response_status,
        path_id_segments=e.path_id_segments,
        response_body_text=e.response_body_excerpt or "",
        full_text=full_text,
    )


_OWNER_FIELDS = re.compile(
    r'"(userId|ownerId|customerId|tenantId|accountId|carrierId|patientId|'
    r'employeeId|firmId|orgId|workspaceId)":\s*"?([^",}\s]+)"?',
    re.IGNORECASE,
)


def _detect_cross_customer(entries: list[HarEntry]) -> bool:
    """True if the same ownership-style field has two distinct values across entries."""
    from collections import defaultdict
    by_field: dict[str, set[str]] = defaultdict(set)
    for e in entries:
        text = e.response_body_excerpt or ""
        for match in _OWNER_FIELDS.finditer(text):
            field_name = match.group(1).lower()
            field_val = match.group(2).strip('"')
            by_field[field_name].add(field_val)
    return any(len(vals) >= 2 for vals in by_field.values())
