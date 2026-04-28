"""Deterministic HAR parser for the PRISM-HAR pipeline.

Extracts all security-relevant structure from an HTTP Archive (HAR) JSON file
without any LLM involvement. Returns a StructuredArtifact that the analyzer and
the fact validator both consume.

The extractor:
  - classifies each entry as auth-flow / analytics / static-resource /
    internal-endpoint / security-relevant
  - normalises request headers to a small security-relevant subset
  - parses URL-encoded and JSON POST bodies
  - detects sequential integer IDs across entries
  - builds a condensed ENTRIES LIST text that the analyzer model receives
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qs, urlparse

from bola_ai.logging_config import get_logger

logger = get_logger("har_extractor")

# ── Security-relevant headers to keep ────────────────────────────────────────

_KEEP_REQ_HEADERS: frozenset[str] = frozenset({
    "authorization", "cookie", "x-tenant-id", "x-org-id", "x-organization-id",
    "x-workspace-id", "x-client-id", "x-user-id", "x-forwarded-for",
    "x-api-key", "x-auth-token", "x-service-name", "content-type",
})
_KEEP_RESP_HEADERS: frozenset[str] = frozenset({
    "cache-control", "vary", "etag", "set-cookie", "www-authenticate",
    "x-frame-options", "content-type",
})

# ── Noise-classification patterns ─────────────────────────────────────────────

_AUTH_PATH_RE = re.compile(
    r"/(oauth|auth|login|token|refresh|connect|authorize|logout|sso|saml|oidc)",
    re.IGNORECASE,
)
_AUTH_BODY_KEYS: frozenset[str] = frozenset({
    "grant_type", "client_id", "refresh_token", "code", "client_secret",
    "response_type", "redirect_uri",
})
_ANALYTICS_HOST_RE = re.compile(
    r"(analytics\.|telemetry\.|tracking\.|metrics\.|datadog|amplitude|mixpanel|"
    r"segment\.io|hotjar|fullstory|\.rum\.|beacon\.|sentry\.io)",
    re.IGNORECASE,
)
_ANALYTICS_PATH_RE = re.compile(
    r"/(collect|track|events?|beacon|ping|rum|ingest|metric|log|heartbeat)",
    re.IGNORECASE,
)
_STATIC_EXT_RE = re.compile(
    r"\.(css|js|jsx|ts|tsx|woff2?|ttf|eot|png|jpg|jpeg|gif|ico|svg|map|webp"
    r"|wasm|gz|zip|pdf)(\?|$)",
    re.IGNORECASE,
)
_INTERNAL_PATH_RE = re.compile(
    r"/(health|status|version|metrics|favicon\.ico|ping|__webpack|livereload)",
    re.IGNORECASE,
)
_INTERNAL_METHOD_RE = re.compile(r"^OPTIONS$", re.IGNORECASE)

# ── ID pattern detection in URL path segments ─────────────────────────────────

_INT_ID_RE = re.compile(r"^\d{4,}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_SF_ID_RE = re.compile(r"^[0-9A-Za-z]{15}([0-9A-Za-z]{3})?$")
_CUSTOM_ID_RE = re.compile(r"^[A-Z]+-\d{3,}(-\d{2,})?$")


@dataclass
class HarEntry:
    id: int
    method: str
    url: str
    host: str
    path: str
    query_string: dict[str, list[str]]
    request_headers: dict[str, str]
    body_text: Optional[str]
    body_params: dict[str, str]
    body_json: Optional[dict]
    response_status: int
    response_headers: dict[str, str]
    response_body_excerpt: Optional[str]
    content_type: Optional[str]
    path_id_segments: list[str]
    is_auth_flow: bool
    is_analytics: bool
    is_static_resource: bool
    is_internal_endpoint: bool

    @property
    def is_noise(self) -> bool:
        return (self.is_auth_flow or self.is_analytics
                or self.is_static_resource or self.is_internal_endpoint)

    def to_condensed_text(self) -> str:
        """Render this entry as the condensed text the analyzer model sees."""
        lines = [
            f"Method: {self.method}",
            f"URL: {self.url}",
            f"Path: {self.path}",
        ]
        if self.query_string:
            lines.append("Query Params:")
            for k, v in self.query_string.items():
                lines.append(f"  {k}: {v[0]}")
        sec_headers = {
            k: v for k, v in self.request_headers.items()
            if k.lower() in _KEEP_REQ_HEADERS
        }
        resp_sec_headers = {
            k: v for k, v in self.response_headers.items()
            if k.lower() in _KEEP_RESP_HEADERS
        }
        all_headers = {**sec_headers, **resp_sec_headers}
        if all_headers:
            lines.append("Headers:")
            for k, v in all_headers.items():
                lines.append(f"  {k}: {v}")
        if self.body_json:
            body_str = json.dumps(self.body_json, indent=2)
            if len(body_str) > 600:
                body_str = body_str[:600] + "\n  ..."
            lines.append("Body (JSON):")
            for bl in body_str.splitlines():
                lines.append(f"  {bl}")
        elif self.body_params:
            lines.append("Body (form-encoded):")
            for k, v in self.body_params.items():
                lines.append(f"  {k}={v}")
        lines.append(f"Response: {self.response_status} {_status_text(self.response_status)}")
        if self.response_body_excerpt:
            lines.append("Response body:")
            lines.append(f"  {self.response_body_excerpt[:300]}")
        return "\n".join(lines)


@dataclass
class AuthContext:
    token_type: Optional[str] = None
    bearer_prefix: Optional[str] = None
    cookie_names: list[str] = field(default_factory=list)


@dataclass
class StructuredArtifact:
    artifact_type: str = "har"
    hosts: list[str] = field(default_factory=list)
    entries: list[HarEntry] = field(default_factory=list)
    auth_context: Optional[AuthContext] = None
    has_sequential_int_ids: bool = False
    has_tenant_params: bool = False
    has_batch_endpoints: bool = False
    entry_count: int = 0
    security_relevant_entry_ids: list[int] = field(default_factory=list)

    def to_entries_list_text(self) -> str:
        """Build the ENTRIES LIST text that the bola-har analyzer model receives."""
        parts = []
        for entry in self.entries:
            entry_text = f"### HAR Entry [{entry.id}]\n{entry.to_condensed_text()}"
            parts.append(entry_text)
        return "\n\n".join(parts)


class HarExtractor:
    """Deterministic HAR JSON → StructuredArtifact.  No LLM involved."""

    def is_har(self, text: str) -> bool:
        try:
            data = json.loads(text.strip())
            return (isinstance(data, dict)
                    and "log" in data
                    and "entries" in data["log"])
        except Exception:
            return False

    def extract(self, raw_text: str) -> Optional[StructuredArtifact]:
        try:
            data = json.loads(raw_text.strip())
        except Exception as exc:
            logger.debug("HAR parse failed: %s", exc)
            return None
        log = data.get("log", {})
        raw_entries = log.get("entries", [])
        if not raw_entries:
            return None

        entries: list[HarEntry] = []
        for idx, raw in enumerate(raw_entries, start=1):
            try:
                entry = self._parse_entry(idx, raw)
                entries.append(entry)
            except Exception as exc:
                logger.debug("Skipping HAR entry %d: %s", idx, exc)

        hosts = list({e.host for e in entries if e.host})
        auth_ctx = self._extract_auth_context(entries)
        sec_ids = [e.id for e in entries if not e.is_noise]

        return StructuredArtifact(
            artifact_type="har",
            hosts=hosts,
            entries=entries,
            auth_context=auth_ctx,
            has_sequential_int_ids=self._detect_sequential_ids(entries),
            has_tenant_params=self._detect_tenant_params(entries),
            has_batch_endpoints=self._detect_batch(entries),
            entry_count=len(entries),
            security_relevant_entry_ids=sec_ids,
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _parse_entry(self, idx: int, raw: dict) -> HarEntry:
        req = raw.get("request", {})
        resp = raw.get("response", {})

        url = req.get("url", "")
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or "/"
        qs = parse_qs(parsed.query)
        method = req.get("method", "GET").upper()

        # Request headers — keep only security-relevant
        req_headers: dict[str, str] = {}
        for h in req.get("headers", []):
            name = h.get("name", "").lower()
            if name in _KEEP_REQ_HEADERS:
                req_headers[h["name"]] = h.get("value", "")
                # Truncate bearer tokens
                if name == "authorization" and "bearer" in h.get("value", "").lower():
                    parts = h["value"].split(" ", 1)
                    if len(parts) == 2 and len(parts[1]) > 40:
                        req_headers[h["name"]] = f"Bearer {parts[1][:40]}..."

        # Response headers
        resp_headers: dict[str, str] = {}
        for h in resp.get("headers", []):
            name = h.get("name", "").lower()
            if name in _KEEP_RESP_HEADERS:
                resp_headers[h["name"]] = h.get("value", "")

        # Body parsing
        post_data = req.get("postData", {}) or {}
        body_text = post_data.get("text", "")
        body_params: dict[str, str] = {}
        body_json: Optional[dict] = None
        ct = (post_data.get("mimeType", "") or "").lower()

        if ct.startswith("application/x-www-form-urlencoded") and body_text:
            for k, v in parse_qs(body_text).items():
                body_params[k] = v[0] if v else ""
        elif ct.startswith("application/json") and body_text:
            try:
                parsed_body = json.loads(body_text)
                if isinstance(parsed_body, dict):
                    body_json = parsed_body
            except Exception:
                pass

        # Response body excerpt
        resp_content = resp.get("content", {}) or {}
        resp_body_text = resp_content.get("text", "")
        resp_excerpt = resp_body_text[:300].strip() if resp_body_text else None

        # Path ID segments
        path_id_segs = [
            seg for seg in path.split("/")
            if seg and self._looks_like_id(seg)
        ]

        entry = HarEntry(
            id=idx,
            method=method,
            url=url,
            host=host,
            path=path,
            query_string=qs,
            request_headers=req_headers,
            body_text=body_text or None,
            body_params=body_params,
            body_json=body_json,
            response_status=resp.get("status", 0),
            response_headers=resp_headers,
            response_body_excerpt=resp_excerpt or None,
            content_type=ct or None,
            path_id_segments=path_id_segs,
            is_auth_flow=False,
            is_analytics=False,
            is_static_resource=False,
            is_internal_endpoint=False,
        )
        return self._classify_entry(entry)

    def _classify_entry(self, e: HarEntry) -> HarEntry:
        if _INTERNAL_METHOD_RE.match(e.method):
            e.is_internal_endpoint = True
            return e
        if _STATIC_EXT_RE.search(e.path):
            e.is_static_resource = True
            return e
        if _INTERNAL_PATH_RE.search(e.path):
            e.is_internal_endpoint = True
            return e
        if _ANALYTICS_HOST_RE.search(e.host) or _ANALYTICS_PATH_RE.search(e.path):
            e.is_analytics = True
            return e
        if _AUTH_PATH_RE.search(e.path):
            e.is_auth_flow = True
            return e
        # Check body keys for auth
        if e.body_params and _AUTH_BODY_KEYS & set(e.body_params.keys()):
            e.is_auth_flow = True
        return e

    def _extract_auth_context(self, entries: list[HarEntry]) -> AuthContext:
        ctx = AuthContext()
        for e in entries:
            for header_name, header_val in e.request_headers.items():
                if header_name.lower() == "authorization":
                    if "bearer" in header_val.lower():
                        ctx.token_type = "Bearer"
                        parts = header_val.split(" ", 1)
                        if len(parts) == 2:
                            ctx.bearer_prefix = parts[1][:40]
                    elif "basic" in header_val.lower():
                        ctx.token_type = "Basic"
                if header_name.lower() == "cookie":
                    names = [c.split("=")[0].strip() for c in header_val.split(";")]
                    ctx.cookie_names.extend(n for n in names if n and n not in ctx.cookie_names)
        return ctx

    def _looks_like_id(self, seg: str) -> bool:
        return bool(
            _INT_ID_RE.match(seg)
            or _UUID_RE.match(seg)
            or _SF_ID_RE.match(seg)
            or _CUSTOM_ID_RE.match(seg)
        )

    def _detect_sequential_ids(self, entries: list[HarEntry]) -> bool:
        """True if any two entries have path integer IDs differing by exactly 1."""
        all_int_ids: list[int] = []
        for e in entries:
            for seg in e.path_id_segments:
                if _INT_ID_RE.match(seg):
                    all_int_ids.append(int(seg))
        if len(all_int_ids) < 2:
            return False
        all_int_ids.sort()
        return any(b - a == 1 for a, b in zip(all_int_ids, all_int_ids[1:]))

    def _detect_tenant_params(self, entries: list[HarEntry]) -> bool:
        tenant_keys = {"tenantid", "orgid", "organizationid", "workspaceid", "clientid"}
        for e in entries:
            for k in e.query_string:
                if k.lower() in tenant_keys:
                    return True
            for k in e.request_headers:
                if k.lower() in {"x-tenant-id", "x-org-id", "x-organization-id",
                                  "x-workspace-id", "x-client-id"}:
                    return True
        return False

    def _detect_batch(self, entries: list[HarEntry]) -> bool:
        for e in entries:
            if e.body_json:
                for v in e.body_json.values():
                    if isinstance(v, list) and len(v) >= 2:
                        return True
        return False


def _status_text(code: int) -> str:
    _MAP = {200: "OK", 201: "Created", 204: "No Content", 206: "Partial Content",
            301: "Moved Permanently", 302: "Found", 400: "Bad Request",
            401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
            405: "Method Not Allowed", 429: "Too Many Requests",
            500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable"}
    return _MAP.get(code, str(code))
