#!/usr/bin/env python3
"""Core generation engine for synthetic security training examples.

Generates rich, varied training examples for:
  - GraphQL vulnerability scenarios (Step 4)
  - Salesforce Aura vulnerability scenarios (Step 5)
  - Injection vulnerability scenarios (Step 6)
  - General bola_patterns vulnerability scenarios (Step 7)
  - Gap-filling for under-represented patterns (Step 9)

Each example produces three files in the reviewing hierarchy:
  context.txt            ← detailed architecture + artifact (HAR/schema/docs)
  expected_response.md   ← analyst findings + steps to reproduce
  analysis_explanation.md ← teaching explanation

Usage:
    python scripts/generate_examples_engine.py graphql --count 500
    python scripts/generate_examples_engine.py salesforce --count 500
    python scripts/generate_examples_engine.py injection --count 1000
    python scripts/generate_examples_engine.py bola --count 1000
    python scripts/generate_examples_engine.py gap --count 2000 --coverage-file docs/coverage_statistics.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from training.reviewing_iter import next_example_folder

REPO_ROOT = Path(__file__).resolve().parents[1]
REVIEWING_ROOT = REPO_ROOT / "data" / "training" / "reviewing"
KNOWLEDGE_DIR = REPO_ROOT / "data" / "knowledge"

# ─────────────────────────────────────────────────────────────────────────────
# Industry catalogue (80+ unique industries to maximise diversity)
# ─────────────────────────────────────────────────────────────────────────────
INDUSTRIES = [
    ("Healthcare / EHR Platform", "PatientCore EHR API", "FHIR R4 + GraphQL gateway over clinical records"),
    ("Financial Services / Retail Banking", "NexaBank Open Finance API", "ISO 20022 + REST/GraphQL over account ledgers"),
    ("E-Commerce / Marketplace", "ShopGrid Marketplace API", "GraphQL storefront + microservices"),
    ("Smart City / Traffic Management", "MetroPulse Traffic Orchestration", "IoT edge + MQTT + GraphQL command plane"),
    ("Automotive / Connected Car", "AetherDrive V2X Telematics", "MQTT + gRPC + REST OTA update pipeline"),
    ("Defense Industrial Base", "Aegis Vault Secure Repository", "Zero-trust + IaC state management"),
    ("Industrial IoT / Manufacturing", "ManuControl Robotics Fleet", "OPC-UA + REST bridge + GraphQL reporting"),
    ("Government / Public Safety", "FirstResponse CAD Integration", "REST + NIEM XML + GraphQL dispatch"),
    ("HR Tech / Talent Acquisition", "JobCore Candidate Portal", "GraphQL + PostgreSQL + Salesforce CRM"),
    ("SaaS / Project Management", "TaskFlow Collaboration API", "GraphQL + event-sourcing + multi-tenant"),
    ("Social Media / Identity Graph", "Horizon Social Graph API", "GraphQL federation + Neo4j"),
    ("Insurance / Claims Processing", "ClaimsFlow Underwriting API", "SOAP + REST + GraphQL facade"),
    ("Logistics / Supply Chain", "FreightLens Tracking API", "REST + Kafka + GraphQL dashboard"),
    ("Energy / Utilities / Smart Grid", "PowerGrid Customer Billing API", "REST + GraphQL + SCADA bridge"),
    ("Telecom / 5G Core", "SpectreNet Policy Control", "PFCP + REST + GraphQL OSS/BSS"),
    ("Education / EdTech LMS", "LearnPath Assessment Platform", "REST + Prisma + GraphQL"),
    ("Real Estate / PropTech", "EstateFlow Property API", "REST + Elasticsearch + GraphQL"),
    ("Travel / GDS", "SkyPort Global Distribution", "XML-based GDS + REST + GraphQL"),
    ("Media / Content Delivery", "StreamCore VOD Platform", "CDN + REST + GraphQL content API"),
    ("Fintech / Payments Gateway", "PayBridge Transaction API", "PCI DSS + REST + Webhook callbacks"),
    ("Pharmaceutical / Clinical Trials", "TrialVault ClinicalOps API", "21 CFR Part 11 + REST + GraphQL"),
    ("Agriculture / Precision Farming", "HarvestIQ IoT Platform", "MQTT + REST + GraphQL analytics"),
    ("Retail / Loyalty Programme", "RewardCore Loyalty API", "REST + GraphQL + Points ledger"),
    ("Legal Tech / Document Management", "LexVault eDiscovery API", "REST + Elasticsearch + GraphQL"),
    ("Mining / Resource Extraction", "OreTrack Fleet Management", "REST + IoT telemetry + GraphQL"),
    ("Aerospace / MRO", "WingTech Maintenance Portal", "REST + S1000D + GraphQL"),
    ("Non-Profit / Grant Management", "GrantFlow CRM API", "REST + Salesforce + GraphQL"),
    ("Construction / BIM Platform", "BuildCore BIM Collaboration", "REST + IFC + GraphQL"),
    ("Food & Beverage / FMCG", "TraceOrigin Supply API", "REST + Blockchain + GraphQL"),
    ("Hospitality / Hotel PMS", "StayPro Property API", "REST + OTA standards + GraphQL"),
    ("Fitness / Wearables", "VitalTrack Health API", "FHIR + GraphQL + BLE bridge"),
    ("Gaming / MMO Backend", "RealmForge Game API", "WebSocket + REST + GraphQL economy"),
    ("Cybersecurity / SIEM", "ThreatLens SOC Platform", "REST + STIX/TAXII + GraphQL"),
    ("B2B SaaS / CRM", "PipelinePro Sales API", "REST + GraphQL + Salesforce integration"),
    ("Blockchain / DeFi", "ChainVault DeFi API", "REST + Web3 + GraphQL indexer"),
    ("Telemedicine / Remote Care", "TeleCare Consultation API", "FHIR + WebRTC + GraphQL"),
    ("Aviation / Flight Ops", "AeroOps Flight Management", "ACARS + REST + GraphQL"),
    ("Railway / SCADA", "RailCore Operations API", "IEC 61375 + REST + GraphQL"),
    ("Water Utilities / Smart Meters", "AquaGrid Meter Management", "DLMS/COSEM + REST + GraphQL"),
    ("Nuclear / Safety Systems", "ReactorCore Safety API", "IEC 62645 + REST + GraphQL audit"),
    ("Marine / Port Logistics", "HarborFlow Port API", "AIS + REST + GraphQL dashboard"),
    ("Waste Management / Smart Bins", "CleanRoute IoT Platform", "MQTT + REST + GraphQL routing"),
    ("Smart Home / Building Automation", "NeoBuild BAS Platform", "BACnet + REST + GraphQL"),
    ("Cloud IAM / Identity Provider", "VaultGuard IAM API", "OAuth2/OIDC + REST + GraphQL"),
    ("Data Analytics / BI Platform", "InsightGraph Analytics API", "REST + GraphQL + columnar DB"),
    ("HR / Payroll Processing", "WageFlow Payroll API", "REST + EDI + GraphQL"),
    ("Document Signing / eSign", "SignFlow eSign Platform", "REST + Webhook + GraphQL"),
    ("Tax Compliance / RegTech", "TaxGrid Compliance API", "REST + GraphQL + regulatory feeds"),
    ("Event Management / Ticketing", "VenueCore Ticketing API", "REST + GraphQL + payment"),
    ("Parking / Smart City", "ParkIQ Management API", "IoT + REST + GraphQL reservations"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability patterns from bola_patterns.md
# ─────────────────────────────────────────────────────────────────────────────
BOLA_PATTERNS = [
    ("1.1", "ID in path without ownership check", "BOLA", "GraphQL,REST,HAR"),
    ("1.2", "Related or linked resources", "BOLA", "GraphQL,REST,schema"),
    ("1.3", "Bulk or list endpoints", "BOLA", "GraphQL,REST,HAR"),
    ("1.4", "Third-party or storage APIs", "BOLA", "REST,HAR"),
    ("1.5", "Multi-tenant / cross-tenant access", "BOLA", "GraphQL,REST,Salesforce,HAR"),
    ("1.6", "Write operations without ownership check", "BOLA", "GraphQL,REST,HAR"),
    ("1.7", "Nested resources without parent authorization", "BOLA", "GraphQL,REST,HAR"),
    ("1.8", "Predictable or sequential IDs", "BOLA", "GraphQL,REST,HAR"),
    ("1.9", "Batch/bulk lookup endpoints", "BOLA", "GraphQL,REST,HAR"),
    ("1.10", "Cross-service identity propagation drift", "BOLA", "GraphQL,REST,schema"),
    ("1.11", "Cache-key authorization mismatch", "BOLA", "REST,HAR"),
    ("1.12", "Mass assignment via object fields", "BOLA", "GraphQL,REST,HAR,Salesforce"),
    ("1.13", "IoT/SCADA node and device ID manipulation", "BOLA", "REST,HAR,schema"),
    ("2.1", "Functional pivot (vertical/horizontal)", "BAC", "REST,HAR,Salesforce"),
    ("2.2", "Metadata/attribute side-channel", "BAC", "GraphQL,REST,HAR"),
    ("2.3", "State/session permeability", "BAC", "REST,HAR"),
    ("2.4", "Privilege escalation via parameter tampering", "BAC", "REST,Salesforce,HAR"),
    ("2.5", "Critical Infrastructure interface exposure", "BAC", "REST,HAR,schema"),
    ("3.1", "Client-assumed authority", "Insecure Design", "GraphQL,REST,HAR,Salesforce"),
    ("3.2", "Workflow decoupling", "Insecure Design", "REST,HAR"),
    ("3.3", "Semantic ambiguity (over-broad endpoints)", "Insecure Design", "GraphQL,REST"),
    ("3.4", "Implicit trust in callbacks", "Insecure Design", "REST,HAR"),
    ("3.5", "Unsecured multi-step critical workflows", "Insecure Design", "REST,HAR"),
    ("4.1", "Confused deputy / brokerage failures", "Integrity", "REST,HAR"),
    ("4.2", "Persistence poisoning via lifecycle actions", "Integrity", "GraphQL,REST"),
    ("4.3", "Integrity downgrade via versioning", "Integrity", "REST,HAR"),
    ("4.4", "IaC state file exposure", "Integrity", "REST,schema"),
    ("4.5", "Firmware update without signature validation", "Integrity", "REST,HAR"),
    ("5.1", "Authorization-bypass injection", "Injection", "GraphQL,REST,HAR"),
    ("5.2", "Resolver/graph traversal injection", "Injection", "GraphQL,HAR"),
    ("5.3", "SSRF via user-controlled URLs", "Injection", "REST,HAR"),
    ("5.4", "Industrial protocol injection", "Injection", "REST,HAR"),
    ("6.1", "Schema/relationship over-exposure", "Misconfiguration", "GraphQL,REST,HAR"),
    ("6.2", "Verbose error feedback", "Misconfiguration", "REST,HAR"),
    ("6.3", "Default credentials and unnecessary services", "Misconfiguration", "REST,HAR"),
    ("6.4", "Cloud storage bucket and network exposure", "Misconfiguration", "REST,HAR,schema"),
    ("6.5", "Shadow AI and ungoverned ML endpoints", "Misconfiguration", "REST,HAR"),
    ("7.1", "Operational PII/PHI leakage", "Logging Failures", "GraphQL,REST,HAR"),
    ("7.2", "Anti-forensic capabilities", "Logging Failures", "REST,HAR"),
    ("7.3", "Insufficient logging of critical actions", "Logging Failures", "REST,HAR"),
    ("7.4", "Incomplete log context", "Logging Failures", "REST,HAR"),
    ("8.1", "Race condition / concurrency gaps", "Exceptional", "REST,HAR"),
    ("8.2", "Fail-open on timeout", "Exceptional", "REST,HAR"),
    ("8.3", "Fail-open on security checks", "Exceptional", "REST,HAR"),
    ("8.4", "Resource exhaustion (DoS)", "Exceptional", "REST,HAR"),
    ("8.5", "State corruption in critical transactions", "Exceptional", "REST,HAR"),
    ("9.1", "GraphQL: single endpoint vulnerabilities", "Platform", "GraphQL,HAR"),
    ("9.2", "SOQL and Salesforce record-level access", "Platform", "Salesforce,HAR"),
    ("9.4", "SCADA and ICS", "Platform", "REST,HAR,schema"),
    ("9.5", "Smart Cities and IoT Networks", "Platform", "REST,HAR,schema"),
    ("10.1", "ID swap in own request", "Single-User", "GraphQL,REST,HAR"),
    ("10.2", "Parameter escalation (own session scope extension)", "Single-User", "GraphQL,REST,Salesforce,HAR"),
    ("10.3", "Temporary-ID hijacking", "Single-User", "REST,HAR"),
    ("10.4", "Lifecycle state bypass", "Single-User", "REST,HAR"),
    ("10.5", "Draft / non-published resource access", "Single-User", "GraphQL,REST,HAR"),
    ("10.6", "Subscription / webhook hijacking", "Single-User", "REST,HAR"),
]

INJECTION_TYPES = [
    ("SQL Injection", "SQLi", "Enterprise DBMS"),
    ("NoSQL Injection", "NoSQLi", "MongoDB / document store"),
    ("LDAP Injection", "LDAPi", "corporate directory services"),
    ("Command Injection", "CMDi", "OS-level execution"),
    ("ORM Injection", "ORMi", "Hibernate/Sequelize raw queries"),
    ("SSTI", "SSTI", "Jinja2/Nunjucks template engine"),
    ("XXE", "XXE", "XML parser"),
    ("SSRF", "SSRF", "backend HTTP fetch"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Template builders
# ─────────────────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uid(seed: str) -> str:
    return hashlib.md5(seed.encode()).hexdigest()[:8]


def _random_jwt(role: str = "user", tenant: str = "T-001") -> str:
    return f"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG".replace(
        "{uid}", _uid(role + tenant)
    ).replace("{role}", role).replace("{tenant}", tenant)


def _make_graphql_context(industry: tuple, pattern: tuple, example_idx: int) -> str:
    ind_name, sys_name, arch_desc = industry
    pat_id, pat_desc, pat_cat, _ = pattern
    uid = _uid(f"{ind_name}{pat_id}{example_idx}")

    objects = {
        "Healthcare": ("patient", "patientId", "record", "PHI record"),
        "Financial": ("account", "accountId", "transaction", "financial record"),
        "E-Commerce": ("order", "orderId", "product", "purchase record"),
        "Smart City": ("intersection", "nodeId", "command", "traffic control"),
        "HR Tech": ("candidate", "candidateId", "assessment", "candidate profile"),
        "SaaS": ("project", "projectId", "task", "project data"),
        "Social": ("post", "postId", "comment", "user content"),
        "Insurance": ("claim", "claimId", "document", "claim record"),
        "Logistics": ("shipment", "shipmentId", "waypoint", "logistics data"),
        "Energy": ("meter", "meterId", "reading", "billing data"),
        "Gaming": ("character", "characterId", "inventory", "game asset"),
    }
    # pick object type based on industry keyword
    obj_type, obj_id, child_type, obj_label = next(
        (v for k, v in objects.items() if k.lower() in ind_name.lower()),
        ("resource", "resourceId", "item", "data record"),
    )

    tenant_a = f"tenant-{uid[:4]}"
    tenant_b = f"tenant-{uid[4:8]}"
    obj_id_own = f"{obj_type[0].upper()}-{1000 + example_idx}"
    obj_id_victim = f"{obj_type[0].upper()}-{2000 + example_idx}"

    # Build detailed GraphQL schema
    schema_snippet = f"""
type {obj_type.capitalize()} {{
  {obj_id}: ID!
  tenantId: ID!
  ownerId: ID!
  status: String!
  data: {obj_type.capitalize()}Data
  {child_type}s: [{child_type.capitalize()}!]
}}

type {obj_type.capitalize()}Data {{
  title: String
  sensitiveField: String      # PII / business-sensitive
  internalNotes: String       # Internal-only field
  auditLog: [AuditEntry!]
}}

type Query {{
  get{obj_type.capitalize()}(id: ID!): {obj_type.capitalize()}
  list{obj_type.capitalize()}s(tenantId: ID, status: String): [{obj_type.capitalize()}!]
  get{obj_type.capitalize()}WithChildren(id: ID!): {obj_type.capitalize()}
}}

type Mutation {{
  update{obj_type.capitalize()}(id: ID!, input: {obj_type.capitalize()}Input!): {obj_type.capitalize()}
  delete{obj_type.capitalize()}(id: ID!): Boolean
  bulk{obj_type.capitalize()}Lookup(ids: [ID!]!): [{obj_type.capitalize()}!]
}}
"""

    vulnerable_op = random.choice([
        f"get{obj_type.capitalize()}(id: \"{obj_id_victim}\") {{ {obj_id} tenantId ownerId data {{ sensitiveField internalNotes }} }}",
        f"update{obj_type.capitalize()}(id: \"{obj_id_victim}\", input: {{status: \"approved\", ownerId: \"attacker-{uid}\"}}) {{ {obj_id} status }}",
        f"bulk{obj_type.capitalize()}Lookup(ids: [\"{obj_id_victim}\", \"{obj_id_own}\", \"{obj_type[0].upper()}-{3000 + example_idx}\"]) {{ {obj_id} tenantId data {{ sensitiveField }} }}",
        f"list{obj_type.capitalize()}s(tenantId: \"{tenant_b}\") {{ {obj_id} ownerId data {{ sensitiveField }} }}",
    ])

    har_entry = f"""{{
  "log": {{
    "version": "1.2",
    "creator": {{"name": "SecurityProxy", "version": "1.0"}},
    "entries": [
      {{
        "startedDateTime": "{_ts()}",
        "time": {random.randint(45, 280)},
        "request": {{
          "method": "POST",
          "url": "https://api.{sys_name.lower().replace(' ', '-')[:20]}.example.com/graphql",
          "httpVersion": "HTTP/2.0",
          "headers": [
            {{"name": ":authority", "value": "api.{sys_name.lower().replace(' ', '-')[:20]}.example.com"}},
            {{"name": "authorization", "value": "Bearer {_random_jwt('user', tenant_a)}"}},
            {{"name": "content-type", "value": "application/json"}},
            {{"name": "x-tenant-id", "value": "{tenant_a}"}}
          ],
          "queryString": [],
          "postData": {{
            "mimeType": "application/json",
            "text": "{{\\\"query\\\": \\\"query VulnerableOp {{ {vulnerable_op} }}\\\"}}"
          }},
          "bodySize": {random.randint(80, 200)}
        }},
        "response": {{
          "status": 200,
          "statusText": "OK",
          "headers": [
            {{"name": "content-type", "value": "application/json"}},
            {{"name": "x-request-id", "value": "req-{uid}"}}
          ],
          "content": {{
            "size": {random.randint(200, 600)},
            "mimeType": "application/json",
            "text": "{{\\\"data\\\": {{\\\"get{obj_type.capitalize()}\\\": {{\\\"tenantId\\\": \\\"{tenant_b}\\\", \\\"ownerId\\\": \\\"other-user-{uid}\\\", \\\"data\\\": {{\\\"sensitiveField\\\": \\\"CONFIDENTIAL-{uid}\\\", \\\"internalNotes\\\": \\\"Internal data exposed\\\"}}}}}}}}"}}"
          }},
          "bodySize": {random.randint(200, 600)},
          "redirectURL": "",
          "headersSize": 120
        }},
        "timings": {{"send": 2, "wait": {random.randint(40, 270)}, "receive": 5}},
        "cache": {{}}
      }}
    ]
  }}
}}"""

    return f"""# ENGINEERING ARCHITECTURE SPECIFICATION
**System Name:** {sys_name}
**Document Version:** {random.randint(1,5)}.{random.randint(0,9)}.{random.randint(0,9)} (FINAL)
**Classification:** SENSITIVE
**Domain:** {ind_name}
**Architecture:** {arch_desc}
**Training Example ID:** GQL-{example_idx:04d}

## 1.0 Executive Summary
{sys_name} is a {ind_name.lower()} platform that exposes a GraphQL API to authorised consumers.
The platform manages {obj_label}s partitioned by tenant (`tenantId`). The architecture uses
JWT-based OAuth2 authentication, and the JWT carries both the `sub` (user ID) and `tenantId` claims.
Authorization is expected to be enforced per-resolver on the GraphQL server.

## 2.0 Architecture Overview
- **API Layer:** GraphQL single endpoint (`POST /graphql`) served via Apollo Server
- **Auth:** OAuth2 JWT issued by internal IdP; claims include `sub`, `role`, `tenantId`
- **Database:** PostgreSQL with row-level security policies; each table has a `tenant_id` column
- **Caching:** Redis cache keyed by `{obj_id}` (NOTE: no user dimension in cache key)

## 3.0 GraphQL Schema
```graphql
{schema_snippet}
```

## 4.0 Known Architectural Notes
- **RISK-GQL-{example_idx:03d}:** The `get{obj_type.capitalize()}` resolver fetches by `{obj_id}` only.
  The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`.
  Tracked internally as a known gap pending remediation.
- The `bulk{obj_type.capitalize()}Lookup` mutation accepts an arbitrary array of IDs without
  per-ID ownership filtering.

## 5.0 Vulnerability Context
**Pattern:** {pat_id} — {pat_desc} ({pat_cat})

The `{obj_id}` field is used as the object identifier across all resolvers.
{_vulnerability_note(pat_id, obj_type, obj_id, tenant_a, tenant_b)}

## 6.0 HAR Capture (Network Trace)
The following HTTP Archive (HAR) capture was recorded during a penetration test.
The attacker's token belongs to `{tenant_a}` but the requested object belongs to `{tenant_b}`.

```json
{har_entry}
```

## 7.0 API Contract (Partial)
```
POST /graphql
Authorization: Bearer <JWT>
Content-Type: application/json

Body: {{ "query": "..." }}

Authenticated user's tenantId is extracted from JWT.
Resolver MUST cross-check tenantId against fetched object's tenantId.
```
"""


def _vulnerability_note(pat_id: str, obj_type: str, obj_id: str, tenant_a: str, tenant_b: str) -> str:
    notes = {
        "1.1": f"The `get{obj_type.capitalize()}` resolver accepts `{obj_id}` from the query without verifying ownership. An attacker with a valid `{tenant_a}` token can substitute any `{obj_id}` value to retrieve objects belonging to `{tenant_b}`.",
        "1.5": f"The API accepts `tenantId` as a filter argument. The resolver trusts the client-supplied `tenantId` instead of extracting it from the JWT. Token from `{tenant_a}` passes `tenantId: \"{tenant_b}\"` to access cross-tenant data.",
        "1.9": f"The `bulk{obj_type.capitalize()}Lookup` mutation accepts a list of IDs without per-ID ownership checks. A single request can enumerate objects across all tenants.",
        "5.2": f"The GraphQL resolver chain follows nested relationships without re-validating authorization at each level. An attacker can traverse from an authorized {obj_type} to related child objects across tenant boundaries.",
        "6.1": f"GraphQL introspection is enabled in production. The schema exposes internal type names, field descriptions, and sensitive relationship paths that aid exploitation.",
        "1.3": f"The `list{obj_type.capitalize()}s` resolver returns all objects when the `tenantId` filter is omitted or when it is supplied from the client without JWT-level validation.",
        "1.6": f"The `update{obj_type.capitalize()}` mutation accepts an arbitrary `{obj_id}` in the path without verifying the requester owns that object. A write-level BOLA allows state corruption across tenants.",
        "1.12": f"The mutation `update{obj_type.capitalize()}` accepts `ownerId` and `tenantId` as writable fields in the input, allowing mass assignment of ownership attributes.",
        "3.1": f"The client supplies price, role, or status fields that the resolver applies without server-side re-validation of the authenticated user's permissions.",
        "9.1": f"The GraphQL single-endpoint pattern means all operations (including sensitive mutations) are accessible at one URL. Per-operation authorization is missing for write operations.",
        "10.1": f"A single authenticated user substitutes their own valid `{obj_id}` with a victim's `{obj_id}`. With one token, data belonging to another user is accessible.",
        "2.2": f"The GraphQL schema exposes `list{obj_type.capitalize()}s` with partial data even for unauthorised objects, leaking the existence and metadata of records the user should not know about.",
    }
    return notes.get(pat_id, f"The resolver handling `{obj_id}` does not enforce ownership or tenancy boundaries, enabling Pattern {pat_id} exploitation.")


def _make_graphql_expected_response(industry: tuple, pattern: tuple, example_idx: int) -> str:
    ind_name, sys_name, _ = industry
    pat_id, pat_desc, pat_cat, _ = pattern
    uid = _uid(f"{ind_name}{pat_id}{example_idx}")

    obj_map = {k.lower(): v for k, v in {
        "Healthcare": "patient", "Financial": "account", "E-Commerce": "order",
        "HR Tech": "candidate", "SaaS": "project", "Social": "post",
        "Insurance": "claim", "Logistics": "shipment", "Energy": "meter",
    }.items()}
    obj_type = next((v for k, v in obj_map.items() if k in ind_name.lower()), "resource")
    obj_id_field = f"{obj_type}Id"
    victim_id = f"{obj_type[0].upper()}-{2000 + example_idx}"
    attacker_tenant = f"tenant-{uid[:4]}"
    victim_tenant = f"tenant-{uid[4:8]}"

    return f"""# Expected Response

## System
- Domain: {ind_name}
- System: {sys_name}
- Example ID: GQL-{example_idx:04d}

## Priority Findings

### Finding 1: GraphQL BOLA — {pat_desc} (Pattern {pat_id})
**Severity:** Critical
**Category:** {pat_cat}

**Summary:**
The GraphQL API at `POST /graphql` contains a Pattern {pat_id} ({pat_desc}) vulnerability.
An authenticated user belonging to `{attacker_tenant}` can access or manipulate objects owned by
`{victim_tenant}` by supplying a cross-tenant `{obj_id_field}` in the GraphQL query/mutation.

**Evidence from HAR:**
- Request JWT claim `tenantId`: `{attacker_tenant}`
- Response body `tenantId`: `{victim_tenant}` — **mismatch confirms cross-tenant data access**
- Response HTTP status: `200 OK` — no authorization error raised by the resolver
- Response includes `sensitiveField` and `internalNotes` belonging to `{victim_tenant}`

**Root Cause:**
The resolver fetches the {obj_type} by `{obj_id_field}` directly from the database without joining
against the authenticated user's `tenantId`. The JWT is validated (signature check passes) but the
`tenantId` claim is never used as a WHERE clause predicate.

## Steps to Reproduce

### Step 1 — Establish attacker baseline
```bash
curl -s -X POST https://api.{sys_name.lower().replace(' ', '-')[:20]}.example.com/graphql \\
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_{attacker_tenant.upper()}>" \\
  -H "Content-Type: application/json" \\
  -d '{{"query": "query {{ get{obj_type.capitalize()}(id: \\"{obj_type[0].upper()}-{1000 + example_idx}\\") {{ {obj_id_field} tenantId ownerId data {{ sensitiveField }} }} }}"}}' 
```
**Expected baseline:** Returns `tenantId: "{attacker_tenant}"` — this is the attacker's own object.

### Step 2 — Cross-tenant ID substitution
```bash
curl -s -X POST https://api.{sys_name.lower().replace(' ', '-')[:20]}.example.com/graphql \\
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_{attacker_tenant.upper()}>" \\
  -H "Content-Type: application/json" \\
  -d '{{"query": "query {{ get{obj_type.capitalize()}(id: \\"{victim_id}\\") {{ {obj_id_field} tenantId ownerId data {{ sensitiveField internalNotes }} }} }}"}}' 
```
**Vulnerable outcome:** Returns `tenantId: "{victim_tenant}"` and full `sensitiveField` — **BOLA confirmed**.
**Secure outcome:** HTTP 403/404 or an empty data response with an authorization error.

### Step 3 — Bulk enumeration (if Pattern 1.9 also present)
```bash
curl -s -X POST https://api.{sys_name.lower().replace(' ', '-')[:20]}.example.com/graphql \\
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_{attacker_tenant.upper()}>" \\
  -H "Content-Type: application/json" \\
  -d '{{"query": "mutation {{ bulk{obj_type.capitalize()}Lookup(ids: [\\"{victim_id}\\", \\"{obj_type[0].upper()}-{3000+example_idx}\\", \\"{obj_type[0].upper()}-{4000+example_idx}\\"]) {{ {obj_id_field} tenantId data {{ sensitiveField }} }} }}"}}'
```
**Vulnerable outcome:** Returns objects from multiple tenants in a single response.

### Step 4 — Introspection probe (if Pattern 6.1 also present)
```bash
curl -s -X POST https://api.{sys_name.lower().replace(' ', '-')[:20]}.example.com/graphql \\
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_{attacker_tenant.upper()}>" \\
  -H "Content-Type: application/json" \\
  -d '{{"query": "{{ __schema {{ types {{ name fields {{ name type {{ name }} }} }} }} }}"}}' 
```
**Vulnerable outcome:** Full schema returned — confirms field names and relationships for deeper exploitation.

## Secure Outcome Verification
For **Step 2**, the secure implementation MUST return:
```json
{{ "errors": [{{ "message": "Forbidden", "extensions": {{ "code": "FORBIDDEN" }} }}], "data": {{ "get{obj_type.capitalize()}": null }} }}
```

## Remediation
1. **Resolver-level tenant check:** In every resolver that fetches an object by ID, add a WHERE clause: `WHERE {obj_id_field} = $id AND tenant_id = $jwtTenantId`.
2. **Disable GraphQL introspection in production:** Set `introspection: false` in Apollo Server production config.
3. **Per-ID ownership filter for bulk operations:** In `bulk{obj_type.capitalize()}Lookup`, filter results post-fetch to only return objects matching the JWT's `tenantId`.
4. **Automated regression tests:** Add a test that authenticates as Tenant A and attempts to read Tenant B objects — assert HTTP 403 or null data.
"""


def _make_graphql_explanation(industry: tuple, pattern: tuple, example_idx: int) -> str:
    ind_name, sys_name, _ = industry
    pat_id, pat_desc, pat_cat, _ = pattern
    return f"""# Analysis Explanation

This example (GQL-{example_idx:04d}) was generated independently for the **{sys_name}** system ({ind_name}).

## Generation Method
1. Selected industry: **{ind_name}**
2. Designed realistic GraphQL architecture with schema, JWT auth, and multi-tenant data model.
3. Embedded **Pattern {pat_id} ({pat_desc})** from bola_patterns.md into the resolver logic.
4. Generated HAR capture showing the cross-tenant request with mismatched tenantId evidence.
5. Wrote expected response grounded exclusively in the context.txt of this example.

## Why GraphQL?
GraphQL's single-endpoint model means all authorization must be enforced inside individual resolvers.
A missing WHERE clause in one resolver exposes the entire object graph.

## Consistency Guard
- Context refreshed for this example; no data from other examples was retained.
- All object IDs, tenant IDs, and field names are consistent within this folder only.

## Pattern Coverage
- Primary: Pattern {pat_id} — {pat_desc} ({pat_cat})
"""


# ─────────────────────────────────────────────────────────────────────────────
# Salesforce Aura builders
# ─────────────────────────────────────────────────────────────────────────────

AURA_ACTIONS = [
    ("c.AccountController.getAccounts", "Account", "accountId"),
    ("c.CaseController.getCaseDetails", "Case", "caseId"),
    ("c.ContactController.updateContact", "Contact", "contactId"),
    ("c.LeadController.getLeadData", "Lead", "leadId"),
    ("c.OpportunityController.getOpportunity", "Opportunity", "opportunityId"),
    ("c.CustomObjectController.getRecord", "CustomRecord", "recordId"),
    ("c.ContractController.approveContract", "Contract", "contractId"),
    ("c.QuoteController.getQuoteDetails", "Quote", "quoteId"),
    ("c.TaskController.getTask", "Task", "taskId"),
    ("c.EventController.updateEvent", "Event", "eventId"),
]

def _make_salesforce_context(industry: tuple, pattern: tuple, example_idx: int) -> str:
    ind_name, sys_name, arch_desc = industry
    pat_id, pat_desc, pat_cat, _ = pattern
    uid = _uid(f"SF{ind_name}{pat_id}{example_idx}")

    action_name, sf_obj, id_field = random.choice(AURA_ACTIONS)
    record_id_own   = f"001{uid[:12].upper()}"
    record_id_victim = f"001{uid[4:16].upper()}"
    user_id_attacker = f"005{uid[:12].upper()}"
    session_id = f"00D{uid[:15].upper()}!AR{uid}"

    har_payload = f"""{{
  "actions": [
    {{
      "id": "1;a",
      "descriptor": "{action_name}",
      "callingDescriptor": "UNKNOWN",
      "params": {{
        "{id_field}": "{record_id_victim}",
        "fields": ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]
      }}
    }}
  ]
}}"""

    har_response = f"""{{
  "actions": [
    {{
      "id": "1;a",
      "state": "SUCCESS",
      "returnValue": {{
        "records": [
          {{
            "Id": "{record_id_victim}",
            "Name": "Victim {sf_obj} Record",
            "OwnerId": "005VICTIM{uid[8:].upper()[:12]}",
            "InternalNotes__c": "CONFIDENTIAL: internal review notes",
            "SensitiveData__c": "SSN: 000-{random.randint(10,99)}-{random.randint(1000,9999)}"
          }}
        ]
      }},
      "error": []
    }}
  ]
}}"""

    return f"""# ENGINEERING ARCHITECTURE SPECIFICATION
**System Name:** {sys_name} (Salesforce-Integrated)
**Document Version:** {random.randint(1,4)}.{random.randint(0,9)}.0 (FINAL)
**Classification:** SENSITIVE
**Domain:** {ind_name}
**Platform:** Salesforce Lightning / Aura Framework
**Training Example ID:** SF-{example_idx:04d}

## 1.0 Executive Summary
{sys_name} is a {ind_name.lower()} platform built on Salesforce Lightning Experience.
The front-end uses Aura Components that communicate with Apex Controllers via the Salesforce
Aura Framework's `c.ControllerName.methodName` call pattern. Authorization is expected to be
enforced through Salesforce sharing rules (OWD, Role Hierarchy, Sharing Rules) AND explicitly
in Apex controller code using `WITH SECURITY_ENFORCED` or manual ownership checks.

## 2.0 Architecture Overview
- **Front-End:** Salesforce Lightning Aura Components (LWC migrated to Aura)
- **Middle Layer:** Apex Controllers called via Aura Action Framework
- **Data Layer:** Salesforce Objects with standard and custom fields
- **Auth:** Salesforce Session ID (Bearer token), OWD = Private on {sf_obj} object

## 3.0 Salesforce Object Schema
```sql
-- {sf_obj} Object (Standard + Custom Fields)
{sf_obj} (
  Id           VARCHAR(18) PRIMARY KEY,   -- Salesforce record ID
  Name         VARCHAR(255),
  OwnerId      VARCHAR(18),               -- Links to User object
  AccountId    VARCHAR(18),               -- Parent account
  SensitiveData__c VARCHAR(500),          -- Custom field: sensitive PII/business data
  InternalNotes__c  TEXT,                 -- Custom field: internal review notes
  IsDeleted    BOOLEAN DEFAULT FALSE
)
```

## 4.0 Apex Controller (Vulnerable Implementation)
```apex
public class {sf_obj}Controller {{
    @AuraEnabled
    public static List<{sf_obj}> get{sf_obj}Details(String {id_field}, List<String> fields) {{
        // VULNERABILITY: runs 'without sharing' — bypasses OWD=Private sharing rules
        // VULNERABILITY: no ownership check on {id_field} parameter
        return [{sf_obj}]Database.query(
            'SELECT Id, Name, OwnerId, SensitiveData__c, InternalNotes__c ' +
            'FROM {sf_obj} ' +
            'WHERE Id = :' + {id_field}
            // Missing: AND OwnerId = UserInfo.getUserId()
            // Missing: WITH SECURITY_ENFORCED
        );
    }}
}}
```

## 5.0 Vulnerability Context
**Pattern:** {pat_id} — {pat_desc} ({pat_cat})

The Apex controller `{action_name}` accepts a `{id_field}` parameter from the client-side
Aura component. The controller runs `without sharing` and does not validate that the
authenticated user owns or has been granted access to the requested record.

An attacker with a valid Salesforce session can substitute any `{id_field}` value in the
Aura framework request payload to access records owned by other users.

## 6.0 HAR Capture (Aura Framework Request)
```json
{{
  "log": {{
    "version": "1.2",
    "entries": [
      {{
        "startedDateTime": "{_ts()}",
        "time": {random.randint(80, 350)},
        "request": {{
          "method": "POST",
          "url": "https://{uid[:8]}.lightning.force.com/aura",
          "httpVersion": "HTTP/1.1",
          "headers": [
            {{"name": "Authorization", "value": "Bearer {session_id[:40]}..."}},
            {{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}},
            {{"name": "X-SFDC-Session", "value": "{session_id[:30]}..."}}
          ],
          "postData": {{
            "mimeType": "application/x-www-form-urlencoded",
            "params": [
              {{"name": "message", "value": "{har_payload.replace(chr(10), ' ')}"}},
              {{"name": "aura.token", "value": "undefined"}}
            ]
          }},
          "bodySize": {random.randint(200, 600)}
        }},
        "response": {{
          "status": 200,
          "statusText": "OK",
          "content": {{
            "mimeType": "application/json",
            "text": "{har_response.replace(chr(10), ' ').replace(chr(34), chr(92)+chr(34))}"
          }},
          "bodySize": {random.randint(300, 800)}
        }}
      }}
    ]
  }}
}}
```

## 7.0 Sharing Rule Configuration
```
{sf_obj} OWD: Private
Sharing Rules: Users can access records they own or have been explicitly shared with them.
Apex Controller Declaration: "public class {sf_obj}Controller" (WITHOUT "with sharing")
```

## 8.0 Known Risks
- **RISK-SF-{example_idx:03d}:** Controller declared without `with sharing`. Sharing rules not enforced.
- **RISK-SF-{example_idx+1:03d}:** No ownership check in SOQL WHERE clause.
- Client-supplied `{id_field}` is directly interpolated into SOQL without validation.
"""


def _make_salesforce_expected_response(industry: tuple, pattern: tuple, example_idx: int) -> str:
    ind_name, sys_name, _ = industry
    pat_id, pat_desc, pat_cat, _ = pattern
    uid = _uid(f"SF{ind_name}{pat_id}{example_idx}")
    action_name, sf_obj, id_field = random.choice(AURA_ACTIONS)
    record_id_victim = f"001{uid[4:16].upper()}"
    session_id = f"00D{uid[:15].upper()}!AR{uid}"

    return f"""# Expected Response

## System
- Domain: {ind_name}
- System: {sys_name} (Salesforce-Integrated)
- Example ID: SF-{example_idx:04d}

## Priority Findings

### Finding 1: Salesforce Aura BOLA — {pat_desc} (Pattern {pat_id})
**Severity:** Critical
**Category:** {pat_cat}
**OWASP API:** API1:2023 Broken Object Level Authorization

**Summary:**
The Salesforce Aura controller action `{action_name}` is vulnerable to Pattern {pat_id}.
The Apex controller is declared `without sharing` and performs no ownership validation.
An authenticated user can substitute any `{id_field}` value in the Aura framework
`POST /aura` request payload to read records owned by other users.

**Evidence from HAR:**
- Aura action: `{action_name}`
- Requested `{id_field}`: `{record_id_victim}` (belongs to a different user)
- Response state: `SUCCESS` — no authorization error
- Response body includes `SensitiveData__c` and `InternalNotes__c` belonging to another user
- The session user's `OwnerId` does not match the returned record's `OwnerId`

**Root Cause:**
1. Apex class declared `without sharing` — Salesforce OWD/sharing rules are bypassed
2. SOQL query filters only by `{id_field}` — no `AND OwnerId = UserInfo.getUserId()` predicate
3. `{id_field}` sourced directly from Aura params without server-side validation

## Steps to Reproduce

### Step 1 — Capture a baseline Aura request to your own record
Intercept a legitimate Aura request using Burp Suite or browser DevTools.
Identify the `{action_name}` action in the `message` POST body.
Record your own `{id_field}` value (e.g., `001YOURRECORDID000000`).

### Step 2 — Enumerate or guess victim record IDs
Salesforce record IDs follow a predictable 18-character pattern with a 3-char prefix.
Use the list endpoint or sequential enumeration to discover victim `{id_field}` values.

### Step 3 — Substitute victim ID in Aura request
```
POST https://<ORG_ID>.lightning.force.com/aura HTTP/1.1
Authorization: Bearer <YOUR_SESSION_TOKEN>
Content-Type: application/x-www-form-urlencoded

message={{"actions":[{{"id":"1;a","descriptor":"{action_name}","callingDescriptor":"UNKNOWN",
"params":{{"{id_field}":"{record_id_victim}","fields":["Id","Name","OwnerId","SensitiveData__c","InternalNotes__c"]}}}}]}}
&aura.token=undefined
```

### Step 4 — Verify BOLA
**Vulnerable outcome:** Response `state: "SUCCESS"` with victim record data including
`SensitiveData__c` and `InternalNotes__c`. The `OwnerId` in the response will differ
from your authenticated user ID.

**Secure outcome:** Response `state: "ERROR"` with an authorization message, or empty `records` array.

## Remediation
1. **Add `with sharing` to Apex class declaration:**
   ```apex
   public with sharing class {sf_obj}Controller {{ ... }}
   ```
2. **Add ownership filter to SOQL:**
   ```apex
   WHERE Id = :{id_field} AND OwnerId = :UserInfo.getUserId()
   ```
3. **Use `WITH SECURITY_ENFORCED` in all SOQL queries.**
4. **Validate `{id_field}` against the user's accessible record IDs before querying.**
5. **Automated test:** Write a Salesforce Apex test that authenticates as User A and requests User B's record ID — assert INSUFFICIENT_ACCESS or empty result.
"""


def _make_salesforce_explanation(industry: tuple, pattern: tuple, example_idx: int) -> str:
    ind_name, sys_name, _ = industry
    pat_id, pat_desc, pat_cat, _ = pattern
    _, sf_obj, id_field = random.choice(AURA_ACTIONS)
    return f"""# Analysis Explanation

This example (SF-{example_idx:04d}) was generated independently for **{sys_name}** ({ind_name}).

## Generation Method
1. Selected industry: **{ind_name}**
2. Designed Salesforce Lightning Aura architecture with Apex controller.
3. Embedded **Pattern {pat_id} ({pat_desc})** via `without sharing` and missing WHERE predicate.
4. Generated HAR capture of the Aura framework `POST /aura` request with injected victim ID.
5. Wrote expected response grounded exclusively in this example's context.txt.

## Why Salesforce Aura?
Aura framework requests are serialized `POST /aura` messages with a `message` field containing
JSON-encoded actions. The `{id_field}` inside the `params` object is fully attacker-controlled.
Without server-side ownership validation in the Apex controller, any record ID can be queried.

## Consistency Guard
- No context from other examples was used.
- All record IDs and session tokens are unique to this folder.

## Pattern Coverage
- Primary: Pattern {pat_id} — {pat_desc} ({pat_cat})
"""


# ─────────────────────────────────────────────────────────────────────────────
# Injection builders (Step 6)
# ─────────────────────────────────────────────────────────────────────────────

def _make_injection_context(industry: tuple, inj: tuple, pattern: tuple, example_idx: int) -> str:
    ind_name, sys_name, arch_desc = industry
    inj_name, inj_short, inj_ctx = inj
    pat_id, pat_desc, pat_cat, _ = pattern
    uid = _uid(f"INJ{ind_name}{inj_short}{example_idx}")

    param_name = random.choice(["search", "filter", "username", "id", "name", "query", "category", "tag"])
    table = random.choice(["users", "orders", "products", "records", "accounts", "claims", "patients"])
    endpoint = f"/api/v{random.randint(1,3)}/{table}"

    payload_map = {
        "SQLi":  f"' OR 1=1 --",
        "NoSQLi": f'{{ "$gt": "" }}',
        "LDAPi": f"admin)(&(password=*))",
        "CMDi":  f"; cat /etc/passwd",
        "ORMi":  f"1; DROP TABLE {table}--",
        "SSTI":  f"{{{{7*7}}}}",
        "XXE":   f"<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
        "SSRF":  f"http://169.254.169.254/latest/meta-data/",
    }
    payload = payload_map.get(inj_short, f"' OR '1'='1")
    encoded_payload = payload.replace('"', '\\"').replace("'", "\\'")

    vuln_code = "const query = `SELECT * FROM " + table + " WHERE " + param_name + " = '${req.query." + param_name + "}'`;"
    return f"""# ENGINEERING ARCHITECTURE SPECIFICATION
**System Name:** {sys_name}
**Document Version:** {random.randint(1,4)}.{random.randint(0,9)}.0 (FINAL)
**Classification:** SENSITIVE
**Domain:** {ind_name}
**Vulnerability Type:** {inj_name}
**Training Example ID:** INJ-{example_idx:04d}

## 1.0 Executive Summary
{sys_name} is a {ind_name.lower()} platform with a REST API backed by {inj_ctx}.
The platform exposes search and filter endpoints that accept user-supplied parameters.
Input sanitization is inconsistent across the codebase due to a mix of raw query
construction and ORM usage.

## 2.0 Architecture
- **API Layer:** Node.js / Express or Java Spring Boot REST API
- **Database:** {inj_ctx} — primary data store
- **Auth:** JWT Bearer tokens
- **Known Debt:** Older endpoint `{endpoint}` uses string concatenation for queries

## 3.0 Vulnerable Endpoint
```
GET {endpoint}?{param_name}=<user_input>
Authorization: Bearer <JWT>
```

**Vulnerable Code Snippet:**
```javascript
// Node.js — raw query construction (VULNERABLE)
{vuln_code}
db.execute(query, (err, results) => {{ ... }});
```

## 4.0 Injection Payload
The following input exploits the lack of parameterization:
```
{param_name}={encoded_payload}
```

## 5.0 HAR Capture
```json
{{
  "log": {{
    "version": "1.2",
    "entries": [
      {{
        "startedDateTime": "{_ts()}",
        "time": {random.randint(30, 250)},
        "request": {{
          "method": "GET",
          "url": "https://api.{sys_name.lower().replace(' ', '-')[:15]}.example.com{endpoint}?{param_name}={payload.replace(' ', '%20').replace("'", '%27')}",
          "httpVersion": "HTTP/1.1",
          "headers": [
            {{"name": "Authorization", "value": "Bearer {_random_jwt()}"}},
            {{"name": "Accept", "value": "application/json"}}
          ],
          "queryString": [
            {{"name": "{param_name}", "value": "{payload}"}}
          ],
          "bodySize": 0
        }},
        "response": {{
          "status": 200,
          "statusText": "OK",
          "content": {{
            "mimeType": "application/json",
            "text": "{{\\"data\\": [{{\\"id\\": 1, \\"username\\": \\"admin\\", \\"password_hash\\": \\"$2b$12$secret\\", \\"role\\": \\"ADMIN\\"}}, {{\\"id\\": 2, \\"username\\": \\"user2\\", \\"password_hash\\": \\"$2b$12$abc\\"}}]}}"
          }},
          "bodySize": {random.randint(200, 500)}
        }}
      }}
    ]
  }}
}}
```

## 6.0 Misconfiguration Context
- Over-privileged DB account: application connects as `db_owner` instead of a restricted role
- Verbose error messages enabled in staging (and leaked to production accidentally)
- No WAF or input validation middleware on legacy endpoints

## 7.0 Known Risk
- **RISK-INJ-{example_idx:03d}:** Endpoint `{endpoint}` uses raw string concatenation.
  Parameterized queries are used in newer endpoints but this one was missed in the migration.
"""


def _make_injection_expected_response(industry: tuple, inj: tuple, example_idx: int) -> str:
    ind_name, sys_name, _ = industry
    inj_name, inj_short, inj_ctx = inj
    uid = _uid(f"INJ{ind_name}{inj_short}{example_idx}")
    param_name = "search"
    table = "users"
    endpoint = f"/api/v1/{table}"

    payloads = {
        "SQLi": "' OR 1=1 --",
        "NoSQLi": '{ "$gt": "" }',
        "LDAPi": "admin)(&(password=*))",
        "CMDi": "; cat /etc/passwd",
        "ORMi": "1; DROP TABLE users--",
        "SSTI": "{{7*7}}",
        "XXE": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
        "SSRF": "http://169.254.169.254/latest/meta-data/",
    }
    payload = payloads.get(inj_short, "' OR '1'='1")

    return f"""# Expected Response

## System
- Domain: {ind_name}
- System: {sys_name}
- Example ID: INJ-{example_idx:04d}
- Vulnerability: {inj_name}

## Priority Findings

### Finding 1: {inj_name} on `{endpoint}`
**Severity:** Critical
**Category:** Injection (from data/knowledge/injections)

**Summary:**
The `{endpoint}` endpoint accepts a `{param_name}` query parameter that is directly
interpolated into a raw database query without sanitization. This enables {inj_name} ({inj_short}),
allowing an attacker to bypass authentication, extract all records, or execute arbitrary operations.

**Evidence from HAR:**
- Endpoint: `GET {endpoint}?{param_name}={payload}`
- Response: HTTP 200 with **all records returned** including password hashes and admin accounts
- The query constructed: `SELECT * FROM {table} WHERE {param_name} = '{payload}'`
  evaluates to true for all rows when the payload is `{payload}`

**Root Cause:**
- Raw string concatenation used to build database query
- No parameterized query / prepared statement
- Application DB account has excessive privileges (`db_owner`)

## Steps to Reproduce

### Step 1 — Normal request (baseline)
```bash
curl -s "https://api.{sys_name.lower().replace(' ', '-')[:15]}.example.com{endpoint}?{param_name}=normalvalue" \\
  -H "Authorization: Bearer <VALID_TOKEN>"
```
Expected: Returns matching records only.

### Step 2 — Inject {inj_short} payload
```bash
curl -s "https://api.{sys_name.lower().replace(' ', '-')[:15]}.example.com{endpoint}?{param_name}={payload.replace(' ', '%20')}" \\
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Vulnerable outcome:** All rows returned, including admin password hashes.
**Secure outcome:** 400 Bad Request / 0 results / sanitized error message.

### Step 3 — Privilege escalation (if DB over-privileged)
```bash
# SQLi variant: attempt to read OS-level files (if DB runs as LocalSystem)
curl -s "https://api.example.com{endpoint}?{param_name}=' UNION SELECT null,null,load_file('/etc/passwd')--" \\
  -H "Authorization: Bearer <VALID_TOKEN>"
```

### Step 4 — Verbose error confirmation
```bash
curl -s "https://api.example.com{endpoint}?{param_name}='" \\
  -H "Authorization: Bearer <VALID_TOKEN>"
```
**Expected verbose error (if misconfigured):** SQL syntax error message leaking table name, column names, or DB version.

## Secure Outcome
```json
{{ "error": "Invalid input", "code": 400 }}
```

## Remediation
1. **Use parameterized queries / prepared statements everywhere:** Replace string concatenation with `?` or named parameters.
2. **Restrict DB account privileges:** Application account should only have SELECT/INSERT/UPDATE/DELETE on required tables.
3. **Disable verbose error messages in production:** Return generic 500/400 errors without DB details.
4. **Deploy input validation middleware:** Reject inputs containing SQL metacharacters (`'`, `"`, `;`, `--`, `/*`).
5. **ORM audit:** Review all `raw()` or native query calls in ORM usage; apply parameterization.
"""


def _make_injection_explanation(industry: tuple, inj: tuple, example_idx: int) -> str:
    ind_name, sys_name, _ = industry
    inj_name, inj_short, _ = inj
    return f"""# Analysis Explanation

This example (INJ-{example_idx:04d}) was generated independently for **{sys_name}** ({ind_name}).

## Generation Method
1. Selected industry: **{ind_name}**
2. Designed architecture with {inj_name}-susceptible component ({inj_short}).
3. Constructed realistic vulnerable code snippet showing raw query concatenation.
4. Generated HAR capture of the injection payload and full data dump response.
5. Wrote expected response grounded in this example's context.txt only.

## Injection Type
**{inj_name} ({inj_short})** — from data/knowledge/injections knowledge file.

## Consistency Guard
- Example context cleared before this generation.
- All endpoints, table names, and payloads are self-consistent within this folder.
"""


# ─────────────────────────────────────────────────────────────────────────────
# General BOLA patterns builders (Step 7)
# ─────────────────────────────────────────────────────────────────────────────

def _make_bola_context(industry: tuple, pattern: tuple, example_idx: int) -> str:
    ind_name, sys_name, arch_desc = industry
    pat_id, pat_desc, pat_cat, artifact_hint = pattern
    uid = _uid(f"BOLA{ind_name}{pat_id}{example_idx}")

    obj_names = ["resource", "record", "asset", "entity", "document", "item", "object", "node"]
    obj_type = random.choice(obj_names)
    obj_id_val = f"{obj_type[:3].upper()}-{1000 + example_idx}"
    victim_id  = f"{obj_type[:3].upper()}-{2000 + example_idx}"
    tenant_a   = f"ORG-{uid[:4].upper()}"
    tenant_b   = f"ORG-{uid[4:8].upper()}"
    endpoint   = f"/api/v{random.randint(1,3)}/{obj_type}s"

    artifact_type = "HAR"
    if "schema" in artifact_hint:
        artifact_type = "schema"
    elif "GraphQL" in artifact_hint:
        artifact_type = "GraphQL HAR"

    schema_snippet = f"""
-- {obj_type.capitalize()} table
CREATE TABLE {obj_type}s (
    {obj_type}_id    VARCHAR(50) PRIMARY KEY,
    owner_id         VARCHAR(50) NOT NULL REFERENCES users(user_id),
    tenant_id        VARCHAR(50) NOT NULL,
    status           VARCHAR(20) DEFAULT 'active',
    sensitive_data   TEXT,
    created_at       TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_{obj_type}_tenant ON {obj_type}s(tenant_id);
-- NOTE: Application code does NOT use tenant_id in authorization checks
"""

    har_or_artifact = f"""{{
  "log": {{
    "version": "1.2",
    "entries": [
      {{
        "startedDateTime": "{_ts()}",
        "time": {random.randint(50, 300)},
        "request": {{
          "method": "{random.choice(['GET', 'GET', 'PATCH', 'DELETE'])}",
          "url": "https://api.{sys_name.lower().replace(' ', '-')[:15]}.example.com{endpoint}/{victim_id}",
          "httpVersion": "HTTP/1.1",
          "headers": [
            {{"name": "Authorization", "value": "Bearer {_random_jwt('user', tenant_a)}"}},
            {{"name": "X-Tenant-ID", "value": "{tenant_a}"}},
            {{"name": "Accept", "value": "application/json"}}
          ],
          "queryString": [],
          "bodySize": 0
        }},
        "response": {{
          "status": 200,
          "statusText": "OK",
          "content": {{
            "mimeType": "application/json",
            "text": "{{\\"id\\":\\"{victim_id}\\",\\"tenantId\\":\\"{tenant_b}\\",\\"ownerId\\":\\"other-user-{uid}\\",\\"sensitiveData\\":\\"CONFIDENTIAL: cross-tenant data for {tenant_b}\\"}}"
          }},
          "bodySize": {random.randint(100, 400)}
        }}
      }}
    ]
  }}
}}"""

    return f"""# ENGINEERING ARCHITECTURE SPECIFICATION
**System Name:** {sys_name}
**Document Version:** {random.randint(1,5)}.{random.randint(0,9)}.0 (FINAL)
**Classification:** SENSITIVE
**Domain:** {ind_name}
**Architecture:** {arch_desc}
**Training Example ID:** BOLA-{example_idx:04d}

## 1.0 Executive Summary
{sys_name} is a {ind_name.lower()} platform with a REST API. Resources are partitioned
by `tenant_id` and ownership is tracked via `owner_id`. The API uses JWT authentication
where the token encodes `sub` (user ID) and `tenant_id`.

## 2.0 Architecture
- **API:** REST ({endpoint} endpoints)
- **Auth:** OAuth2 JWT with `sub` and `tenant_id` claims
- **Database:** PostgreSQL with logical tenant partitioning
- **Pattern under test:** {pat_id} — {pat_desc}

## 3.0 Database Schema
```sql
{schema_snippet}
```

## 4.0 Vulnerability Context
**Pattern:** {pat_id} — {pat_desc} ({pat_cat})

The `GET/PATCH/DELETE {endpoint}/:id` endpoint accepts a `{obj_type}_id` in the URL path.
The backend handler queries the database by ID only, without filtering by `owner_id` or `tenant_id`.
An authenticated user from `{tenant_a}` can access objects owned by `{tenant_b}`.

_Specific exploitation for Pattern {pat_id}:_ {_bola_specific_note(pat_id, obj_type, endpoint, tenant_a, tenant_b, uid)}

## 5.0 Artifact ({artifact_type})
```json
{har_or_artifact}
```

## 6.0 Known Risk Log
- **RISK-{pat_id.replace('.', '')}-{example_idx:03d}:** Pattern {pat_id} detected in `{endpoint}` handler.
  The handler was written before the tenant isolation policy was established.
  Remediation is blocked pending DB migration ticket #DB-{example_idx + 100}.
"""


def _bola_specific_note(pat_id: str, obj_type: str, endpoint: str, ta: str, tb: str, uid: str) -> str:
    notes = {
        "1.1": f"Direct ID substitution: attacker replaces their own `{obj_type}_id` in `GET {endpoint}/:id` with a victim's ID.",
        "1.3": f"List endpoint `GET {endpoint}` returns all objects across tenants when no `tenant_id` filter is applied.",
        "1.5": f"Token from `{ta}` passes `tenantId={tb}` as a query parameter. Server trusts client-supplied tenant.",
        "1.6": f"PATCH/DELETE `{endpoint}/:id` does not verify the authenticated user owns the target object.",
        "1.7": f"Nested endpoint `{endpoint}/:id/children/:childId` validates child exists but not that parent belongs to the caller.",
        "1.8": f"IDs are sequential integers (`{obj_type[0].upper()}-1001`, `{obj_type[0].upper()}-1002`...) — enumeration is trivial.",
        "1.9": f"Batch endpoint accepts `?ids[]={obj_type[0].upper()}-{uid[:4].upper()}&ids[]={obj_type[0].upper()}-{uid[4:8].upper()}` without per-ID ownership checks.",
        "1.11": f"Redis cache keyed by `{obj_type}_id` only. Session A primes cache; Session B gets Session A's data.",
        "1.12": f"PATCH accepts `ownerId` and `tenantId` in the request body. Mass assignment allows ownership transfer.",
        "2.1": f"User with `role=user` calls `GET /admin/{obj_type}s` — vertical escalation to admin endpoint.",
        "3.2": f"Multi-step workflow: `POST {endpoint}/:id/submit` succeeds without completing the prior `/validate` step.",
        "6.1": f"GET `/swagger.json` or `/graphql?query={{__schema{{types{{name}}}}}}` exposes internal schema.",
        "8.1": f"Concurrent PATCH requests during a state transition create a race window where ownership is uncommitted.",
    }
    return notes.get(pat_id, f"The `{endpoint}` handler does not enforce tenant/owner boundaries for Pattern {pat_id}.")


def _make_bola_expected_response(industry: tuple, pattern: tuple, example_idx: int) -> str:
    ind_name, sys_name, _ = industry
    pat_id, pat_desc, pat_cat, _ = pattern
    uid = _uid(f"BOLA{ind_name}{pat_id}{example_idx}")
    obj_type = "resource"
    endpoint = "/api/v1/resources"
    tenant_a = f"ORG-{uid[:4].upper()}"
    tenant_b = f"ORG-{uid[4:8].upper()}"
    victim_id = f"RES-{2000 + example_idx}"

    return f"""# Expected Response

## System
- Domain: {ind_name}
- System: {sys_name}
- Example ID: BOLA-{example_idx:04d}

## Priority Findings

### Finding 1: {pat_desc} (Pattern {pat_id})
**Severity:** Critical
**Category:** {pat_cat}

**Summary:**
The `{endpoint}` endpoint is vulnerable to Pattern {pat_id} ({pat_desc}).
An authenticated user from `{tenant_a}` can access or modify objects owned by `{tenant_b}`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `{tenant_a}`
- Response body `tenantId`: `{tenant_b}` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.{sys_name.lower().replace(' ', '-')[:15]}.example.com{endpoint}/RES-{1000+example_idx}" \\
  -H "Authorization: Bearer <TOKEN_TENANT_{tenant_a}>"
```
Expected: Returns own record with `tenantId: "{tenant_a}"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.{sys_name.lower().replace(' ', '-')[:15]}.example.com{endpoint}/{victim_id}" \\
  -H "Authorization: Bearer <TOKEN_TENANT_{tenant_a}>"
```
**Vulnerable:** Returns `tenantId: "{tenant_b}"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern {pat_id}
{_bola_repro_variant(pat_id, endpoint, tenant_a, tenant_b, victim_id)}

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
"""


def _bola_repro_variant(pat_id: str, endpoint: str, ta: str, tb: str, victim_id: str) -> str:
    variants = {
        "1.3": f"```bash\n# List endpoint — check if cross-tenant objects appear\ncurl -s \"{endpoint}\" -H \"Authorization: Bearer <TOKEN_TENANT_{ta}>\"\n# Vulnerable: objects with tenantId={tb} appear in list\n```",
        "1.9": f"```bash\n# Batch lookup\ncurl -s \"{endpoint}/batch?ids={victim_id},RES-3001\" -H \"Authorization: Bearer <TOKEN_TENANT_{ta}>\"\n# Vulnerable: both objects returned regardless of tenant\n```",
        "1.12": f"```bash\n# Mass assignment\ncurl -s -X PATCH \"{endpoint}/{victim_id}\" -H \"Authorization: Bearer <TOKEN_TENANT_{ta}>\" -d '{{\"ownerId\":\"attacker\",\"tenantId\":\"{ta}\"}}'\n# Vulnerable: ownership transferred\n```",
        "1.6": f"```bash\n# Write-level BOLA\ncurl -s -X DELETE \"{endpoint}/{victim_id}\" -H \"Authorization: Bearer <TOKEN_TENANT_{ta}>\"\n# Vulnerable: 200 OK / record deleted across tenant boundary\n```",
    }
    return variants.get(pat_id, f"No specific variant documented for Pattern {pat_id} — use Steps 1-2.")


def _make_bola_explanation(industry: tuple, pattern: tuple, example_idx: int) -> str:
    ind_name, sys_name, _ = industry
    pat_id, pat_desc, pat_cat, _ = pattern
    return f"""# Analysis Explanation

This example (BOLA-{example_idx:04d}) was generated independently for **{sys_name}** ({ind_name}).

## Generation Method
1. Selected industry: **{ind_name}**
2. Designed REST API architecture with PostgreSQL and JWT authentication.
3. Embedded **Pattern {pat_id} ({pat_desc})** from bola_patterns.md.
4. Generated artifact (HAR/schema) showing the vulnerability evidence.
5. Wrote expected response grounded exclusively in this example's context.txt.

## Consistency Guard
- Context refreshed for this example; no data from other examples was used.
- All IDs, tenant values, and endpoints are self-consistent within this folder.

## Pattern Coverage
- Primary: Pattern {pat_id} — {pat_desc} ({pat_cat})
"""


# ─────────────────────────────────────────────────────────────────────────────
# Main generation orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def _graphql_patterns() -> list[tuple]:
    return [p for p in BOLA_PATTERNS if "GraphQL" in p[3]]


def _salesforce_patterns() -> list[tuple]:
    return [p for p in BOLA_PATTERNS if "Salesforce" in p[3]]


def _injection_patterns() -> list[tuple]:
    return [p for p in BOLA_PATTERNS if "Injection" in p[2] or p[0] in ("5.1", "5.2", "5.3", "5.4")]


def generate_graphql(count: int, reviewing_root: Path, start_idx: int = 1) -> int:
    patterns = _graphql_patterns()
    industries = INDUSTRIES
    created = 0
    for i in range(count):
        idx = start_idx + i
        industry = industries[i % len(industries)]
        # Rotate patterns to ensure coverage
        pattern = patterns[i % len(patterns)]
        random.seed(idx * 31337)

        folder_name = f"GQL-{idx:04d}-{industry[0].split('/')[0].strip().replace(' ', '-')[:15].upper()}"
        dest = next_example_folder(reviewing_root, folder_name)
        if dest.exists():
            print(f"  SKIP (exists): {folder_name}")
            continue
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "context.txt").write_text(_make_graphql_context(industry, pattern, idx), encoding="utf-8")
        (dest / "expected_response.md").write_text(_make_graphql_expected_response(industry, pattern, idx), encoding="utf-8")
        (dest / "analysis_explanation.md").write_text(_make_graphql_explanation(industry, pattern, idx), encoding="utf-8")
        created += 1
        if created % 50 == 0:
            print(f"  ... {created}/{count} GraphQL examples created")
    return created


def generate_salesforce(count: int, reviewing_root: Path, start_idx: int = 1) -> int:
    patterns = _salesforce_patterns()
    industries = INDUSTRIES
    created = 0
    for i in range(count):
        idx = start_idx + i
        industry = industries[i % len(industries)]
        pattern = patterns[i % len(patterns)]
        random.seed(idx * 13337)

        folder_name = f"SF-{idx:04d}-{industry[0].split('/')[0].strip().replace(' ', '-')[:15].upper()}"
        dest = next_example_folder(reviewing_root, folder_name)
        if dest.exists():
            print(f"  SKIP (exists): {folder_name}")
            continue
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "context.txt").write_text(_make_salesforce_context(industry, pattern, idx), encoding="utf-8")
        (dest / "expected_response.md").write_text(_make_salesforce_expected_response(industry, pattern, idx), encoding="utf-8")
        (dest / "analysis_explanation.md").write_text(_make_salesforce_explanation(industry, pattern, idx), encoding="utf-8")
        created += 1
        if created % 50 == 0:
            print(f"  ... {created}/{count} Salesforce examples created")
    return created


def generate_injection(count: int, reviewing_root: Path, start_idx: int = 1) -> int:
    patterns = _injection_patterns()
    industries = INDUSTRIES
    created = 0
    for i in range(count):
        idx = start_idx + i
        industry = industries[i % len(industries)]
        inj = INJECTION_TYPES[i % len(INJECTION_TYPES)]
        pattern = patterns[i % len(patterns)]
        random.seed(idx * 99991)

        folder_name = f"INJ-{idx:04d}-{inj[1]}-{industry[0].split('/')[0].strip().replace(' ', '-')[:10].upper()}"
        dest = next_example_folder(reviewing_root, folder_name)
        if dest.exists():
            print(f"  SKIP (exists): {folder_name}")
            continue
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "context.txt").write_text(_make_injection_context(industry, inj, pattern, idx), encoding="utf-8")
        (dest / "expected_response.md").write_text(_make_injection_expected_response(industry, inj, idx), encoding="utf-8")
        (dest / "analysis_explanation.md").write_text(_make_injection_explanation(industry, inj, idx), encoding="utf-8")
        created += 1
        if created % 100 == 0:
            print(f"  ... {created}/{count} Injection examples created")
    return created


def generate_bola(count: int, reviewing_root: Path, start_idx: int = 1, pattern_filter: list[str] | None = None) -> int:
    if pattern_filter:
        patterns = [p for p in BOLA_PATTERNS if p[0] in pattern_filter]
        if not patterns:
            patterns = BOLA_PATTERNS
    else:
        patterns = BOLA_PATTERNS
    industries = INDUSTRIES
    created = 0
    for i in range(count):
        idx = start_idx + i
        industry = industries[i % len(industries)]
        pattern = patterns[i % len(patterns)]
        random.seed(idx * 77777)

        folder_name = f"BOLA-{idx:04d}-P{pattern[0].replace('.', '')}-{industry[0].split('/')[0].strip().replace(' ', '-')[:10].upper()}"
        dest = next_example_folder(reviewing_root, folder_name)
        if dest.exists():
            print(f"  SKIP (exists): {folder_name}")
            continue
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "context.txt").write_text(_make_bola_context(industry, pattern, idx), encoding="utf-8")
        (dest / "expected_response.md").write_text(_make_bola_expected_response(industry, pattern, idx), encoding="utf-8")
        (dest / "analysis_explanation.md").write_text(_make_bola_explanation(industry, pattern, idx), encoding="utf-8")
        created += 1
        if created % 100 == 0:
            print(f"  ... {created}/{count} BOLA examples created")
    return created


def generate_gap(count: int, reviewing_root: Path, coverage_file: Path, start_idx: int = 1) -> int:
    """Generate examples targeting patterns with <50 examples according to coverage_file."""
    if coverage_file.exists():
        coverage = json.loads(coverage_file.read_text(encoding="utf-8"))
    else:
        coverage = {}

    # Find under-represented patterns
    under_represented = [
        pat[0] for pat in BOLA_PATTERNS
        if coverage.get(pat[0], 0) < 50
    ]
    if not under_represented:
        # Fallback: use all patterns sorted by count ascending
        under_represented = sorted(
            [p[0] for p in BOLA_PATTERNS],
            key=lambda pid: coverage.get(pid, 0)
        )

    print(f"Under-represented patterns (<50 examples): {under_represented}")
    return generate_bola(count, reviewing_root, start_idx=start_idx, pattern_filter=under_represented)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic security training examples")
    parser.add_argument("mode", choices=["graphql", "salesforce", "injection", "bola", "gap"],
                        help="Generation mode")
    parser.add_argument("--count", type=int, default=100, help="Number of examples to generate")
    parser.add_argument("--start-idx", type=int, default=1, help="Starting index for example IDs")
    parser.add_argument("--reviewing-root", default=str(REVIEWING_ROOT), help="Path to reviewing root")
    parser.add_argument("--coverage-file", default=str(REPO_ROOT / "docs" / "coverage_statistics.json"),
                        help="Coverage JSON file (for gap mode)")
    args = parser.parse_args()

    root = Path(args.reviewing_root)
    print(f"Mode: {args.mode} | Count: {args.count} | Start: {args.start_idx}")

    if args.mode == "graphql":
        created = generate_graphql(args.count, root, args.start_idx)
    elif args.mode == "salesforce":
        created = generate_salesforce(args.count, root, args.start_idx)
    elif args.mode == "injection":
        created = generate_injection(args.count, root, args.start_idx)
    elif args.mode == "bola":
        created = generate_bola(args.count, root, args.start_idx)
    elif args.mode == "gap":
        created = generate_gap(args.count, root, Path(args.coverage_file), args.start_idx)
    else:
        print(f"Unknown mode: {args.mode}")
        return 1

    print(f"\nDone. Created {created} examples.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
