"""
Generate BOLA-focused training data (JSONL) for RAG or fine-tuning.
Based on OWASP patterns and real-world examples from GOALS.md.
"""

import json
from pathlib import Path

# Output path
OUTPUT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "training"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

EXAMPLES = [
    {
        "scenario": "Patient API without ownership check",
        "context": "API: GET /api/patients/{id}. Returns patient record. Documentation does not state that the server verifies the authenticated user is the patient or has a care relationship.",
        "risk": "Any logged-in user could query any patient ID and retrieve PII and diagnosis (BOLA).",
        "verification": "1. Log in as user A. 2. Call GET /api/patients/123. 3. Log in as user B. 4. Call GET /api/patients/123. If both return 200 and same data, BOLA is confirmed.",
        "example_queries": ["GET /api/patients/123", "GET /api/patients/124"],
    },
    {
        "scenario": "Restricted case linked to unrestricted team table",
        "context": "Case object is restricted by role. Cases link to team_members table. team_members is not restricted and is queried by case_id.",
        "risk": "User without access to US persons cases can still read team_members by case_id and infer or access restricted data.",
        "verification": "1. As user without case access, call GET /api/team_members?case_id=<restricted_case_id>. 2. If 200 and data returned, related resource is not protected.",
        "example_queries": ["GET /api/team_members?case_id=123"],
    },
    {
        "scenario": "Image storage API allows ID manipulation",
        "context": "Third-party image storage. Frontend gets URL like /storage/images/{id}. No server-side check that the authenticated user is allowed to view that image.",
        "risk": "Any user can change id in URL and download unreleased designs or other users' images.",
        "verification": "1. Obtain one valid image URL. 2. Change the id path segment to another value. 3. If image is returned, BOLA.",
        "example_queries": ["GET /storage/images/abc123", "GET /storage/images/abc124"],
    },
    {
        "scenario": "Order API exposes all orders",
        "context": "GET /api/orders returns list. Documentation does not mention filtering by current user or tenant.",
        "risk": "Backend may return all orders; any authenticated user could see every order.",
        "verification": "1. Create orders as user A. 2. Log in as user B. 3. GET /api/orders. 4. If user B sees user A's orders, BOLA.",
        "example_queries": ["GET /api/orders"],
    },
    {
        "scenario": "Logs and retries expose full request data",
        "context": "Failed or retried API calls are logged with full request/response. Logs are visible to operations team in another country.",
        "risk": "PII and object-level data (e.g. complaint details, customer data) exposed to people who should not have access (GDPR, policy).",
        "verification": "1. Review who has access to logs. 2. Check if logs contain object IDs, PII, or full request bodies. 3. If yes, treat as data exposure / BOLA in operational context.",
        "example_queries": [],
    },
    {
        "scenario": "GraphQL mutation deletes without ownership check",
        "context": "Mutation deleteDocument(id: ID!) exists. No documentation that server checks document ownership before delete.",
        "risk": "User can delete any document by guessing or enumerating IDs.",
        "verification": "1. User A creates document, gets id. 2. User B calls deleteDocument(id). 3. If document is deleted, BOLA.",
        "example_queries": ["mutation { deleteDocument(id: \"doc123\") { success } }"],
    },
    {
        "scenario": "Multi-tenant SaaS API without tenant isolation",
        "context": "GET /api/v1/accounts/{accountId}/reports. Each account belongs to a tenant. API requires Bearer token. No documentation states that the server checks the token's tenant matches the accountId's tenant.",
        "risk": "A user from tenant X could read reports belonging to tenant Y by changing accountId (cross-tenant BOLA).",
        "verification": "1. Obtain token for user in tenant X. 2. Call GET /api/v1/accounts/{accountId_in_tenant_Y}/reports with that token. 3. If data is returned, cross-tenant BOLA is confirmed.",
        "example_queries": ["GET /api/v1/accounts/999/reports"],
    },
    {
        "scenario": "PATCH endpoint updates resource without ownership check",
        "context": "PATCH /api/v1/invoices/{invoiceId}. Updates invoice status or amount. Requires authentication. No documentation states that the caller must be the invoice owner or the assigned merchant.",
        "risk": "Any authenticated user could modify another user's invoice (status, amount) by changing the invoiceId parameter.",
        "verification": "1. User A creates invoice, notes invoiceId. 2. User B calls PATCH /api/v1/invoices/{invoiceId} with different status. 3. If update succeeds, BOLA on write operation.",
        "example_queries": ["PATCH /api/v1/invoices/42 {\"status\": \"cancelled\"}"],
    },
    {
        "scenario": "Nested resource path without parent ownership check",
        "context": "GET /api/projects/{projectId}/tasks/{taskId}. Returns task details. API checks that taskId exists under projectId but does not verify the caller is a member of the project.",
        "risk": "Any authenticated user can enumerate projectIds and read tasks from projects they do not belong to.",
        "verification": "1. User A is member of project 1, not project 2. 2. User A calls GET /api/projects/2/tasks/5. 3. If task data is returned, BOLA on nested resource.",
        "example_queries": ["GET /api/projects/2/tasks/5"],
    },
    {
        "scenario": "File download endpoint using predictable IDs",
        "context": "GET /files/{fileId}/download. Returns file content. fileId is a sequential integer. Documentation says 'requires valid session'. No mention of per-file access control.",
        "risk": "Users can increment fileId to download other users' files (IDOR/BOLA on file download).",
        "verification": "1. Upload a file as user A, note fileId (e.g. 100). 2. As user B, call GET /files/100/download. 3. If the file is returned, BOLA confirmed.",
        "example_queries": ["GET /files/100/download", "GET /files/101/download"],
    },
    {
        "scenario": "Admin endpoint accessible by non-admin role",
        "context": "GET /admin/audit-log/{userId}. Returns audit log for any user. Documentation says role=admin required but no per-user ownership check.",
        "risk": "An admin user can see audit logs of users in other departments or tenants; or if role check is weak, a regular user might access it.",
        "verification": "1. As admin in dept A, call GET /admin/audit-log/{userId_in_dept_B}. 2. If data returned, object-level scope is missing even within the admin role.",
        "example_queries": ["GET /admin/audit-log/user456"],
    },
    {
        "scenario": "Webhook callback endpoint lacks request origin validation",
        "context": "POST /api/webhooks/payment-callback. Accepts orderId in body and updates payment status. Designed for payment gateway callbacks. No signature or origin check documented.",
        "risk": "An attacker can forge callback requests with arbitrary orderId values to mark payments as complete (BOLA on write via callback).",
        "verification": "1. Send POST /api/webhooks/payment-callback with a valid orderId but no gateway signature. 2. Check if the order status changes. 3. If yes, the callback lacks object-level validation.",
        "example_queries": ["POST /api/webhooks/payment-callback {\"orderId\": \"order789\", \"status\": \"paid\"}"],
    },
    {
        "scenario": "Batch endpoint returns objects across tenants",
        "context": "POST /api/v2/batch/lookup. Body: {\"ids\": [\"id1\", \"id2\", ...]}. Returns objects for all provided IDs. No mention of filtering by the caller's tenant or ownership.",
        "risk": "Attacker can submit IDs belonging to other tenants and retrieve their data in a single batch call.",
        "verification": "1. User A (tenant 1) creates objects, notes IDs. 2. User B (tenant 2) calls POST /api/v2/batch/lookup with those IDs. 3. If objects are returned, batch BOLA confirmed.",
        "example_queries": ["POST /api/v2/batch/lookup {\"ids\": [\"obj-001\", \"obj-002\"]}"],
    },
    {
        "scenario": "Prescription API returns data for any prescriptionId",
        "context": "GET /api/v1/prescriptions/{prescriptionId}. Returns medication name, dosage, and patient reference. Requires Bearer token. No mention of verifying that the caller is the patient or the prescribing provider.",
        "risk": "Any authenticated user could access any prescription by changing the prescriptionId, exposing medication and patient data (HIPAA risk).",
        "verification": "1. As user A (patient), call GET /api/v1/prescriptions/{ownPrescriptionId}. 2. As user B (different patient), call GET /api/v1/prescriptions/{samePrescriptionId}. 3. If user B receives data, BOLA is confirmed.",
        "example_queries": ["GET /api/v1/prescriptions/rx-123", "GET /api/v1/prescriptions/rx-124"],
    },
    # GraphQL
    {
        "scenario": "GraphQL query user(id) without ownership check",
        "context": "GraphQL API at POST /graphql. Query: user(id: ID!): User. Returns user profile. No documentation that the resolver checks whether the caller is allowed to access that user's data.",
        "risk": "Any authenticated user can query any user by ID and retrieve profiles (BOLA).",
        "verification": "1. User A calls query { user(id: \"userB-id\") { name email } } with token A. 2. User B calls same query with token B. If both receive userB data, BOLA.",
        "example_queries": ["query { user(id: \"123\") { name email } }"],
    },
    {
        "scenario": "GraphQL nested orders resolver does not filter by user",
        "context": "GraphQL schema: User { id, orders { id, total } }. Query: me: User. The me query returns the current user. Documentation does not state whether orders resolver filters by the parent User or returns all orders.",
        "risk": "If orders resolver does not filter by parent User, a user could receive another user's orders via a different query path or if me is misconfigured.",
        "verification": "1. As user A, call query { me { orders { id } } }. 2. As user B, call query { user(id: \"userA-id\") { orders { id } } } if such query exists. 3. If user B receives user A's orders, nested resolver BOLA.",
        "example_queries": ["query { me { orders { id total } } }"],
    },
    {
        "scenario": "GraphQL batch mutation deletes without per-ID ownership",
        "context": "Mutation: deleteDocuments(ids: [ID!]!): [Boolean]. Deletes documents by ID list. No documentation that each ID is checked for caller ownership.",
        "risk": "User can delete any documents by submitting IDs belonging to other users.",
        "verification": "1. User A creates document, notes id. 2. User B calls mutation { deleteDocuments(ids: [\"userA-doc-id\"]) }. 3. If document is deleted, batch mutation BOLA.",
        "example_queries": ["mutation { deleteDocuments(ids: [\"doc1\", \"doc2\"]) }"],
    },
    # SOQL / Salesforce
    {
        "scenario": "SOQL without WITH SECURITY_ENFORCED exposes cross-tenant records",
        "context": "Apex/API runs SOQL: SELECT Id, Name, Amount FROM Opportunity. No WITH SECURITY_ENFORCED. Sharing model is Private. Documentation does not mention record-level filtering.",
        "risk": "Query may return opportunities from other users or tenants if run in wrong context or without sharing enforcement.",
        "verification": "1. As user A, create Opportunity. 2. As user B (different owner), run equivalent SOQL. 3. If user B sees user A's opportunity, record-level BOLA. Check for WITH SECURITY_ENFORCED in code.",
        "example_queries": ["SELECT Id, Name FROM Opportunity"],
    },
    {
        "scenario": "Salesforce cross-object query exposes related Cases",
        "context": "SOQL: SELECT Id, Name, (SELECT Id, Subject FROM Cases) FROM Account. Account has sharing rules. Documentation does not state whether Cases subquery respects Account sharing or record-level access.",
        "risk": "User with read access to Account might receive Cases they should not see if subquery does not enforce sharing.",
        "verification": "1. User A owns Account X with Cases. 2. User B has limited Account access. 3. Run query as user B for Account X. 4. If Cases are returned when they should not be, cross-object BOLA.",
        "example_queries": ["SELECT Id, (SELECT Id FROM Cases) FROM Account WHERE Id = '001xxx'"],
    },
]


def to_rag_chunk(record: dict) -> str:
    """Format one example as a single text chunk for RAG ingestion."""
    lines = [
        f"## {record['scenario']}",
        f"Context: {record['context']}",
        f"Risk: {record['risk']}",
        f"Verification: {record['verification']}",
    ]
    if record.get("example_queries"):
        lines.append("Example queries: " + "; ".join(record["example_queries"]))
    return "\n".join(lines)


def to_jsonl_line(record: dict) -> dict:
    """One line for JSONL (instruction/target for fine-tuning or RAG)."""
    instruction = (
        "Analyze this scenario for BOLA. Provide: 1) Risk description, 2) Verification steps, 3) Example queries if applicable."
    )
    context = record["context"]
    queries = record.get("example_queries", [])
    target = (
        f"Risk: {record['risk']}\n"
        f"Verification: {record['verification']}"
        + (f"\nExample queries: {'; '.join(queries)}" if queries else "")
    )
    return {"instruction": instruction, "context": context, "target": target}


def main():
    jsonl_path = OUTPUT_DIR / "bola_training.jsonl"
    rag_path = OUTPUT_DIR / "bola_rag_chunks.txt"

    with open(jsonl_path, "w", encoding="utf-8") as f:
        for ex in EXAMPLES:
            f.write(json.dumps(to_jsonl_line(ex), ensure_ascii=False) + "\n")

    with open(rag_path, "w", encoding="utf-8") as f:
        for ex in EXAMPLES:
            f.write(to_rag_chunk(ex) + "\n\n---\n\n")

    print(f"Wrote {jsonl_path} ({len(EXAMPLES)} records)")
    print(f"Wrote {rag_path} (RAG chunks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
