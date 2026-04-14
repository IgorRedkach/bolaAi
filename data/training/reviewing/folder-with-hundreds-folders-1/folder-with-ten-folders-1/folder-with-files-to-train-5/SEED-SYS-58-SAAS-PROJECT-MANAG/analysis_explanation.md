## Analysis reasoning

I reviewed the TaskFlow Project Management API v6.1.0 architecture specification, Go-lang resolver code, schema, and HAR trace.

1. **Parent authorization bypass pattern**: section 4.0 documents the exact assumption that created the gap: "The Task resolver was implemented to only check if the requested task ID exists, relying on the upstream Project resolver to perform all necessary BOLA checks." This is a classic split-responsibility failure — the Project resolver has the authorization logic, but an attacker bypasses the Project resolver entirely by querying `task(id: 20045)` directly. There is no "upstream" in a direct top-level query to `task`.

2. **HAR `x-service-resolved-by: TaskService` is key evidence**: this header shows the Apollo Federation Gateway routed the request directly to the TaskService without passing through the ProjectService. There was no Project-level authorization check executed — only the TaskService's own resolver ran. The TaskService does not perform membership verification, so the data is returned unconditionally.

3. **FK relationship exists but is not enforced**: the `tasks.project_id` FK in the schema is the correct security contract. The resolver has access to `task.ProjectID` (retrieved as part of `db.GetTaskByID(taskId)`) but never passes it to `db.CheckUserProjectMembership()`. The Go code comment explicitly marks this: "Fails to call an external service or perform a DB lookup to check if `db.CheckUserProjectMembership(userId, task.ProjectID)` is true."

4. **Cross-tenant confirmation via project name**: the response includes `projectName.name: "Acquisition Target ORION (Tenant B)"`. The project name itself contains "Tenant B" — confirming the data belongs to a different organizational tenant. The `confidentialNotes` contain M&A valuation details ("Final valuation report attached. Target company's core asset is IP"). This is material non-public corporate information.

5. **Pattern 5.2 vs 1.7**: Pattern 5.2 is about graph edge traversal; Pattern 1.7 is about nested resources without parent authorization. The actual attack here is more 1.7 — the attacker is not traversing an edge (e.g., user → project → tasks) but querying a top-level `task()` resolver directly. The "traversal" element is that the Task is semantically a nested resource that should require the parent Project's authorization context, but the top-level resolver treats it as an independent resource.
