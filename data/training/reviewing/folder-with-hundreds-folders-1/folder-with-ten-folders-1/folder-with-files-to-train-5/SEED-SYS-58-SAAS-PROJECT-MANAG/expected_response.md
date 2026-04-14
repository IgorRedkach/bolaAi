## System

- System: TaskFlow Project Management API v6.1.0
- Domain: SAAS / PROJECT MANAGEMENT / WORK TRACKING
- Risk ID: RISK-GRPH-703

## Findings

### 1. BOLA on Nested Resource via Direct Top-Level Query — Missing Parent Project Membership Check (Pattern 5.2 + Pattern 1.7)

The Go-lang `task(id: Int)` query resolver (`taskResolver.go`, section 6.1) fetches the task by ID without verifying the authenticated user's membership in the task's parent project:

```go
// VULNERABILITY 1.7: Missing Parent Authorization Check
// The code queries the task by ID, but does NOT verify that the authenticated
// user is a member of the task's parent project (Project-B).
task, err := db.GetTaskByID(taskId)
// ...
// Step 2: Fails to call an external service or perform a DB lookup to check
// if db.CheckUserProjectMembership(userId, task.ProjectID) is true.
return task, nil  // Returns unauthorized, confidential data
```

The `tasks` table has `project_id` as a foreign key referencing `projects(project_id)` — this is the parent link (section 5.0, RISK-GRPH-703). The authorization policy (section 3.1) requires the user to be listed in `Project.members` for the task's parent project. The Go resolver retrieves `task.ProjectID` but never calls the membership check. It trusts that the "upstream gateway only checks token validity" — which is insufficient for object-level authorization.

**HAR evidence**: POST `https://api.taskflow.com/graphql`. JWT: `user_id: usr_attacker_1`. Query: `task(id: 20045) { confidentialNotes projectName: project { name } }`. Response header `x-service-resolved-by: TaskService` confirms the Task Service handled the request directly (not via a Project resolver parent). Response: HTTP 200 OK. `task.id: 20045`, `projectName.name: "Acquisition Target ORION (Tenant B)"`, `confidentialNotes: "Final valuation report attached. Target company's core asset is IP, not physical infrastructure. Keep this strictly private."` — cross-tenant corporate acquisition data returned.

## Evidence

- **HAR trace**: attacker JWT → `task(id: 20045)` direct query → `x-service-resolved-by: TaskService` → HTTP 200 OK → cross-tenant `confidentialNotes` and project name returned.
- **Go resolver** (section 6.1): `db.GetTaskByID(taskId)` called without `db.CheckUserProjectMembership(userId, task.ProjectID)`. Comment explicitly marks the missing check.
- **Schema** (section 5.0): `project_id INT REFERENCES projects(project_id) NOT NULL` — parent FK exists in DB but not enforced in application layer.
- **Architecture** (section 4.0, RISK-GRPH-703): "The Task resolver in the Go-lang service was implemented to only check if the requested task ID exists, relying on the upstream Project resolver to perform all necessary BOLA checks."

## Reproduction

```http
POST /graphql HTTP/2.0
Host: api.taskflow.com
Authorization: Bearer <USER_A_JWT>
Content-Type: application/json

{"query": "query TaskBOLA { task(id: 20045) { id confidentialNotes project { name } } }"}
```

`task_id` `20045` must belong to a project where the attacker is not a member.

Expected secure outcome: GraphQL error or `null` — task not found for the authenticated user's membership context.  
Observed vulnerable outcome: HTTP 200 OK, `confidentialNotes: "Final valuation report attached..."`, `project.name: "Acquisition Target ORION (Tenant B)"`.

## Remediation

- **Add parent project membership check to the task resolver** (RISK-GRPH-703): after `db.GetTaskByID(taskId)`, call `db.CheckUserProjectMembership(userId, task.ProjectID)` — return `nil` or a `ForbiddenError` if the check fails.
- **Use a membership-scoped SQL query instead of a two-step lookup**: replace `db.GetTaskByID(taskId)` with a query that joins `task` to `project_members`: `SELECT t.* FROM tasks t JOIN project_members pm ON t.project_id = pm.project_id WHERE t.task_id = $1 AND pm.user_id = $2` — a single query that enforces the FK authorization at the DB layer.
- **Never rely on the upstream gateway for object-level authorization on child resolvers**: every resolver that exposes a data object must independently verify the caller's access to that specific object's authorization context.
