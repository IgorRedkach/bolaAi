# HelpDesk Support API — Internal Spec

## Overview

HelpDesk is used by support agents to manage customer tickets. The API is used by the ticket UI and by internal automation. JWT in `Authorization: Bearer <token>`.

## Authentication

- JWT required. Claims: sub (userId), role (agent|viewer|admin). No per-ticket or per-customer authorization is documented.

## API Endpoints

### Tickets

- **GET /support/tickets/{ticketId}** — Returns ticket details: subject, status, customerId, assignedAgentId, messages. Requires authenticated user.
- **POST /support/tickets/{ticketId}/comments** — Add a comment to the ticket. Body: `{ "body": "..." }`. Documentation does not state whether only the assigned agent or any agent can access or comment on any ticket.

### Comments

- **GET /support/comments/{commentId}** — Returns a single comment by ID. Used for audit. No mention of restricting access to the comment’s ticket owner or assigned agent.

## Data Model

- **Ticket** — ticketId, customerId, assignedAgentId, status, createdAt.
- **Comment** — commentId, ticketId, authorId, body, createdAt.

## Concern

If the API does not enforce that the caller can only access tickets they are assigned to (or that belong to their org), an agent could read or modify any ticket by changing the ticketId in the path.
