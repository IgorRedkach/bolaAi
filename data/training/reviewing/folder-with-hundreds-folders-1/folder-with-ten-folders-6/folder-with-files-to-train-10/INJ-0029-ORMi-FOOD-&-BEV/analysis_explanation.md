# Analysis Explanation
**Example:** INJ-0029-ORMi-FOOD-&-BEV — TraceOrigin Supply API
**Pattern:** ORM Injection (SQL injection via Hibernate/Sequelize raw query)

---

## Why This Is a Vulnerability

ORM Injection is a specific subclass of SQL injection that occurs when a developer uses an ORM (Object-Relational Mapper like Hibernate or Sequelize) but bypasses the ORM's parameterized query protection by using raw query methods with string concatenation. ORMs like Sequelize and Hibernate provide safe, parameterized APIs (e.g., `Model.findAll({ where: {...} })`), but also expose raw execution methods (`db.execute()`, `sequelize.query()`) that, when used with string concatenation, are just as vulnerable as raw SQL. The payload `1; DROP TABLE products--` terminates the SELECT statement with `;`, executes a DDL statement (`DROP TABLE`), and comments out the remainder with `--`.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for INJ-0029.

- **System Name:** TraceOrigin Supply API (§1.0)
- **Domain:** Food & Beverage / FMCG
- **Host:** `api.traceorigin-sup.example.com` (§5.0 HAR)
- **Vulnerable endpoint:** `GET /api/v1/products` (§3.0, §5.0 HAR)
- **Vulnerable parameter:** `name` (§3.0, §4.0)
- **Injection payload:** `1; DROP TABLE products--` (§4.0)
- **ORM:** Hibernate/Sequelize raw queries (§2.0)
- **Vulnerable code:** raw string concatenation `${req.query.name}` in `db.execute()` (§3.0)
- **Data exposed:** admin credentials (`username: admin`, `password_hash: $2b$12$secret`, `role: ADMIN`), user2 credentials (§5.0 response)
- **Compounding factors:** over-privileged DB account (`db_owner`) with DDL permissions, no WAF (§6.0)
- **Known risk:** `RISK-INJ-029` — `/api/v1/products` missed in parameterization migration (§7.0)

## Domain Risk

Food & Beverage / FMCG supply chain platforms manage ingredient traceability, supplier contracts, batch records, and food safety certifications. SQL injection that drops the `products` table causes catastrophic data loss — product supply chain records, batch traceability data, and supplier relationships are destroyed. This could trigger food safety incidents if traceability records needed for recalls are deleted. Admin credential exposure allows full system compromise.

## What the Model Should Learn

- ORM injection is not prevented by using an ORM — it only occurs when raw query methods are used with string concatenation, bypassing the ORM's safe parameterization layer.
- The key distinction: `Model.findAll({ where: { name: value } })` is safe; `db.execute("SELECT * FROM products WHERE name = '" + value + "'")` is vulnerable.
- `1; DROP TABLE products--` is a classic SQL injection test: `1` satisfies the original query, `;` terminates it, `DROP TABLE` destroys data, `--` comments out the rest.
- Data destruction (DDL injection) is more severe than data exfiltration: it is irreversible without backups and can cause business continuity failures.
- `db_owner` over-privilege is the compounding factor that makes `DROP TABLE` possible — a least-privilege read-only role would prevent DDL execution even if injection succeeds.
