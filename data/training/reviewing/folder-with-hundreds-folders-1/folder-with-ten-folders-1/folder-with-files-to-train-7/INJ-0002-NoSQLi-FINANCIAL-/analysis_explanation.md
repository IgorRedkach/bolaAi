## Analysis reasoning

I reviewed the NexaBank Open Finance API v4.6.0 architecture, vulnerable code, and HAR trace.

1. **Critical errors in original expected_response.md**: (a) used `/api/v1/users?search=` instead of the documented `/api/v1/orders?category=`; (b) included `UNION SELECT` in Step 3 — this is an SQL technique, not a MongoDB technique; (c) referenced `load_file('/etc/passwd')` — not a MongoDB capability. These errors would make the training example teach the wrong injection mechanism.

2. **Context internal inconsistency**: section 3.0 shows SQL code (`SELECT * FROM orders WHERE category = '${req.query.category}'`) but section 2.0 says MongoDB and the injection payload is a MongoDB operator (`{ "$gt": "" }`). The vulnerability is described as "NoSQL Injection" and the database is explicitly "MongoDB / document store." The correct interpretation: the platform uses MongoDB and the injection is a MongoDB operator injection — the SQL code in section 3.0 is an error in the synthetic context.

3. **MongoDB operator injection mechanism**: when a Node.js/Express application reads `req.query.category` and passes it directly to MongoDB's `find()`, a URL-encoded JSON object `{%22$gt%22:%22%22}` is deserialized by Express into a JavaScript object `{"$gt":""}`. MongoDB interprets `{category: {"$gt": ""}}` as a comparison operator — returning all documents where `category > ""`, which matches everything. This is the core of the attack.

4. **The `$exists` and `$ne` variants add enumeration power**: MongoDB operator injection supports all comparison, logical, and element operators. `{category: {"$exists": true}}` returns all documents where the field exists. `{category: {"$ne": "INVALID_CATEGORY"}}` returns all documents where `category` is not that value. These variants allow enumeration without knowing exact values.

5. **Remediation differs from SQL injection**: unlike SQLi (which requires parameterized queries), NoSQL operator injection is prevented by: (a) type checking — ensure query parameters are scalar types, not objects; (b) Mongoose schema enforcement; (c) operator key sanitization (strip `$` prefixed keys from user input).
