# Scenario 01: Analyst Query

**Role**: `analyst`
**Tool**: `sql_query`
**Expected**: Success with PII redaction in output

## Query

```
Show me the top 5 customers by total account balance
```

## Expected SQL

```sql
SELECT c.id, c.first_name, c.last_name, SUM(a.balance) as total_balance
FROM customers c
JOIN accounts a ON c.id = a.customer_id
GROUP BY c.id, c.first_name, c.last_name
ORDER BY total_balance DESC
LIMIT 5
```

## Pipeline trace

1. **RBAC**: ✅ Analyst has access to `sql_query`, `customers`, and `accounts` tables
2. **Inbound PII scan**: No PII in query → empty detections
3. **Inbound policy**: No actions needed
4. **Tool execution**: SQL runs successfully, returns 5 rows
5. **Outbound PII scan**: Privacy Filter detects `private_person` spans in customer names
6. **Outbound policy** (PERMISSIVE_ANALYST): Names are **hashed** (`[private_person:a1b2c3d4]`)
7. **Audit log**: Record written with full trace

## Expected output

```json
[
  {"id": 42, "first_name": "[private_person:a1b2c3d4]", "last_name": "[private_person:e5f6g7h8]", "total_balance": 487293.15},
  ...
]
```

Note: SSN and account_number columns are excluded by RBAC (analyst cannot access them).
