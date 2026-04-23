# Scenario 02: RBAC Denial

**Role**: `intern`
**Tool**: any
**Expected**: Blocked at RBAC gate (Layer 1a)

## Query

```
Show me all customer SSNs
```

## Pipeline trace

1. **RBAC (1a)**: ❌ `intern` role has `allowed_tools = {}` (empty set)
   - O(1) set membership check: `"sql_query" not in set()` → **RBACDenied**
   - Pipeline halts immediately — cheapest denial path
2. **Layers 2-6**: Skipped entirely
3. **Audit log**: Record written with `status: "rbac_denied"`

## Expected output

```json
{"error": "RBAC denied: role=intern, tool=sql_query — Role 'intern' does not have access to tool 'sql_query'. Allowed tools: none"}
```

## Audit record

```json
{
  "request_id": "...",
  "actor": {"role": "intern", "user_id": "intern-001"},
  "tool_name": "sql_query",
  "status": "rbac_denied",
  "inbound_detections": [],
  "outbound_detections": [],
  "latency_ms": 0.1
}
```

## Also tested: Analyst blocked from restricted columns

```
SELECT ssn FROM customers
```

This triggers **RBAC step 1b** (SQL parsing): analyst can access `customers` table but `ssn` column is restricted.
