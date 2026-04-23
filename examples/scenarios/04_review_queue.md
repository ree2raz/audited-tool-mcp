# Scenario 04: Review Queue

**Role**: `compliance_officer`
**Tool**: `sql_query`
**Expected**: Some detections flagged for human review (REVIEW action)

## Query

```
Show recent transactions with wire transfer descriptions
```

## Pipeline trace

1. **RBAC**: ✅ Compliance officer has full access
2. **Inbound PII scan**: No PII in query
3. **Inbound policy**: No actions needed
4. **Tool execution**: Returns transactions with descriptions that may contain PII
5. **Outbound PII scan**: Detects various PII in transaction descriptions:
   - Person names in "Transfer to Sarah's account"
   - Dates in transaction descriptions
   - Account numbers in "account ending in 4821"
6. **Outbound policy** (STRICT_FINANCIAL):
   - `private_person` → **REDACT**
   - `private_date` → **REVIEW** (flagged, not blocked)
   - `account_number` → **REDACT**
7. **Review queue**: Entry written to `review_queue.jsonl`
8. **Audit log**: Record with `status: "review_queued"`, `review_queue_id` populated

## Review queue entry

```json
{
  "review_id": "uuid-...",
  "request_id": "uuid-...",
  "actor": {"role": "compliance_officer", "user_id": "co-001"},
  "tool_name": "sql_query",
  "direction": "outbound",
  "detections": [{"category": "private_date", "text": "03/15/2024", ...}],
  "status": "pending"
}
```

## Key behavior

- **REVIEW does not block**: The request proceeds normally
- The review queue entry is written for later human inspection
- The audit log captures the review flag
- In v1, review is synchronous (Option 1). Async hold is a Phase 2 extension.
