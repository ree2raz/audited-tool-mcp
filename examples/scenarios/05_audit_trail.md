# Scenario 05: Audit Trail

**Role**: `analyst`
**Tool**: `sql_query`
**Expected**: Complete audit record with all 17 fields populated

## Query

```
SELECT id, first_name, last_name, email FROM customers WHERE id = 42
```

## Full audit record

```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp_utc": "2026-04-23T15:30:00.000000+00:00",
  "actor": {
    "role": "analyst",
    "user_id": "analyst-001",
    "session_id": "sess-abc123"
  },
  "tool_name": "sql_query",
  "raw_query_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "inbound_detections": [],
  "policy_decisions_inbound": [],
  "tool_input_after_policy": "SELECT id, first_name, last_name, email FROM customers WHERE id = 42",
  "tool_output_raw_hash": "abc123...",
  "outbound_detections": [
    {
      "category": "private_person",
      "start": 25,
      "end": 37,
      "text": "[private_person]",
      "confidence": 0.95
    },
    {
      "category": "private_email",
      "start": 52,
      "end": 73,
      "text": "[private_email]",
      "confidence": 0.98
    }
  ],
  "policy_decisions_outbound": [
    {
      "category": "private_person",
      "action": "hash",
      "reason": "Hash names for identity consistency"
    },
    {
      "category": "private_email",
      "action": "allow",
      "reason": "Emails visible to analysts"
    }
  ],
  "tool_output_final": "[{\"email\": \"alice@example.com\", \"first_name\": \"[private_person:a1b2c3d4]\", \"id\": 42, \"last_name\": \"[private_person:e5f6g7h8]\"}]",
  "status": "success",
  "latency_ms": 42.5,
  "review_queue_id": null,
  "policy_version": "permissive_analyst_v1",
  "model_version": "openai/privacy-filter"
}
```

## Key fields explained

| Field | Purpose | Why it matters for audit |
|-------|---------|------------------------|
| `request_id` | UUID4 per request | Correlate across logs |
| `raw_query_hash` | SHA-256 of original query | Prove what was asked without storing the query |
| `tool_output_raw_hash` | SHA-256 of raw tool output | Prove what the tool returned before policy |
| `policy_version` | Which policy was in effect | Answer "when did we start blocking X?" |
| `model_version` | Which PII model was used | Explain detection pattern changes |
| `review_queue_id` | Links to review queue entry | Track human review workflow |

## What's NOT in the audit log

- Raw PII text (detection `text` fields use `[category]` placeholders)
- Original query text (only the hash)
- Raw tool output (only the hash; the post-policy output is stored)

The vault file (`vault.jsonl`) stores original PII values when the VAULT action fires,
but it's separate and access-controlled.
