# Evaluation Harness

Automated evaluation of the audited-tool-mcp compliance pipeline against a golden set of test cases.

## Usage

```bash
# Run with mock PII detector (fast, no model download)
make eval

# Run with real Privacy Filter model
python eval/eval_harness.py --no-mock

# Use a custom golden set
python eval/eval_harness.py --golden-set path/to/custom_golden.jsonl
```

## Golden Set Format

Each line in `golden_set.jsonl` is a JSON object:

```json
{
  "role": "analyst",
  "query": "SELECT id, first_name FROM customers LIMIT 5",
  "expected_status": "success",
  "expected_rbac": "allow",
  "description": "Basic analyst query",
  "expected_inbound_categories": ["private_email"]
}
```

### Fields

| Field | Required | Values |
|-------|----------|--------|
| `role` | yes | intern, analyst, compliance_officer |
| `query` | yes | SQL or natural language query |
| `expected_status` | yes | success, rbac_denied, blocked, review_queued, error, timeout |
| `expected_rbac` | yes | allow, deny |
| `description` | no | Human-readable test description |
| `expected_inbound_categories` | no | List of PII categories expected in inbound scan |

## Metrics

The harness evaluates 4 dimensions:

1. **RBAC accuracy** — Did the pipeline correctly allow/deny based on role?
2. **Status accuracy** — Did the pipeline produce the expected terminal status?
3. **Inbound PII accuracy** — Were expected PII categories detected in the input?
4. **Audit completeness** — Are all required fields present in the audit record?
