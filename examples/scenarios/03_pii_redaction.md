# Scenario 03: PII Redaction

**Role**: `analyst`
**Tool**: `sql_query`
**Expected**: PII detected and redacted/hashed in output based on policy

## Query

```
Look up transactions for the customer named Sarah Henderson
```

## Pipeline trace

1. **RBAC**: ✅ Analyst has access to `sql_query`
2. **Inbound PII scan**: Detects `private_person` span: "Sarah Henderson"
3. **Inbound policy** (PERMISSIVE_ANALYST): `private_person` → **ALLOW** inbound (names needed for lookups)
4. **Tool execution**: SQL runs with the original name in WHERE clause
5. **Outbound PII scan**: Detects multiple PII spans in results:
   - Customer names → `private_person`
   - Email addresses → `private_email`
   - Phone numbers → `private_phone`
   - Account numbers → `account_number`
6. **Outbound policy** (PERMISSIVE_ANALYST):
   - `private_person` → **HASH** (preserves identity consistency: `[private_person:a1b2c3d4]`)
   - `private_email` → **ALLOW** (analysts can see emails)
   - `private_phone` → **ALLOW** (analysts can see phones)
   - `account_number` → **REDACT** (`[account_number]`)
7. **Audit log**: Full record with all detections, decisions, and mutations

## Key behavior

- Names are **hashed**, not redacted — the same name always produces the same hash,
  allowing analysts to correlate records without seeing the actual PII
- Account numbers are **redacted** — replaced with `[account_number]`
- Emails and phones are **allowed** — visible to analysts per policy
