# Architecture — auditguard-mcp v2

This document explains the architectural decisions behind the v2 pipeline redesign, specifically the introduction of Temporal as an optional orchestration backend.

## Core Principle: Separate Stage Logic from Orchestration

The most important architectural decision in v2 is that the 7 pipeline stages are **pure functions** that don't know how they're being orchestrated. This is the ports-and-adapters (hexagonal) pattern:

- **Ports**: The stage functions in `pipeline/stages.py` — pure, side-effect-free (except audit log write), deterministic.
- **Adapters**: `async_runner.py` and `temporal_runner.py` — thin wrappers that call the stages in the right order, with the right concurrency model, retry policy, and durability guarantees.

This means:
1. **Stage logic is tested once**, not twice. `test_pipeline_stages.py` covers all the business logic.
2. **Behavior is identical across backends**. Both async and Temporal run the same `check_rbac()`, `scan_inbound_pii()`, etc.
3. **Adding a third backend** (e.g., AWS Step Functions, Celery, Airflow) requires writing only the adapter — ~100 lines, not 400.

## Type Boundaries

The pipeline introduces its own types (`AuditRequest`, `AuditContext`, `PipelineDecision`, etc.) that are distinct from the existing domain models (`Actor`, `AuditRecord`, `PolicyDecision`). This separation is intentional:

| Layer | Types | Purpose |
|-------|-------|---------|
| Domain (`models.py`) | `Actor`, `AuditRecord`, `PIIDetection`, `PolicyDecision` | Rich models for the existing auditguard-mcp internals |
| Pipeline (`pipeline/types.py`) | `AuditRequest`, `AuditContext`, `PipelineDecision`, `PipelineLogEntry` | Serializable boundary types for orchestration adapters |

`AuditRequest` bridges to `Actor`. `PipelineLogEntry` bridges to `AuditRecord`. The adapters handle the mapping.

## The 7 Stages

```
Stage 1: check_rbac          → raises RBACDenied on failure
Stage 2: scan_inbound_pii    → returns PIIScanResult
Stage 3: apply_inbound_policy → returns PipelineDecision (ALLOW/TRANSFORM/HUMAN_REVIEW/BLOCK)
Stage 4: execute_bounded     → async, returns tool output string
Stage 5: scan_outbound_pii   → returns PIIScanResult
Stage 6: apply_outbound_policy → returns PipelineDecision
Stage 7: write_audit_log     → writes AuditRecord, returns PipelineLogEntry
```

Stages 1, 2, 3, 5, 6, 7 are synchronous. Stage 4 is async because it calls external tools.

## Async Backend

```python
async def run_audit_pipeline_async(request, context):
    check_rbac(request, context)                        # Stage 1 (thread)
    pii_inbound = await to_thread(scan_inbound_pii, ...) # Stage 2 (thread)
    inbound_decision = await to_thread(apply_inbound_policy, ...)  # Stage 3
    if inbound_decision.action in (DENY, BLOCK):
        return write_audit_log(...)
    output = await execute_bounded(...)                  # Stage 4 (async)
    pii_outbound = await to_thread(scan_outbound_pii, ...)         # Stage 5
    outbound_decision = await to_thread(apply_outbound_policy, ...) # Stage 6
    return write_audit_log(...)                          # Stage 7
```

**Durability gap**: If the Python process crashes after Stage 4 but before Stage 7, the audit log entry is lost. The request is also lost. This is acceptable for high-throughput, stateless workloads where the client can retry.

## Temporal Backend

Each stage becomes a Temporal **activity** with its own retry policy:

| Activity | Retry Policy | Timeout | Notes |
|----------|-------------|---------|-------|
| check_rbac | 3 attempts, 1-5s | 5s | Non-retryable: RBACDenied |
| scan_inbound_pii | 5 attempts, 2-30s, backoff=2x | 60s | Heartbeating for long model inference |
| apply_inbound_policy | No retry (deterministic) | 5s | |
| execute_bounded | 2 attempts, 1-10s | Configurable | Non-retryable: ValidationError |
| scan_outbound_pii | Same as inbound | 60s | |
| apply_outbound_policy | No retry | 5s | |
| write_audit_log | 20 attempts, up to 5m | 10s | Never give up on audit log |

The **workflow** (`AuditPipelineWorkflow`) orchestrates activities using `await workflow.execute_activity(...)`. It is fully deterministic — no random, no real time, no IO. All non-deterministic work happens in activities.

### Human-in-the-loop

The workflow supports a `human_review_complete` signal:

```python
if inbound_decision.action == PipelineAction.HUMAN_REVIEW:
    await workflow.wait_condition(
        lambda: self._human_review_decision is not None or self._cancelled,
        timeout=timedelta(hours=24),
    )
```

This is the killer feature. The workflow can sleep for hours or days while waiting for a human reviewer. Temporal persists the workflow state, so the review survives server restarts. Try doing this with asyncio.

### Why `sandboxed=False`

The workflow imports `pipeline/stages.py`, which imports `privacy.py`, which imports `torch`. Temporal's sandboxed workflow runner has compatibility issues with torch's C-extension initialization. We mark the workflow as `sandboxed=False` because:
1. The workflow code itself is deterministic (no random, no IO, no time).
2. All non-deterministic work (model inference, tool calls, file writes) happens in activities.
3. The sandbox is meant to catch non-determinism, but our architecture already isolates it.

## Tool Registry

Tools are registered in `tools/registry.py` as async callables:

```python
TOOL_REGISTRY: dict[str, ToolCallable] = {
    "sql_query": sql_query_tool,
    "customer_api_lookup": customer_lookup_tool,
    "customer_api_search": customer_search_tool,
}
```

Both backends use the same registry. `execute_bounded()` looks up the tool by name and calls it with the sanitized `tool_input` dict and the caller's role.

## Configuration

`config.py` centralizes backend selection:

```python
class AuditConfig(BaseModel):
    backend: Literal["async", "temporal"] = "async"
    policy_mode: Literal["permissive", "strict"] = "permissive"
    pii_threshold: float = 0.7
    timeout_seconds: int = 30
    temporal_address: str = "localhost:7233"
    temporal_task_queue: str = "auditguard-pipeline"
```

Read from environment variables (`AUDITGUARD_BACKEND`, `TEMPORAL_ADDRESS`, etc.). Other modules keep their own env vars for backward compatibility.

## Testing Strategy

| Test File | What it tests |
|-----------|---------------|
| `test_pipeline_stages.py` | Each stage in isolation (RBAC, PII scan, policy, audit log) |
| `test_async_runner.py` | End-to-end async pipeline (happy path, RBAC denial, policy block, audit completeness) |
| `test_temporal_runner.py` | Temporal workflow semantics (happy path, RBAC failure, signal handling) using `WorkflowEnvironment` |

The Temporal tests use `WorkflowEnvironment.start_time_skipping()` — a test-only in-memory Temporal server that runs workflows instantly. No Docker required. This is the killer feature for testing durable workflows.

## Migration Path from v1

The existing `server.py:_process_pipeline()` is preserved but no longer called by the main MCP tools. The new `_run_pipeline_v2()` constructs an `AuditRequest` + `AuditContext` and dispatches to the configured backend.

Existing tests (`test_integration.py`, `test_audit.py`, etc.) continue to pass because:
1. Domain models (`models.py`) are unchanged.
2. Existing modules (`rbac.py`, `privacy.py`, `policy.py`, `audit.py`) are unchanged.
3. The old `_process_pipeline()` and `_emit_audit()` functions remain in `server.py` for the `demo_query` tool's web UI path.

To fully migrate:
1. Move all tools to the new pipeline.
2. Deprecate `_process_pipeline()`.
3. Update `demo_query` to use the new pipeline exclusively.

## Future Backends

Adding a third backend requires:
1. Create `pipeline/new_backend_runner.py`.
2. Implement the 7-stage orchestration in the new backend's paradigm.
3. Import the runner in `server.py` and add a branch in `_run_pipeline_v2()`.
4. Write backend-specific tests.

Estimated effort: ~100 lines of adapter code + ~50 lines of tests.
