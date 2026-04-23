"""Evaluation harness — runs golden set cases end-to-end and reports per-layer metrics.

Usage:
    python eval/eval_harness.py
    python eval/eval_harness.py --golden-set eval/golden_set.jsonl
    MOCK_PII=1 python eval/eval_harness.py  # Use mock detector for speed
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from audited_tool_mcp.audit import AuditLogger
from audited_tool_mcp.models import (
    Actor,
    AuditRecord,
    RequestStatus,
    Role,
)
from audited_tool_mcp.privacy import use_mock_detector
from audited_tool_mcp.server import _process_pipeline
from audited_tool_mcp.tools.sql_query import execute_sql


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


class EvalMetrics:
    """Per-layer evaluation metrics."""

    def __init__(self):
        self.total = 0
        self.rbac_correct = 0
        self.status_correct = 0
        self.inbound_pii_correct = 0
        self.audit_complete = 0
        self.errors: list[str] = []

    def report(self) -> str:
        """Generate a summary table."""
        lines = [
            "",
            "=" * 70,
            "  EVALUATION RESULTS",
            "=" * 70,
            "",
            f"  Total cases:           {self.total}",
            f"  RBAC accuracy:         {self.rbac_correct}/{self.total} ({self._pct(self.rbac_correct)}%)",
            f"  Status accuracy:       {self.status_correct}/{self.total} ({self._pct(self.status_correct)}%)",
            f"  Inbound PII accuracy:  {self.inbound_pii_correct}/{self.total} ({self._pct(self.inbound_pii_correct)}%)",
            f"  Audit completeness:    {self.audit_complete}/{self.total} ({self._pct(self.audit_complete)}%)",
            "",
        ]

        if self.errors:
            lines.append("  ERRORS:")
            for err in self.errors:
                lines.append(f"    ❌ {err}")
            lines.append("")

        overall = (self.rbac_correct + self.status_correct + self.inbound_pii_correct + self.audit_complete)
        max_score = self.total * 4
        lines.append(f"  Overall score:         {overall}/{max_score} ({self._pct(overall, max_score)}%)")
        lines.append("=" * 70)

        return "\n".join(lines)

    def _pct(self, count: int, total: int | None = None) -> str:
        t = total if total is not None else self.total
        if t == 0:
            return "0"
        return f"{100 * count / t:.0f}"


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


async def evaluate_case(case: dict, audit_logger: AuditLogger) -> dict:
    """Run a single golden set case through the pipeline."""
    role = Role(case["role"])
    query = case["query"]
    expected_status = case["expected_status"]
    expected_rbac = case["expected_rbac"]

    actor = Actor(role=role, user_id=f"eval-{role.value}")

    async def _execute(q: str) -> str:
        return execute_sql(q, role=role)

    # Determine if this is a SQL query
    sql_query = query if query.strip().upper().startswith("SELECT") else None

    result = await _process_pipeline(
        actor=actor,
        tool_name="sql_query",
        query=query,
        tool_executor=_execute,
        sql_query=sql_query,
    )

    # Get the latest audit record
    records = audit_logger.read_all()
    latest = records[-1] if records else None

    return {
        "case": case,
        "result": result,
        "audit_record": latest,
    }


async def run_eval(golden_set_path: str, use_mock: bool = True) -> EvalMetrics:
    """Run the full evaluation harness."""
    if use_mock:
        use_mock_detector(True)

    # Use a temp directory for audit/vault/review files
    with tempfile.TemporaryDirectory() as tmp_dir:
        audit_path = os.path.join(tmp_dir, "audit.jsonl")
        os.environ["VAULT_PATH"] = os.path.join(tmp_dir, "vault.jsonl")
        os.environ["REVIEW_QUEUE_PATH"] = os.path.join(tmp_dir, "review_queue.jsonl")

        # Need to reinitialize the server's audit logger
        from audited_tool_mcp import server as server_module
        server_module.audit_logger = AuditLogger(path=audit_path)
        audit_logger = server_module.audit_logger

        # Load golden set
        cases = []
        with open(golden_set_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    cases.append(json.loads(line))

        metrics = EvalMetrics()
        metrics.total = len(cases)

        print(f"\nRunning {len(cases)} evaluation cases...")
        print("-" * 70)

        for i, case in enumerate(cases, 1):
            desc = case.get("description", case["query"][:50])
            print(f"  [{i:2d}/{len(cases)}] {desc}...", end=" ")

            try:
                result = await evaluate_case(case, audit_logger)
                audit_record = result["audit_record"]

                # Check RBAC
                expected_rbac = case["expected_rbac"]
                if audit_record:
                    actual_rbac = "deny" if audit_record.status == RequestStatus.RBAC_DENIED else "allow"
                    if actual_rbac == expected_rbac:
                        metrics.rbac_correct += 1
                    else:
                        metrics.errors.append(
                            f"Case {i}: RBAC expected={expected_rbac}, got={actual_rbac}"
                        )

                    # Check status
                    expected_status = case["expected_status"]
                    if audit_record.status.value == expected_status:
                        metrics.status_correct += 1
                    elif expected_status == "success" and audit_record.status == RequestStatus.REVIEW_QUEUED:
                        # REVIEW_QUEUED is acceptable for "success" cases
                        metrics.status_correct += 1
                    else:
                        metrics.errors.append(
                            f"Case {i}: Status expected={expected_status}, got={audit_record.status.value}"
                        )

                    # Check inbound PII detection
                    expected_categories = set(case.get("expected_inbound_categories", []))
                    if expected_categories:
                        actual_categories = {d.category.value for d in audit_record.inbound_detections}
                        if expected_categories.issubset(actual_categories):
                            metrics.inbound_pii_correct += 1
                        else:
                            missing = expected_categories - actual_categories
                            metrics.errors.append(
                                f"Case {i}: Missing inbound PII categories: {missing}"
                            )
                    else:
                        metrics.inbound_pii_correct += 1  # No expected categories = pass

                    # Check audit completeness
                    required_fields = [
                        "request_id", "timestamp_utc", "actor", "tool_name",
                        "raw_query_hash", "status", "policy_version", "model_version",
                    ]
                    record_dict = audit_record.model_dump()
                    all_present = all(
                        record_dict.get(f) not in (None, "")
                        for f in required_fields
                        if f != "policy_version" or audit_record.status != RequestStatus.RBAC_DENIED
                    )
                    if all_present:
                        metrics.audit_complete += 1
                    else:
                        missing = [
                            f for f in required_fields
                            if record_dict.get(f) in (None, "")
                            and not (f == "policy_version" and audit_record.status == RequestStatus.RBAC_DENIED)
                        ]
                        metrics.errors.append(
                            f"Case {i}: Missing audit fields: {missing}"
                        )

                else:
                    metrics.errors.append(f"Case {i}: No audit record produced")

                print("✅")

            except Exception as e:
                metrics.errors.append(f"Case {i}: Exception: {e}")
                print(f"❌ ({e})")

        return metrics


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Evaluation harness for audited-tool-mcp")
    parser.add_argument(
        "--golden-set",
        default=str(Path(__file__).parent / "golden_set.jsonl"),
        help="Path to golden set JSONL file",
    )
    parser.add_argument(
        "--no-mock",
        action="store_true",
        help="Use the real Privacy Filter model (requires download)",
    )
    args = parser.parse_args()

    use_mock = not args.no_mock
    if os.environ.get("MOCK_PII", "0") == "1":
        use_mock = True

    metrics = asyncio.run(run_eval(args.golden_set, use_mock=use_mock))
    print(metrics.report())


if __name__ == "__main__":
    main()
