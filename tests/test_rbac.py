"""Tests for RBAC module (audited_tool_mcp.rbac).

Tests the three-step fail-fast RBAC check:
  1a. Tool name O(1) membership check
  1b. SQL table/column access validation
  1c. API endpoint/param access validation
"""

from __future__ import annotations

import pytest

from audited_tool_mcp.models import Actor, RBACDenied, Role, RolePermissions
from audited_tool_mcp.rbac import (
    ROLE_PERMISSIONS,
    check_access,
    filter_columns,
    get_restricted_columns,
    validate_api_access,
    validate_sql_access,
    _extract_tables,
    _extract_select_columns,
)


# ---------------------------------------------------------------------------
# Test role definitions
# ---------------------------------------------------------------------------


class TestRoleDefinitions:
    def test_intern_has_no_tools(self):
        perms = ROLE_PERMISSIONS[Role.INTERN]
        assert perms.allowed_tools == set()

    def test_analyst_has_two_tools(self):
        perms = ROLE_PERMISSIONS[Role.ANALYST]
        assert perms.allowed_tools == {"sql_query", "customer_api"}

    def test_compliance_officer_has_tools(self):
        perms = ROLE_PERMISSIONS[Role.COMPLIANCE_OFFICER]
        assert "sql_query" in perms.allowed_tools
        assert "customer_api" in perms.allowed_tools

    def test_analyst_cannot_see_ssn(self):
        perms = ROLE_PERMISSIONS[Role.ANALYST]
        customers_cols = perms.allowed_columns.get("customers", set())
        assert "ssn" not in customers_cols

    def test_analyst_cannot_see_account_number(self):
        perms = ROLE_PERMISSIONS[Role.ANALYST]
        accounts_cols = perms.allowed_columns.get("accounts", set())
        assert "account_number" not in accounts_cols

    def test_compliance_officer_has_all_columns(self):
        perms = ROLE_PERMISSIONS[Role.COMPLIANCE_OFFICER]
        # Empty allowed_columns means no restrictions
        assert perms.allowed_columns == {}


# ---------------------------------------------------------------------------
# Test RBAC check — Step 1a: tool name
# ---------------------------------------------------------------------------


class TestRBACToolCheck:
    def test_intern_blocked_from_all_tools(self):
        actor = Actor(role=Role.INTERN, user_id="intern-001")

        with pytest.raises(RBACDenied) as exc_info:
            check_access(actor, "sql_query")

        assert "does not have access" in str(exc_info.value)
        assert exc_info.value.role == Role.INTERN

    def test_intern_blocked_from_customer_api(self):
        actor = Actor(role=Role.INTERN, user_id="intern-001")

        with pytest.raises(RBACDenied):
            check_access(actor, "customer_api")

    def test_analyst_allowed_sql_query(self):
        actor = Actor(role=Role.ANALYST, user_id="analyst-001")
        perms = check_access(actor, "sql_query")
        assert isinstance(perms, RolePermissions)

    def test_analyst_allowed_customer_api(self):
        actor = Actor(role=Role.ANALYST, user_id="analyst-001")
        perms = check_access(actor, "customer_api")
        assert isinstance(perms, RolePermissions)

    def test_analyst_blocked_unknown_tool(self):
        actor = Actor(role=Role.ANALYST, user_id="analyst-001")

        with pytest.raises(RBACDenied):
            check_access(actor, "admin_panel")

    def test_compliance_officer_allowed(self):
        actor = Actor(role=Role.COMPLIANCE_OFFICER, user_id="co-001")
        perms = check_access(actor, "sql_query")
        assert isinstance(perms, RolePermissions)


# ---------------------------------------------------------------------------
# Test SQL parsing helpers
# ---------------------------------------------------------------------------


class TestSQLParsing:
    def test_extract_single_table(self):
        tables = _extract_tables("SELECT * FROM customers WHERE id = 1")
        assert tables == {"customers"}

    def test_extract_multiple_tables(self):
        tables = _extract_tables(
            "SELECT c.name, a.balance FROM customers c JOIN accounts a ON c.id = a.customer_id"
        )
        assert "customers" in tables
        assert "accounts" in tables

    def test_extract_columns_star(self):
        cols = _extract_select_columns("SELECT * FROM customers")
        assert cols is None  # SELECT * = all columns

    def test_extract_specific_columns(self):
        cols = _extract_select_columns("SELECT id, name, email FROM customers")
        assert cols is not None
        assert "id" in cols
        assert "name" in cols
        assert "email" in cols

    def test_extract_columns_with_table_prefix(self):
        cols = _extract_select_columns(
            "SELECT customers.ssn, customers.name FROM customers"
        )
        assert cols is not None
        assert "ssn" in cols
        assert "name" in cols


# ---------------------------------------------------------------------------
# Test RBAC check — Step 1b: SQL access
# ---------------------------------------------------------------------------


class TestRBACSQLAccess:
    def test_analyst_allowed_normal_query(self):
        actor = Actor(role=Role.ANALYST, user_id="analyst-001")
        # Should not raise
        check_access(
            actor, "sql_query",
            sql_query="SELECT id, first_name, last_name FROM customers"
        )

    def test_analyst_blocked_from_ssn(self):
        actor = Actor(role=Role.ANALYST, user_id="analyst-001")

        with pytest.raises(RBACDenied) as exc_info:
            check_access(
                actor, "sql_query",
                sql_query="SELECT ssn FROM customers"
            )

        assert "ssn" in str(exc_info.value).lower()

    def test_analyst_blocked_from_unknown_table(self):
        actor = Actor(role=Role.ANALYST, user_id="analyst-001")

        with pytest.raises(RBACDenied):
            check_access(
                actor, "sql_query",
                sql_query="SELECT * FROM admin_logs"
            )

    def test_compliance_officer_can_see_everything(self):
        actor = Actor(role=Role.COMPLIANCE_OFFICER, user_id="co-001")
        # Compliance officer has no column restrictions
        check_access(
            actor, "sql_query",
            sql_query="SELECT ssn, account_number FROM customers"
        )


# ---------------------------------------------------------------------------
# Test RBAC check — Step 1c: API access
# ---------------------------------------------------------------------------


class TestRBACAPIAccess:
    def test_analyst_api_without_restricted_fields(self):
        actor = Actor(role=Role.ANALYST, user_id="analyst-001")
        # Should not raise
        check_access(
            actor, "customer_api",
            api_endpoint="/customers/123",
        )

    def test_analyst_api_with_restricted_field(self):
        actor = Actor(role=Role.ANALYST, user_id="analyst-001")

        with pytest.raises(RBACDenied):
            check_access(
                actor, "customer_api",
                api_endpoint="/customers/123",
                api_params={"fields": "name,ssn,email"},
            )


# ---------------------------------------------------------------------------
# Test column filtering
# ---------------------------------------------------------------------------


class TestColumnFiltering:
    def test_filter_analyst_customers(self):
        result = filter_columns(
            Role.ANALYST, "customers",
            {"id", "first_name", "last_name", "ssn", "email"}
        )
        assert "ssn" not in result
        assert "id" in result
        assert "first_name" in result

    def test_compliance_officer_no_filtering(self):
        result = filter_columns(
            Role.COMPLIANCE_OFFICER, "customers",
            {"id", "first_name", "ssn"}
        )
        # No restrictions — all columns pass through
        assert result == {"id", "first_name", "ssn"}

    def test_get_restricted_columns_analyst(self):
        restricted = get_restricted_columns(Role.ANALYST, "customers")
        assert "ssn" in restricted

    def test_get_restricted_columns_compliance(self):
        restricted = get_restricted_columns(Role.COMPLIANCE_OFFICER, "customers")
        assert restricted == set()  # No restrictions
