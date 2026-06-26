"""Invariant #8 guard (static): only a single read-only SELECT survives validation."""

from __future__ import annotations

import pytest

from app.nodes.sql_tool import SQLValidationError, validate_sql

ALLOWED = [
    "SELECT 1",
    "SELECT amount FROM sales WHERE region = 'EMEA'",
    "SELECT region, SUM(amount) AS total FROM sales GROUP BY region",
    "WITH t AS (SELECT amount FROM sales) SELECT SUM(amount) FROM t",
    "SELECT s.amount FROM sales s JOIN customers c ON c.id = s.customer_id",
]

REJECTED = [
    "",
    "INSERT INTO sales (amount) VALUES (1)",
    "UPDATE sales SET amount = 0",
    "DELETE FROM sales",
    "DROP TABLE sales",
    "TRUNCATE sales",
    "ALTER TABLE sales ADD COLUMN x int",
    "GRANT SELECT ON sales TO public",
    "SELECT 1; SELECT 2",  # multiple statements
    "SELECT amount INTO tmp FROM sales",  # SELECT INTO creates a table
    "SET ROLE postgres",  # parsed as Command
    "WITH x AS (DELETE FROM sales RETURNING *) SELECT * FROM x",  # data-modifying CTE
    "SELECT 1; DROP TABLE sales",  # injection via second statement
]


@pytest.mark.parametrize("sql", ALLOWED)
def test_allows_read_only_selects(sql):
    out = validate_sql(sql)
    assert out  # normalized SQL returned
    assert out.lower().lstrip().startswith(("select", "with"))


@pytest.mark.parametrize("sql", REJECTED)
def test_rejects_non_select(sql):
    with pytest.raises(SQLValidationError):
        validate_sql(sql)


def test_trailing_semicolon_is_tolerated():
    assert validate_sql("SELECT 1;").lower().startswith("select")
