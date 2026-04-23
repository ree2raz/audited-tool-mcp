"""Generate synthetic financial services data for the audited-tool-mcp demo.

Creates ~500 rows across 4 tables: customers, accounts, transactions, advisors.
Uses Faker for realistic names/addresses/emails/phones.
Includes deliberate edge cases for Privacy Filter evaluation.

Usage:
    python scripts/seed_data.py
"""

from __future__ import annotations

import os
import random
import sqlite3
import sys
from pathlib import Path

from faker import Faker

# Ensure the project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

fake = Faker()
Faker.seed(42)
random.seed(42)

DB_PATH = os.environ.get("DB_PATH", str(Path(__file__).parent.parent / "data" / "synthetic_fs.sqlite"))


def create_tables(conn: sqlite3.Connection) -> None:
    """Create the schema for all 4 tables."""
    conn.executescript("""
        DROP TABLE IF EXISTS transactions;
        DROP TABLE IF EXISTS accounts;
        DROP TABLE IF EXISTS customers;
        DROP TABLE IF EXISTS advisors;

        CREATE TABLE customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            address TEXT NOT NULL,
            ssn TEXT NOT NULL,
            date_of_birth TEXT NOT NULL
        );

        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            account_number TEXT NOT NULL,
            account_type TEXT NOT NULL,
            balance REAL NOT NULL,
            opened_date TEXT NOT NULL,
            FOREIGN KEY (customer_id) REFERENCES customers(id)
        );

        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            description TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            counterparty TEXT NOT NULL,
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        );

        CREATE TABLE advisors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            region TEXT NOT NULL
        );
    """)


def generate_customers(conn: sqlite3.Connection, count: int = 100) -> list[int]:
    """Generate customer records with realistic PII."""
    customer_ids = []
    for _ in range(count):
        cursor = conn.execute(
            """INSERT INTO customers (first_name, last_name, email, phone, address, ssn, date_of_birth)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                fake.first_name(),
                fake.last_name(),
                fake.email(),
                fake.phone_number(),
                fake.address().replace("\n", ", "),
                fake.ssn(),
                fake.date_of_birth(minimum_age=18, maximum_age=85).isoformat(),
            ),
        )
        customer_ids.append(cursor.lastrowid)
    return customer_ids


def generate_accounts(conn: sqlite3.Connection, customer_ids: list[int]) -> list[int]:
    """Generate account records — 1-3 accounts per customer."""
    account_types = ["checking", "savings", "investment", "trust", "retirement"]
    account_ids = []

    for cid in customer_ids:
        num_accounts = random.randint(1, 3)
        for _ in range(num_accounts):
            acct_num = f"{random.randint(1000,9999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}"
            cursor = conn.execute(
                """INSERT INTO accounts (customer_id, account_number, account_type, balance, opened_date)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    cid,
                    acct_num,
                    random.choice(account_types),
                    round(random.uniform(100, 500000), 2),
                    fake.date_between(start_date="-10y", end_date="today").isoformat(),
                ),
            )
            account_ids.append(cursor.lastrowid)

    return account_ids


def generate_transactions(conn: sqlite3.Connection, account_ids: list[int]) -> None:
    """Generate transaction records with edge-case descriptions.

    Includes deliberate PII edge cases for Privacy Filter evaluation:
    - Aliases ("my wife's account")
    - Compound identifiers ("account ending in 4821")
    - One-hop references ("the Henderson trust's primary contact")
    - Ambiguous contexts ("transfer to John")
    """
    # Normal transaction descriptions
    normal_descriptions = [
        "Monthly payroll deposit",
        "Grocery purchase",
        "Utility bill payment",
        "ATM withdrawal",
        "Direct deposit",
        "Online purchase",
        "Subscription payment",
        "Insurance premium",
        "Rent payment",
        "Restaurant charge",
        "Gas station purchase",
        "Medical copay",
        "Pharmacy purchase",
        "Parking fee",
        "Cable bill",
    ]

    # Edge-case descriptions with embedded PII
    edge_case_descriptions = [
        "Transfer to my wife Sarah's account ending in 4821",
        "Wire transfer per the Henderson trust's primary contact",
        "Payment authorized by Dr. James Wilson for patient services",
        "Deposit from Johnson & Johnson settlement ref #JJ-2024-0891",
        "Reimbursement to Margaret Chen for conference expenses",
        "Transfer to account 8847-2193-5512 per client request",
        "Payment to landlord Robert O'Brien at 742 Evergreen Terrace",
        "Insurance payout per claim filed by the Davis family",
        "Advisory fee for the Nakamura retirement portfolio",
        "Wire to Bank of Springfield, routing 021000089",
        "Check deposit from Emily Rodriguez, memo: birthday gift",
        "ACH transfer initiated by accounting@hendersontrustco.com",
        "Withdrawal authorized via phone call from 555-867-5309",
        "Transfer per email from j.smith@privateclient.com dated 03/15/2024",
        "Quarterly distribution from the Alexander Family Trust",
    ]

    for aid in account_ids:
        num_txns = random.randint(1, 5)
        for _ in range(num_txns):
            # 20% chance of an edge-case description
            if random.random() < 0.2 and edge_case_descriptions:
                desc = random.choice(edge_case_descriptions)
            else:
                desc = random.choice(normal_descriptions)

            amount = round(random.uniform(-10000, 50000), 2)
            conn.execute(
                """INSERT INTO transactions (account_id, amount, description, timestamp, counterparty)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    aid,
                    amount,
                    desc,
                    fake.date_time_between(start_date="-1y", end_date="now").isoformat(),
                    fake.company(),
                ),
            )


def generate_advisors(conn: sqlite3.Connection, count: int = 20) -> None:
    """Generate financial advisor records."""
    regions = [
        "Northeast", "Southeast", "Midwest", "Southwest", "West Coast",
        "Pacific Northwest", "Mountain", "Gulf Coast", "Mid-Atlantic", "New England",
    ]
    for _ in range(count):
        conn.execute(
            """INSERT INTO advisors (name, email, phone, region)
               VALUES (?, ?, ?, ?)""",
            (
                fake.name(),
                fake.company_email(),
                fake.phone_number(),
                random.choice(regions),
            ),
        )


def generate_sample_queries() -> list[dict]:
    """Generate 15-20 natural-language queries covering all scenarios."""
    return [
        # Scenario 1: Normal analyst query
        {"role": "analyst", "query": "Show me all customers with a balance over $100,000",
         "scenario": "01_analyst_query"},
        {"role": "analyst", "query": "What is the total transaction volume for account type 'investment' last quarter?",
         "scenario": "01_analyst_query"},
        {"role": "analyst", "query": "List the top 10 customers by total balance across all accounts",
         "scenario": "01_analyst_query"},

        # Scenario 2: RBAC denial
        {"role": "intern", "query": "Show me all customer SSNs",
         "scenario": "02_rbac_denial"},
        {"role": "intern", "query": "What are the account balances?",
         "scenario": "02_rbac_denial"},
        {"role": "analyst", "query": "SELECT ssn FROM customers",
         "scenario": "02_rbac_denial"},

        # Scenario 3: PII redaction
        {"role": "analyst", "query": "Look up John Henderson's accounts and recent transactions",
         "scenario": "03_pii_redaction"},
        {"role": "analyst", "query": "Show me the account details for customer with email sarah.j@example.com",
         "scenario": "03_pii_redaction"},
        {"role": "analyst", "query": "Find transactions related to the address 742 Evergreen Terrace",
         "scenario": "03_pii_redaction"},

        # Scenario 4: Review queue (ambiguous PII)
        {"role": "compliance_officer", "query": "Show recent transactions for the Henderson trust",
         "scenario": "04_review_queue"},
        {"role": "compliance_officer",
         "query": "Pull all transactions mentioning wire transfers in the last 30 days",
         "scenario": "04_review_queue"},

        # Scenario 5: Full audit trail
        {"role": "compliance_officer",
         "query": "Show me the complete account history for customer ID 42",
         "scenario": "05_audit_trail"},
        {"role": "analyst",
         "query": "What is the average balance for checking accounts by region?",
         "scenario": "05_audit_trail"},

        # Edge cases with PII in query
        {"role": "analyst",
         "query": "Find the account ending in 4821 that belongs to my wife Sarah",
         "scenario": "03_pii_redaction"},
        {"role": "analyst",
         "query": "Look up transactions where Dr. James Wilson authorized payments",
         "scenario": "03_pii_redaction"},
    ]


def main() -> None:
    """Generate synthetic data and save to SQLite."""
    # Ensure data directory exists
    db_path = Path(DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # Remove existing DB
    if db_path.exists():
        db_path.unlink()

    print(f"Creating synthetic database at {db_path}...")

    conn = sqlite3.connect(str(db_path))
    try:
        create_tables(conn)

        print("  Generating 100 customers...")
        customer_ids = generate_customers(conn, 100)

        print("  Generating accounts (1-3 per customer)...")
        account_ids = generate_accounts(conn, customer_ids)

        print("  Generating transactions (1-5 per account)...")
        generate_transactions(conn, account_ids)

        print("  Generating 20 advisors...")
        generate_advisors(conn, 20)

        conn.commit()

        # Print summary
        counts = {}
        for table in ["customers", "accounts", "transactions", "advisors"]:
            cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
            counts[table] = cursor.fetchone()[0]

        print(f"\n  Summary:")
        for table, count in counts.items():
            print(f"    {table}: {count} rows")

        total = sum(counts.values())
        print(f"    Total: {total} rows")

        # Generate sample queries
        queries = generate_sample_queries()
        print(f"\n  Generated {len(queries)} sample queries for scenarios")

    finally:
        conn.close()

    print(f"\n✓ Database created at {db_path}")


if __name__ == "__main__":
    main()
