from __future__ import annotations

import os
import sqlite3


DATABASE = os.environ.get("BANK_DEMO_DATABASE", "bank.db")


class TransferError(Exception):
    """A safe, user-displayable transfer validation error."""


def _connect():
    con = sqlite3.connect(DATABASE)
    con.row_factory = sqlite3.Row
    return con


def get_owned_accounts(owner: str):
    with _connect() as con:
        rows = con.execute(
            # Every owner value is bound, never interpolated, which prevents SQL
            # Injection even if a malicious JWT subject somehow reached here.
            "SELECT id, balance FROM accounts WHERE owner = ? ORDER BY id",
            (owner,),
        ).fetchall()
    return [{"id": row["id"], "balance": row["balance"]} for row in rows]


def get_balance(account_number: str, owner: str):
    with _connect() as con:
        row = con.execute(
            # Authorization is part of the lookup: users can only retrieve
            # balances for accounts they own.
            "SELECT balance FROM accounts WHERE id = ? AND owner = ?",
            (account_number, owner),
        ).fetchone()
    return None if row is None else row["balance"]


def do_transfer(source: str, target: str, amount: int, owner: str) -> None:
    if source == target:
        raise TransferError("Choose two different accounts.")

    con = _connect()
    try:
        # A transaction makes debit and credit atomic: either both updates commit
        # or neither does. BEGIN IMMEDIATE also prevents a race from spending the
        # same balance twice in this SQLite demo.
        con.execute("BEGIN IMMEDIATE")

        source_row = con.execute(
            "SELECT balance FROM accounts WHERE id = ? AND owner = ?",
            (source, owner),
        ).fetchone()
        if source_row is None:
            raise TransferError("Transfer could not be completed.")
        if amount > source_row["balance"]:
            raise TransferError("Insufficient funds.")

        target_row = con.execute(
            "SELECT id FROM accounts WHERE id = ?",
            (target,),
        ).fetchone()
        if target_row is None:
            raise TransferError("Transfer could not be completed.")

        con.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, source))
        con.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, target))
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()
