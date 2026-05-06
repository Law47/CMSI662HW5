import sqlite3

from passlib.hash import pbkdf2_sha256


con = sqlite3.connect("bank.db")
cur = con.cursor()

# Recreate the tiny demo database so repeated setup runs are predictable.
cur.execute("DROP TABLE IF EXISTS accounts")
cur.execute("DROP TABLE IF EXISTS users")

cur.execute(
    """
    CREATE TABLE users (
        email TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        password TEXT NOT NULL
    )
    """
)
cur.execute(
    """
    CREATE TABLE accounts (
        id TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        balance INTEGER NOT NULL CHECK (balance >= 0),
        FOREIGN KEY(owner) REFERENCES users(email)
    )
    """
)

# passlib's PBKDF2 helper generates a unique salt for each stored hash, so the
# database never stores plaintext passwords or repeatable unsalted hashes.
cur.execute(
    "INSERT INTO users VALUES (?, ?, ?)",
    ("alice@example.com", "Alice Xu", pbkdf2_sha256.hash("123456")),
)
cur.execute(
    "INSERT INTO users VALUES (?, ?, ?)",
    ("bob@example.com", "Bobby Tables", pbkdf2_sha256.hash("123456")),
)

# Bound parameters are used in setup too. It keeps the example consistent with
# the app's SQL Injection defense even though these seed values are trusted.
cur.execute("INSERT INTO accounts VALUES (?, ?, ?)", ("100", "alice@example.com", 7500))
cur.execute("INSERT INTO accounts VALUES (?, ?, ?)", ("190", "alice@example.com", 200))
cur.execute("INSERT INTO accounts VALUES (?, ?, ?)", ("998", "bob@example.com", 1000))
cur.execute("INSERT INTO accounts VALUES (?, ?, ?)", ("777", "bob@example.com", 650))

con.commit()
con.close()
