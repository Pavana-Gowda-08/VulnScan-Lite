import os

import psycopg
from psycopg.rows import dict_row
from contextlib import contextmanager
from werkzeug.security import generate_password_hash


DATABASE_URL = os.getenv("DATABASE_URL")


if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL environment variable is not set."
    )


@contextmanager
def connect():

    connection = psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row
    )

    try:
        yield connection
        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def init_db():

    with connect() as db:

        db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            status TEXT NOT NULL,
            score INTEGER,
            grade TEXT,
            result_json TEXT,
            error TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY(user_id)
            REFERENCES users(id)
        );
        """)

        demo_email = "demo@vulnscan.local"

        existing = db.execute(
            """
            SELECT 1
            FROM users
            WHERE email=%s
            """,
            (demo_email,)
        ).fetchone()

        if existing is None:

            db.execute(
                """
                INSERT INTO users
                (email, password_hash)
                VALUES (%s, %s)
                """,
                (
                    demo_email,
                    generate_password_hash("Demo123!")
                )
            )


def create_user(email, password):

    with connect() as db:

        cursor = db.execute(
            """
            INSERT INTO users
            (email, password_hash)
            VALUES (%s, %s)
            RETURNING id
            """,
            (
                email.lower().strip(),
                generate_password_hash(password)
            )
        )

        return cursor.fetchone()["id"]


def get_user(email):

    with connect() as db:

        row = db.execute(
            """
            SELECT *
            FROM users
            WHERE email=%s
            """,
            (email.lower().strip(),)
        ).fetchone()

        return dict(row) if row else None


def create_scan(user_id, url):

    with connect() as db:

        cursor = db.execute(
            """
            INSERT INTO scans
            (user_id, url, status)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (
                user_id,
                url,
                "QUEUED"
            )
        )

        return cursor.fetchone()["id"]


def set_scan(scan_id, **fields):

    allowed = {
        "status",
        "score",
        "grade",
        "result_json",
        "error"
    }

    fields = {
        key: value
        for key, value in fields.items()
        if key in allowed
    }

    if not fields:
        return

    sql = ", ".join(
        f"{key}=%s"
        for key in fields
    )

    values = list(fields.values())
    values.append(scan_id)

    with connect() as db:

        db.execute(
            f"""
            UPDATE scans
            SET {sql}
            WHERE id=%s
            """,
            values
        )


def get_scan(scan_id, user_id=None):

    with connect() as db:

        if user_id is None:

            row = db.execute(
                """
                SELECT *
                FROM scans
                WHERE id=%s
                """,
                (scan_id,)
            ).fetchone()

        else:

            row = db.execute(
                """
                SELECT *
                FROM scans
                WHERE id=%s
                AND user_id=%s
                """,
                (
                    scan_id,
                    user_id
                )
            ).fetchone()

        return dict(row) if row else None


def list_scans(user_id, limit=50):

    with connect() as db:

        rows = db.execute(
            """
            SELECT
                id,
                url,
                status,
                score,
                grade,
                created_at
            FROM scans
            WHERE user_id=%s
            ORDER BY id DESC
            LIMIT %s
            """,
            (
                user_id,
                limit
            )
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]