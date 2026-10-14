import os

import psycopg


DATABASE_CONFIG = {
    "host": os.getenv("OPSLENS_DB_HOST", "localhost"),
    "port": int(os.getenv("OPSLENS_DB_PORT", "5432")),
    "dbname": os.getenv("OPSLENS_DB_NAME", "nexabank"),
    "user": os.getenv("OPSLENS_DB_USER", "postgres"),
    "password": os.getenv("OPSLENS_DB_PASSWORD"),
}


def get_connection():
    if not DATABASE_CONFIG["password"]:
        raise RuntimeError(
            "Database password is missing. "
            "Set the OPSLENS_DB_PASSWORD environment variable."
        )

    return psycopg.connect(**DATABASE_CONFIG)