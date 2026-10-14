import os

import psycopg


def get_test_connection():
    password = os.getenv("OPSLENS_TEST_DB_PASSWORD")

    if not password:
        raise RuntimeError(
            "Test database password is missing. "
            "Set the OPSLENS_TEST_DB_PASSWORD environment variable."
        )

    return psycopg.connect(
        host=os.getenv("OPSLENS_DB_HOST", "localhost"),
        port=int(os.getenv("OPSLENS_DB_PORT", "5432")),
        dbname="opslens_test",
        user=os.getenv("OPSLENS_DB_USER", "postgres"),
        password=password,
    )