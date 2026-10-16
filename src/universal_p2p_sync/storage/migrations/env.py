"""Alembic environment for the synchronization store.

Migrations run per application schema. The library calls them on start
(``auto_migrate=True``) with an open connection; they can also be run from the
command line with ``python -m universal_p2p_sync db-upgrade``.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine

config = context.config
schema = config.attributes["schema"]


def _run(connection) -> None:  # type: ignore[no-untyped-def]
    connection.exec_driver_sql(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
    context.configure(
        connection=connection,
        target_metadata=None,
        version_table="alembic_version",
        version_table_schema=schema,
        transaction_per_migration=True,
    )
    with context.begin_transaction():
        context.run_migrations()


connection = config.attributes.get("connection")
if connection is not None:
    _run(connection)
else:
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    with engine.begin() as conn:
        _run(conn)
    engine.dispose()
