"""Runtime checks that a deployment is on the reviewed Alembic revision.

The application does not run migrations at import time in staging or
production. A release runs ``alembic upgrade head`` as an explicit deployment
step; this module fails startup if the database is behind, ahead, or unversioned
so a process never serves against an unexpected schema.
"""

from __future__ import annotations

import os

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
DEFAULT_CONFIG_PATH = os.path.join(REPO_ROOT, "alembic.ini")


class MigrationStateError(RuntimeError):
    """Raised when the database revision does not match the code revision."""


def head_revision(config_path: str = DEFAULT_CONFIG_PATH) -> str:
    config = Config(config_path)
    script = ScriptDirectory.from_config(config)
    head = script.get_current_head()
    if not head:
        raise MigrationStateError("No Alembic head revision is defined")
    return head


def current_revision(engine) -> str | None:
    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        return context.get_current_revision()


def assert_database_current(engine, config_path: str = DEFAULT_CONFIG_PATH) -> str:
    """Return the matched revision or raise ``MigrationStateError``."""

    head = head_revision(config_path)
    current = current_revision(engine)
    if current is None:
        raise MigrationStateError(
            "Database has no Alembic revision. Run 'alembic upgrade head' "
            "(or 'alembic stamp head' after verifying an existing schema) "
            "before starting the service."
        )
    if current != head:
        raise MigrationStateError(
            f"Database schema is at revision {current!r}, code expects {head!r}. "
            "Run 'alembic upgrade head' before starting the service."
        )
    return current
