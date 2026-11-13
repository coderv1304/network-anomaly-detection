"""Alembic baseline and runtime revision guard."""

import os
import subprocess
import sys

import pytest
from sqlalchemy import create_engine, inspect

import app as app_module
from migrations_runtime import (
    MigrationStateError,
    assert_database_current,
    current_revision,
    head_revision,
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _upgrade(database_url):
    env = os.environ.copy()
    env["DATABASE_URL"] = database_url
    env["NETSHIELD_ENV"] = "development"
    env["MIGRATIONS_REQUIRED"] = "false"
    env["METRICS_ENABLED"] = "false"
    completed = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout


def test_baseline_migration_creates_the_model_schema(tmp_path):
    database = tmp_path / "migration.db"
    database_url = f"sqlite:///{database.as_posix()}"
    _upgrade(database_url)

    engine = create_engine(database_url)
    tables = set(inspect(engine).get_table_names()) - {"alembic_version"}
    assert tables == set(app_module.db.metadata.tables)
    assert current_revision(engine) == head_revision()
    assert assert_database_current(engine) == head_revision()


def test_unversioned_database_fails_the_startup_guard(tmp_path):
    database = tmp_path / "unversioned.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with pytest.raises(MigrationStateError, match="no Alembic revision"):
        assert_database_current(engine)
