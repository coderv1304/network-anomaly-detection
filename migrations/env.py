"""Alembic environment for NetShield.

The application metadata is the source of truth. Importing ``app`` is side
effect free here because ``NETSHIELD_SKIP_BOOTSTRAP`` prevents the development
``create_all`` path. The database URL comes from ``DATABASE_URL`` (or the Flask
configuration) so no credential is stored in ``alembic.ini``.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig

from alembic import context

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

os.environ["NETSHIELD_SKIP_BOOTSTRAP"] = "true"
os.environ.setdefault("METRICS_ENABLED", "false")
os.environ.setdefault("ENABLE_LOCAL_CAPTURE", "false")

from app import app, db  # noqa: E402

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

url = os.environ.get("DATABASE_URL") or app.config["SQLALCHEMY_DATABASE_URI"]
if not url:
    raise RuntimeError("DATABASE_URL or SQLALCHEMY_DATABASE_URI is required")
# ConfigParser treats percent signs as interpolation markers.
config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))

target_metadata = db.metadata

# One-time helper used to generate the baseline revision from current models.
# Never set this in a normal deployment.
if os.environ.get("ALEMBIC_AUTOGENERATE_FROM_EMPTY", "false").lower() == "true":
    with app.app_context():
        db.drop_all()


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    with app.app_context(), db.engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
