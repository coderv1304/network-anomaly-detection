"""flow ingestion provenance

Revision ID: c4f8a9d2e613
Revises: a1c4e9f2b7d0
Create Date: 2026-11-18 00:00:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c4f8a9d2e613'
down_revision: Union[str, None] = 'a1c4e9f2b7d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('flow', sa.Column('provenance', sa.String(length=64), nullable=True))
    op.create_index('ix_flow_provenance', 'flow', ['provenance'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_flow_provenance', table_name='flow')
    op.drop_column('flow', 'provenance')
