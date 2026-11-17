"""sensor heartbeats and incident triage

Revision ID: a1c4e9f2b7d0
Revises: f68710d807f3
Create Date: 2026-11-17 00:00:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1c4e9f2b7d0'
down_revision: Union[str, None] = 'f68710d807f3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'sensor_reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=True),
        sa.Column('sensor_id', sa.String(length=80), nullable=False),
        sa.Column('interface', sa.String(length=120), nullable=False),
        sa.Column('interface_description', sa.String(length=200), nullable=False),
        sa.Column('vector', sa.String(length=24), nullable=False),
        sa.Column('vector_basis', sa.String(length=32), nullable=False),
        sa.Column('capture_driver', sa.String(length=40), nullable=True),
        sa.Column('link_type', sa.String(length=40), nullable=True),
        sa.Column('link_speed_mbps', sa.Float(), nullable=True),
        sa.Column('rx_bytes', sa.Float(), nullable=True),
        sa.Column('tx_bytes', sa.Float(), nullable=True),
        sa.Column('rx_packets', sa.Float(), nullable=True),
        sa.Column('tx_packets', sa.Float(), nullable=True),
        sa.Column('rx_dropped', sa.Float(), nullable=True),
        sa.Column('tx_dropped', sa.Float(), nullable=True),
        sa.Column('uptime_seconds', sa.Float(), nullable=True),
        sa.Column('reported_at', sa.DateTime(), nullable=False),
        sa.Column('received_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'tenant_id',
            'sensor_id',
            'interface',
            name='uq_sensor_reports_identity',
        ),
    )
    op.create_index(
        op.f('ix_sensor_reports_tenant_id'), 'sensor_reports', ['tenant_id'], unique=False
    )
    op.create_index(
        op.f('ix_sensor_reports_sensor_id'), 'sensor_reports', ['sensor_id'], unique=False
    )
    op.create_index(
        op.f('ix_sensor_reports_received_at'),
        'sensor_reports',
        ['received_at'],
        unique=False,
    )

    op.create_table(
        'incident_triage',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=True),
        sa.Column('incident_id', sa.String(length=200), nullable=False),
        sa.Column('source_ip', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=24), nullable=False),
        sa.Column('assignee', sa.String(length=120), nullable=True),
        sa.Column('note', sa.String(length=2000), nullable=False),
        sa.Column('updated_by', sa.String(length=120), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'tenant_id', 'incident_id', name='uq_incident_triage_identity'
        ),
    )
    op.create_index(
        op.f('ix_incident_triage_tenant_id'), 'incident_triage', ['tenant_id'], unique=False
    )
    op.create_index(
        op.f('ix_incident_triage_incident_id'),
        'incident_triage',
        ['incident_id'],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f('ix_incident_triage_incident_id'), table_name='incident_triage'
    )
    op.drop_index(op.f('ix_incident_triage_tenant_id'), table_name='incident_triage')
    op.drop_table('incident_triage')

    op.drop_index(
        op.f('ix_sensor_reports_received_at'), table_name='sensor_reports'
    )
    op.drop_index(op.f('ix_sensor_reports_sensor_id'), table_name='sensor_reports')
    op.drop_index(op.f('ix_sensor_reports_tenant_id'), table_name='sensor_reports')
    op.drop_table('sensor_reports')
