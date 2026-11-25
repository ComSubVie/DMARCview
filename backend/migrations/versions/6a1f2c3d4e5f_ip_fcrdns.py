"""ip metadata forward-confirmed rDNS

Revision ID: 6a1f2c3d4e5f
Revises: 38cc042c3c10
Create Date: 2026-11-25 09:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
import sqlmodel


revision = "6a1f2c3d4e5f"
down_revision = "38cc042c3c10"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("ip_meta", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("fcrdns_status", sqlmodel.sql.sqltypes.AutoString(length=32), nullable=True)
        )
        batch_op.add_column(
            sa.Column("fcrdns_forward", sqlmodel.sql.sqltypes.AutoString(length=255), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("ip_meta", schema=None) as batch_op:
        batch_op.drop_column("fcrdns_forward")
        batch_op.drop_column("fcrdns_status")
