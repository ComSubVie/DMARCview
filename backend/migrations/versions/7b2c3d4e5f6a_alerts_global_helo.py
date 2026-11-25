"""global alerts and per-domain HELO hostname

Revision ID: 7b2c3d4e5f6a
Revises: 6a1f2c3d4e5f
Create Date: 2026-11-25 10:10:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
import sqlmodel


revision = "7b2c3d4e5f6a"
down_revision = "6a1f2c3d4e5f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("alert_events", schema=None) as batch_op:
        batch_op.alter_column(
            "domain_id",
            existing_type=sa.Integer(),
            nullable=True,
        )
    with op.batch_alter_table("domain_settings", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("helo_hostname", sqlmodel.sql.sqltypes.AutoString(length=255), nullable=True)
        )


def downgrade() -> None:
    # Global events have no domain; they cannot exist under the old NOT NULL schema.
    op.execute("DELETE FROM alert_events WHERE domain_id IS NULL")
    with op.batch_alter_table("domain_settings", schema=None) as batch_op:
        batch_op.drop_column("helo_hostname")
    with op.batch_alter_table("alert_events", schema=None) as batch_op:
        batch_op.alter_column(
            "domain_id",
            existing_type=sa.Integer(),
            nullable=False,
        )
