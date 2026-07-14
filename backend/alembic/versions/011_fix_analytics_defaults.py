"""Fix analytics column defaults — set NULL to 0, add server default

Migration 002 added analytics_view_count with default=0 (Python-side only),
allowing NULL in existing rows. This migration:
  1. Sets existing NULL analytics_view_count rows to 0
  2. Adds a server_default to prevent future NULLs

Revision ID: 011
Revises: 010
Create Date: 2026-07-13
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade():
    # Set existing NULL analytics_view_count to 0
    op.execute(
        "UPDATE vulnerabilities SET analytics_view_count = 0 "
        "WHERE analytics_view_count IS NULL"
    )

    # Alter column to have a server default (batch mode for SQLite compat)
    with op.batch_alter_table("vulnerabilities") as batch_op:
        batch_op.alter_column(
            "analytics_view_count",
            server_default=sa.text("0"),
            existing_type=sa.Integer(),
            existing_nullable=True,
        )


def downgrade():
    # Remove server default (note: does NOT re-introduce NULLs — data is preserved)
    with op.batch_alter_table("vulnerabilities") as batch_op:
        batch_op.alter_column(
            "analytics_view_count",
            server_default=None,
            existing_type=sa.Integer(),
            existing_nullable=True,
        )
