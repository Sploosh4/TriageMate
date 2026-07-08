"""Add tier_1_features TEXT column to vulnerabilities

Revision ID: 006
Revises: 005
Create Date: 2026-07-08
"""

from alembic import op
import sqlalchemy as sa

revision = "006"
down_revision = "005"


def upgrade():
    op.add_column(
        "vulnerabilities",
        sa.Column("tier_1_features", sa.Text(), nullable=True),
    )


def downgrade():
    op.drop_column("vulnerabilities", "tier_1_features")
