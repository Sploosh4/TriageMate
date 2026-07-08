"""Add tier_1_features TEXT column to resolved_vulnerabilities

Revision ID: 007
Revises: 006
Create Date: 2026-07-08
"""

from alembic import op
import sqlalchemy as sa

revision = "007"
down_revision = "006"


def upgrade():
    op.add_column(
        "resolved_vulnerabilities",
        sa.Column("tier_1_features", sa.Text(), nullable=True),
    )


def downgrade():
    op.drop_column("resolved_vulnerabilities", "tier_1_features")
