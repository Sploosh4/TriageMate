"""Add analytics tracking columns

Revision ID: 002
Revises: 001
Create Date: 2026-06-30
"""

from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"


def upgrade():
    op.add_column(
        "vulnerabilities",
        sa.Column("analytics_view_count", sa.Integer(), default=0),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("analytics_last_viewed", sa.DateTime(), nullable=True),
    )


def downgrade():
    op.drop_column("vulnerabilities", "analytics_view_count")
    op.drop_column("vulnerabilities", "analytics_last_viewed")
