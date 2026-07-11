"""Sprint 22 schema catchup — add pre_tier_features and epss_features columns

These columns were added to the application DDL via ALTER TABLE in database.py
(Sprint 18) but were never recorded in the Alembic migration history.

Revision ID: 009
Revises: 008
Create Date: 2026-07-11 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None


def upgrade():
    for table in ["vulnerabilities", "resolved_vulnerabilities"]:
        op.add_column(table, sa.Column("pre_tier_features", sa.Text(), nullable=True))
        op.add_column(table, sa.Column("epss_features", sa.Text(), nullable=True))


def downgrade():
    for table in ["vulnerabilities", "resolved_vulnerabilities"]:
        op.drop_column(table, "epss_features")
        op.drop_column(table, "pre_tier_features")
