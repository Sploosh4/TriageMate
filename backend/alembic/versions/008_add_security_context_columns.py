"""Add security context columns — telemetry + network context

Revision ID: 008
Revises: 007
Create Date: 2026-07-09 12:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade():
    for table in ["vulnerabilities", "resolved_vulnerabilities"]:
        op.add_column(table, sa.Column("telemetry_json", sa.Text(), nullable=True))
        op.add_column(
            table, sa.Column("network_context_json", sa.Text(), nullable=True)
        )


def downgrade():
    for table in ["vulnerabilities", "resolved_vulnerabilities"]:
        op.drop_column(table, "telemetry_json")
        op.drop_column(table, "network_context_json")
