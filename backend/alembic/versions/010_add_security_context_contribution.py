"""Add security_context_contribution column

The security_context_contribution INTEGER DEFAULT 0 column exists in the
application DDL (both SQLite and PostgreSQL) as a server-side default,
but was never recorded in Alembic migration history. This migration adds
it to both tables with a proper server_default, matching the inline DDL.

Revision ID: 010
Revises: 009
Create Date: 2026-07-13
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade():
    for table in ["vulnerabilities", "resolved_vulnerabilities"]:
        op.add_column(
            table,
            sa.Column(
                "security_context_contribution",
                sa.Integer(),
                server_default=sa.text("0"),
                nullable=False,
            ),
        )


def downgrade():
    for table in ["vulnerabilities", "resolved_vulnerabilities"]:
        op.drop_column(table, "security_context_contribution")
