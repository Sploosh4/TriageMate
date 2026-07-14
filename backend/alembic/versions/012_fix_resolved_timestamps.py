"""Fix resolved_vulnerabilities created_at/updated_at type mismatch

Migration 003 defined created_at and updated_at as sa.Text() in the
resolved_vulnerabilities table, but migration 001 uses sa.DateTime() for
the same columns in the vulnerabilities table. This migration aligns the
types so that resolved_vulnerabilities matches the vulnerabilities schema.

Uses Alembic batch mode for SQLite compatibility (SQLite does not support
ALTER COLUMN TYPE directly — batch recreates the table). PostgreSQL receives
an explicit cast because a TEXT-to-timestamp type change is not implicit.

Revision ID: 012
Revises: 011
Create Date: 2026-07-13
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade():
    # Use batch mode for SQLite compatibility — Alembic recreates the table
    # with the new column types. PostgreSQL needs an explicit USING clause
    # to convert the legacy TEXT values.
    with op.batch_alter_table("resolved_vulnerabilities") as batch_op:
        batch_op.alter_column(
            "created_at",
            type_=sa.DateTime(),
            existing_type=sa.Text(),
            existing_nullable=True,
            postgresql_using="created_at::timestamp without time zone",
        )
        batch_op.alter_column(
            "updated_at",
            type_=sa.DateTime(),
            existing_type=sa.Text(),
            existing_nullable=True,
            postgresql_using="updated_at::timestamp without time zone",
        )


def downgrade():
    with op.batch_alter_table("resolved_vulnerabilities") as batch_op:
        batch_op.alter_column(
            "created_at",
            type_=sa.Text(),
            existing_type=sa.DateTime(),
            existing_nullable=True,
            postgresql_using="created_at::text",
        )
        batch_op.alter_column(
            "updated_at",
            type_=sa.Text(),
            existing_type=sa.DateTime(),
            existing_nullable=True,
            postgresql_using="updated_at::text",
        )
