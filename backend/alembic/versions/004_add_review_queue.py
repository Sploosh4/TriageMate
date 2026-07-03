"""Add review queue columns and reviews table

Revision ID: 004
Revises: 003
Create Date: 2026-07-02
"""

from alembic import op
import sqlalchemy as sa

revision = "004"
down_revision = "003"


def upgrade():
    # Add review columns to vulnerabilities
    op.add_column(
        "vulnerabilities",
        sa.Column("flagged_for_review", sa.Boolean(), default=False),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("review_status", sa.Text(), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("review_decision", sa.Text(), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("reviewed_by", sa.Text(), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("reviewed_at", sa.Text(), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("override_score", sa.Integer(), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("override_band", sa.Text(), nullable=True),
    )

    # Add same columns to resolved_vulnerabilities
    op.add_column(
        "resolved_vulnerabilities",
        sa.Column("flagged_for_review", sa.Boolean(), default=False),
    )
    op.add_column(
        "resolved_vulnerabilities",
        sa.Column("review_status", sa.Text(), nullable=True),
    )
    op.add_column(
        "resolved_vulnerabilities",
        sa.Column("review_decision", sa.Text(), nullable=True),
    )
    op.add_column(
        "resolved_vulnerabilities",
        sa.Column("reviewed_by", sa.Text(), nullable=True),
    )
    op.add_column(
        "resolved_vulnerabilities",
        sa.Column("reviewed_at", sa.Text(), nullable=True),
    )
    op.add_column(
        "resolved_vulnerabilities",
        sa.Column("override_score", sa.Integer(), nullable=True),
    )
    op.add_column(
        "resolved_vulnerabilities",
        sa.Column("override_band", sa.Text(), nullable=True),
    )

    # Create reviews audit log table
    op.create_table(
        "reviews",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("vulnerability_id", sa.Text(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("analyst_decision", sa.Text(), nullable=False),
        sa.Column("override_score", sa.Integer(), nullable=True),
        sa.Column("override_band", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("analyst_name", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade():
    op.drop_table("reviews")

    for table in ("vulnerabilities", "resolved_vulnerabilities"):
        op.drop_column(table, "flagged_for_review")
        op.drop_column(table, "review_status")
        op.drop_column(table, "review_decision")
        op.drop_column(table, "reviewed_by")
        op.drop_column(table, "reviewed_at")
        op.drop_column(table, "override_score")
        op.drop_column(table, "override_band")
