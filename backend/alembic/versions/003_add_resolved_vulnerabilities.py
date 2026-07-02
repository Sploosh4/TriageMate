"""Add resolved_vulnerabilities table

Revision ID: 003
Revises: 002
Create Date: 2026-07-02
"""

from alembic import op
import sqlalchemy as sa

revision = "003"
down_revision = "002"


def upgrade():
    from sqlalchemy import inspect

    conn = op.get_bind()
    inspector = inspect(conn)
    if "resolved_vulnerabilities" in inspector.get_table_names():
        return
    op.create_table(
        "resolved_vulnerabilities",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("original_id", sa.Integer(), nullable=True),
        sa.Column("vulnerability_id", sa.Text(), nullable=False),
        sa.Column("hostname", sa.Text(), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.Text(), nullable=True),
        sa.Column("cisa_kev", sa.Boolean(), default=False),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("mission_prevalence", sa.Text(), nullable=True),
        sa.Column("mission_prevalence_conf", sa.Float(), nullable=True),
        sa.Column("public_wellbeing_impact", sa.Text(), nullable=True),
        sa.Column("public_wellbeing_conf", sa.Float(), nullable=True),
        sa.Column("tier_0_routing", sa.Text(), nullable=True),
        sa.Column("tier_0_resolution", sa.Text(), nullable=True),
        sa.Column("tier_1_confidence", sa.Float(), nullable=True),
        sa.Column("tier_1_exploitation_prob", sa.Float(), nullable=True),
        sa.Column("tier_1_routing", sa.Text(), nullable=True),
        sa.Column("tier_2_text_conflict", sa.Boolean(), nullable=True),
        sa.Column("tier_2_conflict_note", sa.Text(), nullable=True),
        sa.Column("tier_2_rag_result", sa.Text(), nullable=True),
        sa.Column("tier_2_confidence", sa.Float(), nullable=True),
        sa.Column("tier_2_resolution_summary", sa.Text(), nullable=True),
        sa.Column("priority_score", sa.Integer(), nullable=False),
        sa.Column("risk_band", sa.Text(), nullable=False),
        sa.Column("cvss_contribution", sa.Integer(), nullable=True),
        sa.Column("epss_contribution", sa.Integer(), nullable=True),
        sa.Column("asset_criticality_contribution", sa.Integer(), nullable=True),
        sa.Column("exposure_contribution", sa.Integer(), nullable=True),
        sa.Column("patch_remediation_contribution", sa.Integer(), nullable=True),
        sa.Column("epss_substituted", sa.Boolean(), default=False),
        sa.Column("epss_substituted_value", sa.Float(), nullable=True),
        sa.Column("epss_substitution_confidence", sa.Float(), nullable=True),
        sa.Column("epss_substitution_reason", sa.Text(), nullable=True),
        sa.Column("data_classification", sa.Text(), nullable=True),
        sa.Column("network_zone", sa.Text(), nullable=True),
        sa.Column("interface_type", sa.Text(), nullable=True),
        sa.Column("patch_cycle", sa.Text(), nullable=True),
        sa.Column("last_patch_date", sa.Text(), nullable=True),
        sa.Column("last_scan_date", sa.Text(), nullable=True),
        sa.Column("operating_system", sa.Text(), nullable=True),
        sa.Column("role", sa.Text(), nullable=True),
        sa.Column("business_owner", sa.Text(), nullable=True),
        sa.Column("technical_owner", sa.Text(), nullable=True),
        sa.Column("registered_applications", sa.Text(), nullable=True),
        sa.Column("dependent_assets", sa.Text(), nullable=True),
        sa.Column("service_account", sa.Text(), nullable=True),
        sa.Column("detection_tier", sa.Text(), nullable=True),
        sa.Column("detection_reason", sa.Text(), nullable=True),
        sa.Column("scanner_output_raw", sa.Text(), nullable=True),
        sa.Column("weakness_template_raw", sa.Text(), nullable=True),
        sa.Column("advisory_ref_id", sa.Text(), nullable=True),
        sa.Column("advisory_quote", sa.Text(), nullable=True),
        sa.Column("investigation_notes", sa.Text(), nullable=True),
        sa.Column("mitre_techniques_json", sa.Text(), nullable=True),
        sa.Column("scoring_weights_json", sa.Text(), nullable=True),
        sa.Column("asset_registry_json", sa.Text(), nullable=True),
        sa.Column("summary_paragraphs_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.Text(), nullable=True),
        sa.Column("last_recheck_date", sa.Text(), nullable=True),
        sa.Column("audit_selected", sa.Boolean(), default=False),
        sa.Column("audit_result", sa.Text(), nullable=True),
        sa.Column("audit_date", sa.Text(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("resolution_reason", sa.Text(), default="demo_clear"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade():
    op.drop_table("resolved_vulnerabilities")
