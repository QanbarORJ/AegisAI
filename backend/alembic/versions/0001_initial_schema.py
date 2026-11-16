"""Initial AegisAI Multi-Tenant Database Schema.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-07
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op
from app.db.base import JsonVariant

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. organizations
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("slug", sa.String(length=80), nullable=False),
        sa.Column("max_rps_limit", sa.Float(), nullable=False, server_default="5.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=True)

    # 2. users
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=160), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=40), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_organization_id", "users", ["organization_id"], unique=False)
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # 3. audit_logs
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("resource_type", sa.String(length=60), nullable=False),
        sa.Column("resource_id", sa.String(length=64), nullable=False),
        sa.Column("details_json", JsonVariant, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_organization_id", "audit_logs", ["organization_id"], unique=False)
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"], unique=False)
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"], unique=False)

    # 4. target_profiles
    op.create_table(
        "target_profiles",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("architecture_type", sa.String(length=40), nullable=False),
        sa.Column("integration_mode", sa.String(length=40), nullable=False),
        sa.Column("endpoint_url", sa.String(length=512), nullable=False),
        sa.Column("allowed_hosts", JsonVariant, nullable=False),
        sa.Column("auth_type", sa.String(length=40), nullable=False),
        sa.Column("encrypted_credentials", sa.Text(), nullable=True),
        sa.Column("credential_preview", sa.String(length=64), nullable=True),
        sa.Column("request_template", JsonVariant, nullable=False),
        sa.Column("architecture_manifest", JsonVariant, nullable=False),
        sa.Column("rag_harness_config", JsonVariant, nullable=True),
        sa.Column("agent_harness_config", JsonVariant, nullable=True),
        sa.Column("rate_limit_rps", sa.Float(), nullable=False, server_default="2.0"),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="15"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_target_profiles_organization_id", "target_profiles", ["organization_id"], unique=False)

    # 5. assessments
    op.create_table(
        "assessments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("target_profile_id", sa.String(length=36), nullable=False),
        sa.Column("initiated_by_user_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("selected_modules", JsonVariant, nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("scope_attestation", JsonVariant, nullable=False),
        sa.Column("target_profile_snapshot", JsonVariant, nullable=False),
        sa.Column("progress_pct", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_tests_planned", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tests_completed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("overall_risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("posture_grade", sa.String(length=16), nullable=True),
        sa.Column("summary_metrics", JsonVariant, nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_profile_id"], ["target_profiles.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["initiated_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_assessments_organization_id", "assessments", ["organization_id"], unique=False)
    op.create_index("ix_assessments_target_profile_id", "assessments", ["target_profile_id"], unique=False)
    op.create_index("ix_assessments_status", "assessments", ["status"], unique=False)

    # 6. test_execution_results
    op.create_table(
        "test_execution_results",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("assessment_id", sa.String(length=36), nullable=False),
        sa.Column("test_id", sa.String(length=40), nullable=False),
        sa.Column("module", sa.String(length=30), nullable=False),
        sa.Column("test_title", sa.String(length=200), nullable=False),
        sa.Column("test_category", sa.String(length=100), nullable=False),
        sa.Column("target_component", sa.String(length=100), nullable=False),
        sa.Column("execution_status", sa.String(length=30), nullable=False),
        sa.Column("vulnerability_status", sa.String(length=40), nullable=False),
        sa.Column("probes_sent", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("execution_duration_ms", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("execution_log", JsonVariant, nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_test_execution_results_assessment_id", "test_execution_results", ["assessment_id"], unique=False)
    op.create_index("ix_test_execution_results_test_id", "test_execution_results", ["test_id"], unique=False)
    op.create_index("ix_test_execution_results_execution_status", "test_execution_results", ["execution_status"], unique=False)

    # 7. findings
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("assessment_id", sa.String(length=36), nullable=False),
        sa.Column("test_result_id", sa.String(length=36), nullable=False),
        sa.Column("test_id", sa.String(length=40), nullable=False),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("module", sa.String(length=30), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("affected_component", sa.String(length=120), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.String(length=20), nullable=False),
        sa.Column("is_confirmed", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("avss_score", sa.Float(), nullable=False),
        sa.Column("avss_vector", sa.String(length=140), nullable=False),
        sa.Column("severity_rationale", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("exploitability_summary", sa.Text(), nullable=False),
        sa.Column("remediation_structured", JsonVariant, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["test_result_id"], ["test_execution_results.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_organization_id", "findings", ["organization_id"], unique=False)
    op.create_index("ix_findings_assessment_id", "findings", ["assessment_id"], unique=False)
    op.create_index("ix_findings_severity", "findings", ["severity"], unique=False)

    # 8. technical_evidence
    op.create_table(
        "technical_evidence",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("probe_name", sa.String(length=160), nullable=False),
        sa.Column("request_payload", JsonVariant, nullable=False),
        sa.Column("response_payload", JsonVariant, nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("detector_name", sa.String(length=80), nullable=False),
        sa.Column("matched_artifacts", JsonVariant, nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_technical_evidence_finding_id", "technical_evidence", ["finding_id"], unique=False)

    # 9. security_frameworks
    op.create_table(
        "security_frameworks",
        sa.Column("id", sa.String(length=60), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("version", sa.String(length=40), nullable=False),
        sa.Column("publisher", sa.String(length=100), nullable=False),
        sa.Column("official_url", sa.String(length=512), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # 10. framework_controls
    op.create_table(
        "framework_controls",
        sa.Column("id", sa.String(length=80), nullable=False),
        sa.Column("framework_id", sa.String(length=60), nullable=False),
        sa.Column("control_id", sa.String(length=50), nullable=False),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("applicable_architectures", JsonVariant, nullable=False),
        sa.Column("official_reference_url", sa.String(length=512), nullable=False),
        sa.ForeignKeyConstraint(["framework_id"], ["security_frameworks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_framework_controls_framework_id", "framework_controls", ["framework_id"], unique=False)
    op.create_index("ix_framework_controls_control_id", "framework_controls", ["control_id"], unique=False)

    # 11. finding_framework_mappings
    op.create_table(
        "finding_framework_mappings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("framework_control_id", sa.String(length=80), nullable=False),
        sa.Column("mapping_type", sa.String(length=30), nullable=False),
        sa.Column("mapping_rationale", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["framework_control_id"], ["framework_controls.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_finding_framework_mappings_finding_id", "finding_framework_mappings", ["finding_id"], unique=False)
    op.create_index("ix_finding_framework_mappings_framework_control_id", "finding_framework_mappings", ["framework_control_id"], unique=False)

    # 12. reports
    op.create_table(
        "reports",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("assessment_id", sa.String(length=36), nullable=False),
        sa.Column("generated_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("report_format", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("executive_summary", sa.String(length=4000), nullable=False),
        sa.Column("report_payload", JsonVariant, nullable=False),
        sa.Column("rendered_html", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["generated_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_reports_organization_id", "reports", ["organization_id"], unique=False)
    op.create_index("ix_reports_assessment_id", "reports", ["assessment_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_reports_assessment_id", table_name="reports")
    op.drop_index("ix_reports_organization_id", table_name="reports")
    op.drop_table("reports")

    op.drop_index("ix_finding_framework_mappings_framework_control_id", table_name="finding_framework_mappings")
    op.drop_index("ix_finding_framework_mappings_finding_id", table_name="finding_framework_mappings")
    op.drop_table("finding_framework_mappings")

    op.drop_index("ix_framework_controls_control_id", table_name="framework_controls")
    op.drop_index("ix_framework_controls_framework_id", table_name="framework_controls")
    op.drop_table("framework_controls")

    op.drop_table("security_frameworks")

    op.drop_index("ix_technical_evidence_finding_id", table_name="technical_evidence")
    op.drop_table("technical_evidence")

    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_assessment_id", table_name="findings")
    op.drop_index("ix_findings_organization_id", table_name="findings")
    op.drop_table("findings")

    op.drop_index("ix_test_execution_results_execution_status", table_name="test_execution_results")
    op.drop_index("ix_test_execution_results_test_id", table_name="test_execution_results")
    op.drop_index("ix_test_execution_results_assessment_id", table_name="test_execution_results")
    op.drop_table("test_execution_results")

    op.drop_index("ix_assessments_status", table_name="assessments")
    op.drop_index("ix_assessments_target_profile_id", table_name="assessments")
    op.drop_index("ix_assessments_organization_id", table_name="assessments")
    op.drop_table("assessments")

    op.drop_index("ix_target_profiles_organization_id", table_name="target_profiles")
    op.drop_table("target_profiles")

    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_index("ix_audit_logs_organization_id", table_name="audit_logs")
    op.drop_table("audit_logs")

    op.drop_index("ix_users_email", table_name="users")
    op.drop_index("ix_users_organization_id", table_name="users")
    op.drop_table("users")

    op.drop_index("ix_organizations_slug", table_name="organizations")
    op.drop_table("organizations")
