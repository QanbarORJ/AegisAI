"""Export all ORM models so SQLAlchemy and Alembic register them cleanly."""

from app.models.assessment import Assessment, AssessmentStatusEnum, ReportArtifact
from app.models.audit import AuditLog
from app.models.finding import Finding, TechnicalEvidence, TestExecutionResult
from app.models.framework import (
    FindingFrameworkMapping,
    FrameworkControl,
    SecurityFramework,
)
from app.models.target import (
    ArchitectureTypeEnum,
    AuthTypeEnum,
    IntegrationModeEnum,
    TargetProfile,
)
from app.models.user import Organization, User

__all__ = [
    "ArchitectureTypeEnum",
    "Assessment",
    "AssessmentStatusEnum",
    "AuditLog",
    "AuthTypeEnum",
    "Finding",
    "FindingFrameworkMapping",
    "FrameworkControl",
    "IntegrationModeEnum",
    "Organization",
    "ReportArtifact",
    "SecurityFramework",
    "TargetProfile",
    "TechnicalEvidence",
    "TestExecutionResult",
    "User",
]
