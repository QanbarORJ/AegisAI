"""Pydantic v2 schemas for Security Frameworks, Controls, and Tenant Compliance Posture."""

from pydantic import BaseModel, ConfigDict, Field


class FrameworkControlResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    framework_id: str
    control_id: str
    title: str
    category: str
    description: str
    official_reference_url: str


class SecurityFrameworkSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    version: str
    publisher: str
    release_date: str
    description: str
    official_url: str
    control_count: int = 0


class SecurityFrameworkDetailResponse(SecurityFrameworkSummaryResponse):
    controls: list[FrameworkControlResponse] = Field(default_factory=list)


class ComplianceControlImpactResponse(BaseModel):
    control_id: str
    title: str
    category: str
    official_reference_url: str
    finding_count: int
    highest_severity: str
    relationship_types: list[str] = Field(default_factory=list)


class FrameworkComplianceSummaryItem(BaseModel):
    framework_id: str
    name: str
    version: str
    publisher: str
    official_url: str
    total_controls: int
    affected_controls_count: int
    direct_findings_count: int
    related_findings_count: int
    supporting_findings_count: int
    affected_controls: list[ComplianceControlImpactResponse] = Field(default_factory=list)


class TenantCompliancePostureResponse(BaseModel):
    organization_id: str
    assessment_id: str | None = None
    total_findings_evaluated: int
    confirmed_findings_count: int
    suspected_findings_count: int
    frameworks: list[FrameworkComplianceSummaryItem] = Field(default_factory=list)
