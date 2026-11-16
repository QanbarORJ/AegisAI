"""Pydantic v2 schemas for Enterprise Security Assessment Reports (`ReportArtifact`)."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ReportCreateRequest(BaseModel):
    """Request payload to generate a security assessment report."""

    report_format: str = Field(
        default="HTML",
        description="Desired report format: HTML, JSON, or PDF.",
    )
    title: str | None = Field(
        default=None,
        max_length=240,
        description="Optional custom report title.",
    )


class ReportSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    assessment_id: str
    title: str
    report_format: str
    executive_summary: str = ""
    generated_by_user_id: str | None = None
    created_at: datetime


class ReportDetailResponse(ReportSummaryResponse):
    report_payload: dict[str, Any] = Field(default_factory=dict)
    rendered_html: str | None = None
