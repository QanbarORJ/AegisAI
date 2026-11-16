"""TargetProfile ORM model (DATABASE_SCHEMA.md Section 2.2)."""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JsonVariant, utc_now

if TYPE_CHECKING:
    from app.models.assessment import Assessment
    from app.models.user import Organization


class ArchitectureTypeEnum(StrEnum):
    LLM_APP = "LLM_APP"
    RAG_PIPELINE = "RAG_PIPELINE"
    AI_AGENT = "AI_AGENT"
    HYBRID = "HYBRID"


class IntegrationModeEnum(StrEnum):
    BLACK_BOX_REST = "BLACK_BOX_REST"
    OPENAI_COMPAT = "OPENAI_COMPAT"
    ASSISTED_HARNESS = "ASSISTED_HARNESS"
    CONFIG_ONLY = "CONFIG_ONLY"
    SIMULATOR = "SIMULATOR"


class AuthTypeEnum(StrEnum):
    NONE = "NONE"
    BEARER_TOKEN = "BEARER_TOKEN"
    API_KEY_HEADER = "API_KEY_HEADER"
    DUAL_TENANT_BEARER = "DUAL_TENANT_BEARER"


class TargetProfile(Base):
    """Represents a configured AI application endpoint, scope allowlist, and encrypted credentials."""

    __tablename__ = "target_profiles"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    architecture_type: Mapped[str] = mapped_column(
        String(40), default=ArchitectureTypeEnum.LLM_APP.value, nullable=False
    )
    integration_mode: Mapped[str] = mapped_column(
        String(40), default=IntegrationModeEnum.SIMULATOR.value, nullable=False
    )
    endpoint_url: Mapped[str] = mapped_column(String(512), nullable=False)
    allowed_hosts: Mapped[list[str]] = mapped_column(
        JsonVariant, default=list, nullable=False
    )
    auth_type: Mapped[str] = mapped_column(
        String(40), default=AuthTypeEnum.NONE.value, nullable=False
    )
    encrypted_credentials: Mapped[str | None] = mapped_column(Text, nullable=True)
    credential_preview: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_template: Mapped[dict[str, Any]] = mapped_column(
        JsonVariant, default=dict, nullable=False
    )
    architecture_manifest: Mapped[dict[str, Any]] = mapped_column(
        JsonVariant, default=dict, nullable=False
    )
    rag_harness_config: Mapped[dict[str, Any] | None] = mapped_column(
        JsonVariant, nullable=True
    )
    agent_harness_config: Mapped[dict[str, Any] | None] = mapped_column(
        JsonVariant, nullable=True
    )
    rate_limit_rps: Mapped[float] = mapped_column(Float, default=2.0, nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=15, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="target_profiles"
    )
    assessments: Mapped[list["Assessment"]] = relationship(
        "Assessment", back_populates="target_profile", cascade="all, delete-orphan"
    )
