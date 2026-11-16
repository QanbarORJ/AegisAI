"""TargetProfile Pydantic v2 schemas (SECURITY_DESIGN.md Section 2, 3, 4)."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.target import ArchitectureTypeEnum, AuthTypeEnum, IntegrationModeEnum


class TargetProfileCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    architecture_type: ArchitectureTypeEnum = Field(default=ArchitectureTypeEnum.LLM_APP)
    integration_mode: IntegrationModeEnum = Field(default=IntegrationModeEnum.SIMULATOR)
    endpoint_url: str = Field(min_length=8, max_length=512)
    allowed_hosts: list[str] = Field(min_length=1)
    auth_type: AuthTypeEnum = Field(default=AuthTypeEnum.NONE)

    @field_validator("auth_type", mode="before")
    @classmethod
    def _normalize_auth_type(cls, value: Any) -> Any:
        if isinstance(value, str):
            upper = value.strip().upper()
            if upper == "BEARER":
                return AuthTypeEnum.BEARER_TOKEN.value
            if upper == "API_KEY":
                return AuthTypeEnum.API_KEY_HEADER.value
        return value
    credentials: dict[str, Any] | None = Field(
        default=None,
        description="Plaintext target credentials encrypted at rest using AES-256-GCM before DB persistence.",
    )
    request_template: dict[str, Any] = Field(default_factory=dict)
    architecture_manifest: dict[str, Any] = Field(default_factory=dict)
    rag_harness_config: dict[str, Any] | None = Field(default=None)
    agent_harness_config: dict[str, Any] | None = Field(default=None)
    rate_limit_rps: float = Field(default=2.0, gt=0.0, le=50.0)
    timeout_seconds: int = Field(default=15, ge=1, le=120)


class TargetProfileResponse(BaseModel):
    """Safe API representation of TargetProfile — never exposes `encrypted_credentials`."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    name: str
    architecture_type: ArchitectureTypeEnum
    integration_mode: IntegrationModeEnum
    endpoint_url: str
    allowed_hosts: list[str]
    auth_type: AuthTypeEnum
    credential_preview: str | None = None
    request_template: dict[str, Any]
    architecture_manifest: dict[str, Any]
    rag_harness_config: dict[str, Any] | None = None
    agent_harness_config: dict[str, Any] | None = None
    rate_limit_rps: float
    timeout_seconds: int
    created_at: datetime
