"""Authentication, Organization, User, and AuditLog Pydantic v2 schemas."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.core.security import RoleEnum


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    slug: str
    max_rps_limit: float
    created_at: datetime


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    email: EmailStr
    full_name: str
    role: RoleEnum
    is_active: bool
    created_at: datetime


class RegisterOrganizationRequest(BaseModel):
    organization_name: str = Field(min_length=2, max_length=160)
    organization_slug: str = Field(
        min_length=2,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9\-]*[a-z0-9]$",
        description="URL-safe tenant slug (lowercase alphanumeric and hyphens).",
    )
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=160)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class UserCreateRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=160)
    password: str = Field(min_length=8, max_length=128)
    role: RoleEnum = Field(default=RoleEnum.SECURITY_ENGINEER)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int
    user: UserResponse
    organization: OrganizationResponse


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    user_id: str | None
    action: str
    resource_type: str
    resource_id: str
    details_json: dict[str, Any]
    created_at: datetime
