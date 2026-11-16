"""Authoritative SecurityFramework, FrameworkControl, and FindingFrameworkMapping ORM models."""

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JsonVariant

if TYPE_CHECKING:
    from app.models.finding import Finding


class SecurityFramework(Base):
    """Authoritative cybersecurity or AI risk management standard."""

    __tablename__ = "security_frameworks"

    id: Mapped[str] = mapped_column(String(60), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    publisher: Mapped[str] = mapped_column(String(100), nullable=False)
    release_date: Mapped[str] = mapped_column(String(40), default="", nullable=False)
    official_url: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)

    controls: Mapped[list["FrameworkControl"]] = relationship(
        "FrameworkControl", back_populates="framework", cascade="all, delete-orphan"
    )


class FrameworkControl(Base):
    """Official control, risk, or adversarial technique within a SecurityFramework."""

    __tablename__ = "framework_controls"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    framework_id: Mapped[str] = mapped_column(
        String(60), ForeignKey("security_frameworks.id", ondelete="CASCADE"), index=True, nullable=False
    )
    control_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    applicable_architectures: Mapped[list[str]] = mapped_column(
        JsonVariant, default=list, nullable=False
    )
    official_reference_url: Mapped[str] = mapped_column(String(512), nullable=False)

    framework: Mapped["SecurityFramework"] = relationship(
        "SecurityFramework", back_populates="controls"
    )


class FindingFrameworkMapping(Base):
    """Join model mapping a Finding to an authoritative FrameworkControl (DIRECT vs CONCEPTUAL)."""

    __tablename__ = "finding_framework_mappings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False
    )
    framework_control_id: Mapped[str] = mapped_column(
        String(80), ForeignKey("framework_controls.id", ondelete="CASCADE"), index=True, nullable=False
    )
    mapping_type: Mapped[str] = mapped_column(String(30), nullable=False)
    mapping_rationale: Mapped[str] = mapped_column(Text, nullable=False)

    finding: Mapped["Finding"] = relationship(
        "Finding", back_populates="framework_mappings"
    )
    control: Mapped["FrameworkControl"] = relationship("FrameworkControl")
