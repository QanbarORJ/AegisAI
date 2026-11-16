"""SQLAlchemy 2.0 Declarative Base and cross-database JSONB/UUID helpers."""

from datetime import UTC, datetime

from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase


def utc_now() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(UTC)


# Cross-dialect JSONB type: uses native JSONB on PostgreSQL 16 and standard JSON on SQLite
JsonVariant = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    """Declarative base for all AegisAI SQLAlchemy models."""
    pass
