"""Phase 2 Verification: Alembic Migration Upgrade/Downgrade & SQLAlchemy 2.0 Schema Consistency."""

from pathlib import Path

from alembic.config import Config
from sqlalchemy import create_engine, inspect

import app.models  # noqa: F401
from alembic import command
from app.db.base import Base

EXPECTED_TABLES = {
    "organizations",
    "users",
    "audit_logs",
    "target_profiles",
    "assessments",
    "test_execution_results",
    "findings",
    "technical_evidence",
    "security_frameworks",
    "framework_controls",
    "finding_framework_mappings",
    "reports",
}


def test_alembic_initial_migration_upgrade_and_downgrade(
    tmp_path: Path, monkeypatch
) -> None:
    """Verify Alembic 0001_initial_schema upgrades cleanly, matches ORM metadata, and downgrades cleanly."""
    db_file = tmp_path / "alembic_verify.db"
    db_url = f"sqlite:///{db_file.as_posix()}"

    monkeypatch.setenv("DATABASE_URL", db_url)
    from app.core.config import get_settings

    get_settings.cache_clear()

    backend_dir = Path(__file__).resolve().parents[1]
    alembic_cfg = Config(str(backend_dir / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)

    try:
        # Upgrade to head
        command.upgrade(alembic_cfg, "head")

        engine = create_engine(db_url)
        inspector = inspect(engine)
        migrated_tables = set(inspector.get_table_names()) - {"alembic_version"}
        assert migrated_tables == EXPECTED_TABLES
        assert set(Base.metadata.tables.keys()) == EXPECTED_TABLES

        # Downgrade to base
        command.downgrade(alembic_cfg, "base")
        inspector_after_down = inspect(engine)
        remaining_tables = set(inspector_after_down.get_table_names()) - {
            "alembic_version"
        }
        assert remaining_tables == set()

        # Re-upgrade to head
        command.upgrade(alembic_cfg, "head")
        inspector_reup = inspect(engine)
        assert (
            set(inspector_reup.get_table_names()) - {"alembic_version"}
            == EXPECTED_TABLES
        )
        engine.dispose()
    finally:
        get_settings.cache_clear()
