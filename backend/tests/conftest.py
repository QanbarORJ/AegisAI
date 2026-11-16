"""Pytest fixtures for isolated database sessions, FastAPI TestClient, and multi-tenant RBAC contexts."""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.core.security import RoleEnum, create_access_token, hash_password
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.user import Organization, User


@pytest.fixture()
def db_session() -> Generator[Session, None, None]:
    """Provide a fresh, isolated in-memory SQLite database session per test."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> Generator[TestClient, None, None]:
    """Provide a FastAPI TestClient wired to the isolated `db_session` fixture."""
    import app.main as main_module

    monkeypatch.setattr(main_module, "engine", db_session.get_bind())
    app = create_app()

    def _override_get_db() -> Generator[Session, None, None]:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def multi_tenant_seed(db_session: Session) -> dict[str, object]:
    """Seed two isolated organizations (Alpha and Beta) with ORG_ADMIN, SECURITY_ENGINEER, and VIEWER users."""
    org_alpha = Organization(name="Acme Alpha Security", slug="acme-alpha", max_rps_limit=5.0)
    org_beta = Organization(name="Globex Beta Corp", slug="globex-beta", max_rps_limit=5.0)
    db_session.add_all([org_alpha, org_beta])
    db_session.flush()

    alpha_admin = User(
        organization_id=org_alpha.id,
        email="admin@alpha.example.com",
        full_name="Alpha Admin",
        password_hash=hash_password("AlphaAdminPass123!"),
        role=RoleEnum.ORG_ADMIN.value,
        is_active=True,
    )
    alpha_engineer = User(
        organization_id=org_alpha.id,
        email="engineer@alpha.example.com",
        full_name="Alpha Engineer",
        password_hash=hash_password("AlphaEngPass123!"),
        role=RoleEnum.SECURITY_ENGINEER.value,
        is_active=True,
    )
    alpha_viewer = User(
        organization_id=org_alpha.id,
        email="viewer@alpha.example.com",
        full_name="Alpha Viewer",
        password_hash=hash_password("AlphaViewPass123!"),
        role=RoleEnum.VIEWER.value,
        is_active=True,
    )
    beta_admin = User(
        organization_id=org_beta.id,
        email="admin@beta.example.com",
        full_name="Beta Admin",
        password_hash=hash_password("BetaAdminPass123!"),
        role=RoleEnum.ORG_ADMIN.value,
        is_active=True,
    )

    db_session.add_all([alpha_admin, alpha_engineer, alpha_viewer, beta_admin])
    db_session.commit()

    return {
        "org_alpha": org_alpha,
        "org_beta": org_beta,
        "alpha_admin": alpha_admin,
        "alpha_engineer": alpha_engineer,
        "alpha_viewer": alpha_viewer,
        "beta_admin": beta_admin,
        "tokens": {
            "alpha_admin": create_access_token(
                user_id=alpha_admin.id,
                organization_id=org_alpha.id,
                email=alpha_admin.email,
                role=RoleEnum.ORG_ADMIN,
            ),
            "alpha_engineer": create_access_token(
                user_id=alpha_engineer.id,
                organization_id=org_alpha.id,
                email=alpha_engineer.email,
                role=RoleEnum.SECURITY_ENGINEER,
            ),
            "alpha_viewer": create_access_token(
                user_id=alpha_viewer.id,
                organization_id=org_alpha.id,
                email=alpha_viewer.email,
                role=RoleEnum.VIEWER,
            ),
            "beta_admin": create_access_token(
                user_id=beta_admin.id,
                organization_id=org_beta.id,
                email=beta_admin.email,
                role=RoleEnum.ORG_ADMIN,
            ),
        },
    }
